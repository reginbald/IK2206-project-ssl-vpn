/**************************************************************************
 * simpletun.c                                                            *
 *                                                                        *
 * A simplistic, simple-minded, naive tunnelling program using tun/tap    *
 * interfaces and TCP. Handles (badly) IPv4 for tun, ARP and IPv4 for     *
 * tap. DO NOT USE THIS PROGRAM FOR SERIOUS PURPOSES.                     *
 *                                                                        *
 * You have been warned.                                                  *
 *                                                                        *
 * (C) 2009 Davide Brini.                                                 *
 *                                                                        *
 * DISCLAIMER AND WARNING: this is all work in progress. The code is      *
 * ugly, the algorithms are naive, error checking and input validation    *
 * are very basic, and of course there can be bugs. If that's not enough, *
 * the program has not been thoroughly tested, so it might even fail at   *
 * the few simple things it should be supposed to do right.               *
 * Needless to say, I take no responsibility whatsoever for what the      *
 * program might do. The program has been written mostly for learning     *
 * purposes, and can be used in the hope that is useful, but everything   *
 * is to be taken "as is" and without any kind of warranty, implicit or   *
 * explicit. See the file LICENSE for further details.                    *
 *************************************************************************/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <linux/if.h>
#include <linux/if_tun.h>
#include <sys/types.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <arpa/inet.h>
#include <sys/select.h>
#include <sys/time.h>
#include <errno.h>
#include <stdarg.h>
#include "AES.h"
#include "HMAC.h"
#include "common.h"
#include "server.h"
#include "client.h"
#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>


/* buffer for reading from tun/tap interface, must be >= 1500 */
#define BUFSIZE 2000
#define CLIENT 0
#define SERVER 1
#define PORT 55555

/* some common lengths */
#define IP_HDR_LEN 20
#define ETH_HDR_LEN 14
#define ARP_PKT_LEN 28

int debug;
char *progname;

/**************************************************************************
 * tun_alloc: allocates or reconnects to a tun/tap device. The caller     *
 *            needs to reserve enough space in *dev.                      *
 **************************************************************************/
int tun_alloc(char *dev, int flags) {

  struct ifreq ifr;
  int fd, err;

  if ( (fd = open("/dev/net/tun", O_RDWR)) < 0 ) {
    perror("Opening /dev/net/tun");
    return fd;
  }

  memset(&ifr, 0, sizeof(ifr));

  ifr.ifr_flags = flags;

  if (*dev) {
    strncpy(ifr.ifr_name, dev, IFNAMSIZ);
  }

  if ( (err = ioctl(fd, TUNSETIFF, (void *)&ifr)) < 0 ) {
    perror("ioctl(TUNSETIFF)");
    close(fd);
    return err;
  }

  strcpy(dev, ifr.ifr_name);

  return fd;
}

/**************************************************************************
 * cread: read routine that checks for errors and exits if an error is    *
 *        returned.                                                       *
 **************************************************************************/
int cread(int fd, char *buf, int n) {

  int nread;

  if ((nread = read(fd, buf, n)) < 0) {
    perror("Reading data");
    exit(1);
  }
  return nread;
}

/**************************************************************************
 * cwrite: write routine that checks for errors and exits if an error is  *
 *         returned.                                                      *
 **************************************************************************/
int cwrite(int fd, char *buf, int n) {

  int nwrite;

  if ((nwrite = write(fd, buf, n)) < 0) {
    perror("Writing data");
    exit(1);
  }
  return nwrite;
}

/**************************************************************************
 * read_n: ensures we read exactly n bytes, and puts those into "buf".    *
 *         (unless EOF, of course)                                        *
 **************************************************************************/
int read_n(int fd, char *buf, int n) {

  int nread, left = n;

  while (left > 0) {
    if ((nread = cread(fd, buf, left)) == 0) {
      return 0 ;
    } else {
      left -= nread;
      buf += nread;
    }
  }
  return n;
}

/**************************************************************************
 * do_debug: prints debugging stuff (doh!)                                *
 **************************************************************************/
void do_debug(char *msg, ...) {

  va_list argp;

  if (debug) {
    va_start(argp, msg);
    vfprintf(stderr, msg, argp);
    va_end(argp);
  }
}

/**************************************************************************
 * my_err: prints custom error messages on stderr.                        *
 **************************************************************************/
void my_err(char *msg, ...) {

  va_list argp;

  va_start(argp, msg);
  vfprintf(stderr, msg, argp);
  va_end(argp);
}

/**************************************************************************
 * usage: prints usage and exits.                                         *
 **************************************************************************/
void usage(void) {
  fprintf(stderr, "Usage:\n");
  fprintf(stderr, "%s -i <ifacename> [-s|-c <serverIP>] [-p <port>] [-u|-a] [-d]\n", progname);
  fprintf(stderr, "%s -h\n", progname);
  fprintf(stderr, "\n");
  fprintf(stderr, "-i <ifacename>: Name of interface to use (mandatory)\n");
  fprintf(stderr, "-s|-c <serverIP>: run in server mode (-s), or specify server address (-c <serverIP>) (mandatory)\n");
  fprintf(stderr, "-p <port>: port to listen on (if run in server mode) or to connect to (in client mode), default 55555\n");
  fprintf(stderr, "-u|-a: use TUN (-u, default) or TAP (-a)\n");
  fprintf(stderr, "-d: outputs debug information while running\n");
  fprintf(stderr, "-h: prints this help text\n");
  exit(1);
}


void print_hex(uint8_t *buf, size_t len) {
    size_t i;
    for (i = 0; i < len; i++) {
        printf("%02x ", buf[i]);
    }
    printf("\n");
}

int main(int argc, char *argv[]) {

  int tap_fd, option;
  int flags = IFF_TUN;
  char if_name[IFNAMSIZ] = "";
  int header_len = IP_HDR_LEN;
  int maxfd;
  uint16_t nread, nwrite, plength;
//  uint16_t total_len, ethertype;
  char buffer[BUFSIZE], temp[BUFSIZE];

  struct sockaddr_in local, remote;
  char remote_ip[16] = "";
  unsigned short int port = PORT;
  int sock_fd, net_fd, optval = 1;
  socklen_t remotelen;
  int cliserv = -1;    /* must be specified on cmd line */
  unsigned long int tap2net = 0, net2tap = 0;

  progname = argv[0];

  /* use select() to handle two descriptors at once */
  maxfd = (tap_fd > net_fd) ? tap_fd : net_fd;

  //Init of encryption
  unsigned char *key = (unsigned char*)malloc(32);

  /* A 128 bit IV */
  unsigned char *iv = (unsigned char*)malloc(16);

  /* Set up the library */
  ERR_load_crypto_strings();
  ERR_load_SSL_strings();
  ERR_load_BIO_strings();
  OpenSSL_add_all_algorithms();
  SSL_library_init();
  SSLeay_add_ssl_algorithms();
  OPENSSL_config(NULL);

  BIO * bio, *bbio, *acpt, *out;
  SSL * ssl;
  SSL_CTX * ctx;
  char number[10];
  char tmpbuf[11];
  static int ssl_session_ctx_id = 1;

  /* Check command line options */
  while ((option = getopt(argc, argv, "i:s:c:p:uahd")) > 0) {
    switch (option) {
    case 'd':
      debug = 1;
      break;
    case 'h':
      usage();
      break;
    case 'i':
      strncpy(if_name, optarg, IFNAMSIZ - 1);
      break;
    case 's':
      cliserv = SERVER;
      strncpy(remote_ip, optarg, 15);
      break;
    case 'c':
      cliserv = CLIENT;
      strncpy(remote_ip, optarg, 15);
      break;
    case 'p':
      port = atoi(optarg);
      break;
    case 'u':
      flags = IFF_TUN;
      break;
    case 'a':
      flags = IFF_TAP;
      header_len = ETH_HDR_LEN;
      break;
    default:
      my_err("Unknown option %c\n", option);
      usage();
    }
  }

  argv += optind;
  argc -= optind;

  if (argc > 0) {
    my_err("Too many options!\n");
    usage();
  }

  if (*if_name == '\0') {
    my_err("Must specify interface name!\n");
    usage();
  } else if (cliserv < 0) {
    my_err("Must specify client or server mode!\n");
    usage();
  } else if ((*remote_ip == '\0')) {
    my_err("Must specify server address!\n");
    usage();
  }

  /* SSL context setup */
  if (cliserv == CLIENT) {
    ctx = SSL_CTX_new(SSLv23_client_method());
    if (!ctx) {
        ERR_print_errors_fp(stderr);
        exit(1);
    }
    if (SSL_CTX_use_certificate_file(ctx,"/home/seed/ik2206-ssl-vpn/client.crt", SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stderr);
        exit(2);
    }
    if (SSL_CTX_use_PrivateKey_file(ctx, "/home/seed/ik2206-ssl-vpn/client.key", SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stderr);
        exit(3);
    }
    if (SSL_CTX_check_private_key(ctx) <= 0) {
        ERR_print_errors_fp(stderr);
        exit(4);
    }
    if (SSL_CTX_load_verify_locations(ctx, "/home/seed/ik2206-ssl-vpn/ca.crt", NULL) <= 0) {
        ERR_print_errors_fp(stderr);
        exit(5);
    }
    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, NULL);

    bio = BIO_new_ssl_connect(ctx);
    
    BIO_get_ssl(bio, &ssl);

    if (!ssl) {
      ERR_print_errors_fp(stderr);
        exit(6);
    }

    /* Don't want any retries */
    SSL_set_mode(ssl, SSL_MODE_AUTO_RETRY);
    /* We might want to do other things with ssl here */

    // set connection parameters
    BIO_set_conn_hostname(bio, remote_ip);
    BIO_set_conn_port(bio, "4433");

    // create a buffer to print to the screen
    out = BIO_new_fp(stdout, BIO_NOCLOSE);

    // establish a connection to the server
    //printf("Attempting to to connect to the server... ");
    if (BIO_do_connect(bio) <= 0) {
      fprintf(stderr, "Error connecting to server\n");
      ERR_print_errors_fp(stderr);
      BIO_free_all(bio);
      BIO_free(out);
      SSL_CTX_free(ctx);
      exit(1);
    }
    printf("SUCCESS!\n");

    // initiate the handshake with the server
    printf("Initiating SSL handshake with the server... \n");
    if (BIO_do_handshake(bio) <= 0) {
      fprintf(stderr, "Error establishing SSL connection\n");
      ERR_print_errors_fp(stderr);
      BIO_free_all(bio);
      BIO_free(out);
      SSL_CTX_free(ctx);
      exit(1);
    }
    printf("SUCCESS!\n");
    // Get the random number from the server
    printf("Waiting for random number from server... \n");
    memset(tmpbuf, '\0', 11);
    memset(number, '\0', 11);
    int len = BIO_read(bio, tmpbuf, 10);
    strcpy(number, tmpbuf);
    printf("SUCCESS!\nRandom number is: %s\n", number);
    SSL_SESSION *session =SSL_get_session(ssl);
    //SSL_SESSION_print(out, session);
    printf("MASTERKEY:\n");
    print_hex(session->master_key, session->master_key_length);
    printf("copying key:\n");
    memcpy(key, (session->master_key), 256);
    print_hex(key, 32);
    printf("copying iv:\n");
    memcpy(iv, &(session->master_key[32]), 128);
    print_hex(iv, 16);

  } else {
    ctx = SSL_CTX_new(SSLv23_server_method());
    if (!ctx) {
        ERR_print_errors_fp(stderr);
        exit(1);
    }
    if (SSL_CTX_use_certificate_file(ctx,"/home/seed/ik2206-ssl-vpn/server.crt", SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stderr);
        exit(2);
    }
    if (SSL_CTX_use_PrivateKey_file(ctx, "/home/seed/ik2206-ssl-vpn/server.key", SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stderr);
        exit(3);
    }
    if (SSL_CTX_check_private_key(ctx) <= 0) {
        ERR_print_errors_fp(stderr);
        exit(4);
    }
    if (SSL_CTX_load_verify_locations(ctx, "/home/seed/ik2206-ssl-vpn/ca.crt", NULL) <= 0) {
        ERR_print_errors_fp(stderr);
        exit(5);
    }
    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, NULL);

    /* New SSL BIO setup as server */
    bio = BIO_new_ssl(ctx, 0);

    BIO_get_ssl(bio, &ssl);

    if (!ssl) {
      ERR_print_errors_fp(stderr);
        exit(6);
    }

    /* Create the buffering BIO */
    bbio = BIO_new(BIO_f_buffer());

    /* Add to chain */
    bio = BIO_push(bbio, bio);

    acpt = BIO_new_accept("4433");
    /* By doing this when a new connection is established
     * we automatically have bio inserted into it. The
     * BIO chain is now 'swallowed' by the accept BIO and
     * will be freed when the accept BIO is freed.
     */
    BIO_set_accept_bios(acpt, bio);

    /* Setup accept BIO */
    printf("Setting up the accept BIO... \n");
    if (BIO_do_accept(acpt) <= 0) {
      fprintf(stderr, "Error setting up accept BIO\n");
      ERR_print_errors_fp(stderr);
      return (0);
    }
    printf("SUCCESS!\n");

    /* Now wait for incoming connection */
    printf("Setting up the incoming connection... \n");
    if (BIO_do_accept(acpt) <= 0) {
      fprintf(stderr, "Error in connection\n");
      ERR_print_errors_fp(stderr);
      return (0);
    }
    printf("SUCCESS!\n");

    /* We only want one connection so remove and free
     * accept BIO
     */

    bio = BIO_pop(acpt);

    BIO_free_all(acpt);

    // wait for ssl handshake from the client
    printf("Waiting for SSL handshake...\n");
    if (BIO_do_handshake(bio) <= 0) {
      fprintf(stderr, "Error in SSL handshake\n");
      ERR_print_errors_fp(stderr);
      return (0);
    }
    printf("SUCCESS!\n");
    // generate the random number for the challenge
    srand((unsigned)time(NULL));
    sprintf(number, "%d", rand());

    // send the random number to the client
    printf("Sending the random number challenge to the client. Number is %s... \n", number);
    if (BIO_write(bio, number, strlen(number)) <= 0) {
      fprintf(stderr, "Error in sending random number\n");
      ERR_print_errors_fp(stderr);
      exit(1);
    }
    printf("SUCCESS!\n");

    BIO_flush(bio);
    
    out = BIO_new_fp(stdout, BIO_NOCLOSE);
    //// Get the random number from the server
    //printf("Waiting for random number from client... \n");
    //memset(tmpbuf, '\0', 11);
    //memset(number, '\0', 11);
    //int len = BIO_read(bio, tmpbuf, 10);
    //strcpy(number, tmpbuf);
    //printf("SUCCESS!\nRandom number is: %s\n", number);
    sleep(1); // sometimes the ssl pointer is not ready?
    BIO_get_ssl(bio, &ssl);
    SSL_SESSION *session =SSL_get_session(ssl);
    //SSL_SESSION_print(out, session);
    printf("MASTERKEY:\n");
    print_hex(session->master_key, session->master_key_length);
    printf("copying key:\n");
    memcpy(key, (session->master_key), 256);
    print_hex(key, 32);
    printf("copying iv:\n");
    memcpy(iv, &(session->master_key[32]), 128);
    print_hex(iv, 16);
  }

  /* initialize tun/tap interface */
  if ( (tap_fd = tun_alloc(if_name, flags | IFF_NO_PI)) < 0 ) {
    my_err("Error connecting to tun/tap interface %s!\n", if_name);
    exit(1);
  }

  do_debug("Successfully connected to interface %s\n", if_name);

  if ( (sock_fd = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
    perror("socket()");
    exit(1);
  }

  if(cliserv==CLIENT){
    /* Client, try to connect to server */

    /* assign the destination address */
    memset(&local, 0, sizeof(local));
    local.sin_family = AF_INET;
    local.sin_addr.s_addr = htonl(INADDR_ANY); /*accept any IP*/
    local.sin_port = htons(port);

    /* bind request */
    if (bind(sock_fd, (struct sockaddr*) &local, sizeof(local)) < 0){
      perror("bind()");
      exit(1);
    }

    memset(&remote, 0, sizeof(remote));
    remote.sin_family = AF_INET;
    remote.sin_addr.s_addr = inet_addr(remote_ip);
    remote.sin_port = htons(port);
    remotelen = sizeof(remote);

    net_fd = sock_fd;
    do_debug("CLIENT: Connected to server %s\n", inet_ntoa(remote.sin_addr));
    
  } else {
    /* Server, wait for connections */

    /* avoid EADDRINUSE error on bind() */
    if(setsockopt(sock_fd, SOL_SOCKET, SO_REUSEADDR, (char *)&optval, sizeof(optval)) < 0){
      perror("setsockopt()");
      exit(1);
    }
    
    memset(&local, 0, sizeof(local));
    local.sin_family = AF_INET;
    local.sin_addr.s_addr = htonl(INADDR_ANY);
    local.sin_port = htons(port);
    if (bind(sock_fd, (struct sockaddr*) &local, sizeof(local)) < 0){
      perror("bind()");
      exit(1);
    }
    
    net_fd = sock_fd;
    memset(&remote, 0, sizeof(remote));
    remote.sin_family = AF_INET;
    remote.sin_addr.s_addr = inet_addr(remote_ip);
    remote.sin_port = htons(port);
    remotelen = sizeof(remote);

    do_debug("SERVER: Client connected from %s\n", inet_ntoa(remote.sin_addr));
  }
  
  /* use select() to handle two descriptors at once */
  maxfd = (tap_fd > net_fd)?tap_fd:net_fd;



  while(1) {
    int ret, cret;
    fd_set rd_set;
    fd_set console;
    struct timeval tv;

    FD_ZERO(&rd_set);
    FD_SET(tap_fd, &rd_set); FD_SET(net_fd, &rd_set);

    FD_ZERO(&console);
    FD_SET(0, &console);

    /* Wait up to five seconds. */
    tv.tv_sec = 5;
    tv.tv_usec = 0;

    ret = select(maxfd + 1, &rd_set, NULL, NULL, NULL);
    cret = select(1, &console, NULL, NULL, NULL);

    if (cret)
      printf("INPUT\n");

    if (ret < 0 && errno == EINTR){
      continue;
    }

    if (ret < 0) {
      perror("select()");
      exit(1);
    }

    if(FD_ISSET(tap_fd, &rd_set)){
      /* data from tun/tap: just read it and write it to the network */
      
      nread = cread(tap_fd, buffer, BUFSIZE);

      tap2net++;
      do_debug("TAP2NET %lu: Read %d bytes from the tap interface\n", tap2net, nread);

      /* write packet */
      nread = encrypt (buffer, nread, key, iv, temp);
      unsigned char* t = generate_hmac(key, temp);
      memcpy(temp+nread, t, 32);
      nwrite = sendto(net_fd, temp, nread+32, 0, (struct sockaddr*) &remote, remotelen); 
      if (nwrite < 0) {
        perror("Sending data");
        exit(1);
      }

      do_debug("TAP2NET %lu: Written %d bytes to the network\n", tap2net, nwrite);
    }

    if(FD_ISSET(net_fd, &rd_set)){
      /* data from the network: read it, and write it to the tun/tap interface. 
       * We need to read the length first, and then the packet */

      net2tap++;

      /* read packet */
      nread = recvfrom(net_fd, buffer, sizeof(buffer), 0, (struct sockaddr*)&remote, &remotelen);
      if (nread < 0) {
        perror("Reading data");
        exit(1);
      }

      do_debug("NET2TAP %lu: Read %d bytes from the network\n", net2tap, nread);
      memcpy(temp, buffer, nread-32);
      if (compare_hmac(key, temp, buffer+nread)){
          perror("Wrong");
          exit(1);
      }
      nread = decrypt(temp, nread-32, key, iv, buffer);
      /* now buffer[] contains a full packet or frame, write it into the tun/tap interface */ 
      nwrite = cwrite(tap_fd, buffer, nread);
      do_debug("NET2TAP %lu: Written %d bytes to the tap interface\n", net2tap, nwrite);
    }
  }

  /* Close the connection and free the context */
  BIO_free_all(bio);
  SSL_CTX_free(ctx);

  return (0);
}