#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <netdb.h>
#include <fcntl.h>
#include <signal.h>
#include <unistd.h>
#include <string.h>
#include <openssl/ssl.h>

SSL_CTX *initialize_ctx(char* crt_file, char* priv_key_file)
  {
    SSL_METHOD *meth;
    SSL_CTX *ctx;
    
    SSL_library_init();
    SSL_load_error_strings();

    
    /* Create our context*/
    meth=SSLv23_method();
    ctx=SSL_CTX_new(meth);

    /* Load our keys and certificates*/
    if(!(SSL_CTX_use_certificate_chain_file(ctx,
      "server.crt"))){
      printf("Can't read certificate file\n");
      exit(1);
    }

    if(!(SSL_CTX_use_PrivateKey_file(ctx,
      "server.key",SSL_FILETYPE_PEM))) { 
      printf("Can't read key file\n");
      exit(1);
   } 

    /* Load the CAs we trust*/
    if(!(SSL_CTX_load_verify_locations(ctx,
      "ca.crt",0))){
      printf("Can't read CA list\n");
      exit(1);
    }
    
    return ctx;
  }