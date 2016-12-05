#include "common.h"
#include "server.h"
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

int tcp_listen()
  {
    int sock;
    struct sockaddr_in sin;
    int val=1;
    
    if((sock=socket(AF_INET,SOCK_STREAM,0))<0){
      printf("Couldn't make socket");
      exit(1);
    }
    
    memset(&sin,0,sizeof(sin));
    sin.sin_addr.s_addr=INADDR_ANY;
    sin.sin_family=AF_INET;
    sin.sin_port=htons(PORT_TCP);
    setsockopt(sock,SOL_SOCKET,SO_REUSEADDR,
      &val,sizeof(val));
    
    if(bind(sock,(struct sockaddr *)&sin,
      sizeof(sin))<0){
      printf("Couldn't bind");
      exit(1);
    }
    listen(sock,5);  

    return(sock);
  }

void load_dh_params(ctx,file)
  SSL_CTX *ctx;
  char *file;
  {
    DH *ret=0;
    BIO *bio;

    if ((bio=BIO_new_file(file,"r")) == NULL) {
      printf("Couldn't open DH file");
      exit(1);
    } 

    ret=PEM_read_bio_DHparams(bio,NULL,NULL,
      NULL);
    BIO_free(bio);
    if(SSL_CTX_set_tmp_dh(ctx,ret)<0) {
      printf("Couldn't set DH parameters");
      exit(1);
    }
  }