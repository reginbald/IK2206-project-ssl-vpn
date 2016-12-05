#include "common.h"
#include "client.h"
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

int tcp_connect(host,port)
  char *host;
  int port;
  {
    struct hostent *hp;
    struct sockaddr_in addr;
    int sock;
    
    memset(&addr,0,sizeof(addr));
    addr.sin_addr.s_addr=inet_addr(host);
    addr.sin_family=AF_INET;
    addr.sin_port=htons(PORT_TCP);

    if((sock=socket(AF_INET,SOCK_STREAM,
      IPPROTO_TCP))<0){
      printf("Couldn't create socket\n");
      exit(1);
    }
    if(connect(sock,(struct sockaddr *)&addr,
      sizeof(addr))<0){
      printf("Couldn't connect socket");
      exit(1);
    }
    return sock;
  }