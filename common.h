#ifndef __COMMON_H__
#define __COMMON_H__
#include <openssl/ssl.h>
#define PORT_TCP "4433"

SSL_CTX *initialize_ctx(char* crt_file, char* priv_key_file);

#endif