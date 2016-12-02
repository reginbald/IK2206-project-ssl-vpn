#ifndef __HMAC_H__
#define __HMAC_H__

unsigned char* generate_hmac(unsigned char *key, unsigned char *data);

bool compare_hmac(unsigned char *key, unsigned char *data, unsigned char *hmac);

#endif