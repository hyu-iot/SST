#ifndef C_COMMON_H
#define C_COMMON_H

#include <stdio.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <string.h>
#include <stdint.h>
#include <time.h>
#include <math.h>
#include <openssl/rand.h>
#include <openssl/err.h>
#include <openssl/aes.h> 
#include <openssl/pem.h>
#include <openssl/bio.h>
#include <openssl/ssl.h>
#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/sha.h>
#include <openssl/x509.h>
#include <openssl/hmac.h>
#include <pthread.h>

void hello_yeongbin(int hi);
void print_buf(unsigned char * print_buffer, int n);
void generate_nonce(unsigned char * nonce_buf, int size_n);
void write_in_n_bytes(unsigned char * buffer, int num, int n);
void hello_dongha(int asd, int vid);
void temptemp(int hi);

#endif