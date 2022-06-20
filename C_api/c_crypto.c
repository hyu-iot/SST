#include "c_crypto.h"
/*
    function:
    input:
    output:
*/
/*
    function: prints error message
    input: Error message to display
    output: input message & openssl error
*/
void print_last_error(char *msg){
    char * err = malloc(130);;
    ERR_load_crypto_strings();
    ERR_error_string(ERR_get_error(), err);
    printf("%s ERROR: %s\n",msg, err);
    free(err);
}

//TODO: 영빈이형 여기 check input 순서 맞추려고 input 순서 바꿈. 확인시 지워줭.

/*
    function: read X509cert.pem file & get pubkey from 'path'. RSA_public_encrypt 'data' to 'ret' with 'padding'
    input: 'ret': encrypted buf, 'data': data to encrypt
    output: length of encrypted data
*/
int public_encrypt(unsigned char *ret, unsigned char * data, int * data_len,  int padding, char * path) {
    FILE *pemFile = fopen(path, "rb");
    X509 *cert = PEM_read_X509(pemFile, NULL, NULL, NULL );
    EVP_PKEY *pkey = X509_get_pubkey(cert);
    if (pkey == NULL){
        print_last_error("public key getting fail");
    }
    int id = EVP_PKEY_id(pkey);
    if ( id != EVP_PKEY_RSA ) {
        print_last_error("is not RSA Encryption file");
    }
    RSA *rsa = EVP_PKEY_get1_RSA(pkey);
    if ( rsa == NULL ) {
        print_last_error("EVP_PKEY_get1_RSA fail");
    }
    int result = RSA_public_encrypt(*data_len, data, ret, rsa, padding);
    if(result == -1){ // RSA_public_encrypt() returns -1 on error
        print_last_error("Public Encrypt failed!\n");
        exit(0);
    }
    else{
        printf("Public Encryption Success!\n");
    }
    return result; // RSA_public_encrypt() returns the size of the encrypted data 
}

//TODO: 영빈이형 여기도 순서 바뀌었엉

/*
    function: read PEM key from 'path'. RSA_Private_decrypt 'encrypted' and save in 'ret' with 'padding'
    input: 'ret': decrypted result buf, 'enc_data': data to decrypt
    output: return decrypted length
*/
int private_decrypt(unsigned char *ret, unsigned char * enc_data, int * enc_data_len, int padding, char * path){

    FILE *keyfile = fopen(path, "rb"); 
    RSA *rsa = PEM_read_RSAPrivateKey(keyfile, NULL, NULL, NULL);
    RSA *PEM_read_RSAPublicKey(FILE *fp, RSA **x,
                                        pem_password_cb *cb, void *u);
    int result = RSA_private_decrypt(*enc_data_len, enc_data, ret, rsa, padding);
    if(result == -1){  // RSA_private_decrypt() returns -1 on error
        print_Last_error("Private Decrypt failed!");
        exit(0);
    }
    else{
        printf("Private Decrypt Success!\n");
    }
    return result;
}

/*
    function: make sign to 'sigret' buf, with private key from 'path', and data 'encrypted' 
    input:'sigret': return signed buf, 'encrypted': data to sign
    output: 
*/
void SHA256_sign(unsigned char *sigret, unsigned int * sigret_length, unsigned char *encrypted, unsigned int *encrypted_length, char * path){

    FILE *keyfile = fopen(path, "rb"); 
    RSA *rsa = PEM_read_RSAPrivateKey(keyfile, NULL, NULL, NULL);
    unsigned char dig_enc[SHA256_DIGEST_LENGTH];
    make_digest_msg(dig_enc, encrypted, encrypted_length);

    int sign_result = RSA_sign(NID_sha256, dig_enc,SHA256_DIGEST_LENGTH,
          sigret, sigret_length, rsa);
    if(sign_result == 1)
        printf("Sign successed! \n");
    else
        print_Last_error("Sign failed! \n");
}

/*
    function: Checks if sign and data verified. needs to digest message.
    input:
    output: error when verify fails
*/
//TODO: 동하가 고치기
void SHA256_verify(unsigned char * data, unsigned int * data_length, unsigned char * sign, unsigned int * sign_length, char * path){
    FILE *pemFile = fopen(path, "rb");
    X509 *cert = PEM_read_X509( pemFile, NULL, NULL, NULL );
    EVP_PKEY *pkey = X509_get_pubkey(cert);
    if (pkey == NULL){
        print_Last_error("public key getting fail");
    }
    int id = EVP_PKEY_id(pkey);
    if ( id != EVP_PKEY_RSA ) {
        print_Last_error("is not RSA Encryption file");
    }
    RSA *rsa = EVP_PKEY_get1_RSA(pkey);
    if ( rsa == NULL ) {
        print_Last_error("EVP_PKEY_get1_RSA fail");
    }
    // verify! 
    unsigned char digest_buf[SHA256_DIGEST_LENGTH];
    make_digest_msg(digest_buf, data, data_length);
    // RSA * rsa2 = create_RSA(authPublicKey,true);   
    int verify_result = RSA_verify(NID_sha256, digest_buf,SHA256_DIGEST_LENGTH,
          sign, sign_length, rsa);

    if(verify_result ==1)
        printf("verify success\n\n");
    else{
        print_Last_error("verify failed\n");
    }
}
/*
    function: make SHA256 digest message
    input:
    output:
*/
void SHA256_make_digest_msg(unsigned char *dig_enc, unsigned char *encrypted ,int encrypted_length){
    SHA256_CTX ctx;
    SHA256_Init(&ctx);
    SHA256_Update(&ctx, encrypted, encrypted_length); 
    SHA256_Final(dig_enc, &ctx);   
}

void AES_CBC_128_encrypt(unsigned char * ret, unsigned int * ret_length, unsigned char * plaintext, unsigned int plaintext_length, unsigned char * key, unsigned int key_length, unsigned char * iv, unsigned int iv_length){ 
    unsigned char iv_temp[16];
    memcpy(iv_temp, iv, 16);
    AES_KEY enc_key_128;
    if(AES_set_encrypt_key(key, 128, &enc_key_128) < 0){
        error_handling("AES key setting failed!") ;
    }; 
    AES_cbc_encrypt(plaintext, ret, plaintext_length , &enc_key_128, iv_temp, AES_ENCRYPT);  //iv 가 바뀐다.
    *ret_length = ((plaintext_length) +iv_length)/iv_length *iv_length;
}
void AES_CBC_128_decrypt(unsigned char * ret, unsigned int * ret_length, unsigned char * encrypted, unsigned int encrypted_length, unsigned char * key, unsigned int key_length, unsigned char  * iv, unsigned int iv_length){ 
    AES_KEY enc_key_128;
    if(AES_set_decrypt_key(key, 128, &enc_key_128) < 0){
        error_handling("AES key setting failed!") ;
    }; 
    AES_cbc_encrypt(encrypted, ret, encrypted_length, &enc_key_128, iv, AES_DECRYPT); //iv가 바뀐다??
    *ret_length = ((encrypted_length) +iv_length)/iv_length *iv_length;
}