

void print_last_error(char *msg){
    char * err = malloc(130);;
    ERR_load_crypto_strings();
    ERR_error_string(ERR_get_error(), err);
    printf("%s ERROR: %s\n",msg, err);
    free(err);
}

int public_encrypt(unsigned char * data, int data_len, unsigned char *encrypted, int padding, char * path) {
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
    int result = RSA_public_encrypt(data_len,data,encrypted, rsa,padding);
    if(result == -1){ // RSA_public_encrypt() returns -1 on error
        print_last_error("Public Encrypt failed!\n");
        exit(0);
    }
    else{
        printf("Public Encryption Success!\n");
    }
    return result; // RSA_public_encrypt() returns the size of the encrypted data 
}


int private_decrypt(unsigned char * enc_data,int data_len, unsigned char *decrypted, int padding, char * path){

    FILE *keyfile = fopen(path, "rb"); 
    RSA *rsa = PEM_read_RSAPrivateKey(keyfile, NULL, NULL, NULL);
    RSA *PEM_read_RSAPublicKey(FILE *fp, RSA **x,
                                        pem_password_cb *cb, void *u);
    int result = RSA_private_decrypt(data_len,enc_data,decrypted,rsa,padding);
    if(result == -1){  // RSA_private_decrypt() returns -1 on error
        print_Last_error("Private Decrypt failed!");
        exit(0);
    }
    else{
        printf("Private Decrypt Success!\n");
    }
    return result;
}

void sign(unsigned char *sigret, unsigned int * sigret_length, unsigned char *encrypted, unsigned int encrypted_length, char * path){

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

//TODO: 동하가 고치기
void verify(signed_data *distribution_key_buf, char * path){
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
    unsigned char distribution_key_buf_dig[SHA256_DIGEST_LENGTH];
    make_digest_msg(distribution_key_buf_dig, distribution_key_buf->data, distribution_key_buf->data_length);
    // RSA * rsa2 = create_RSA(authPublicKey,true);   
    int verify_result = RSA_verify(NID_sha256, distribution_key_buf_dig,SHA256_DIGEST_LENGTH,
          distribution_key_buf->sign, distribution_key_buf->sign_length, rsa);

    if(verify_result ==1)
        printf("verify success\n\n");
    else{
        print_Last_error("verify failed\n");
    }
}