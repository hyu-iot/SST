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
void print_last_error(char *msg)
{
    char * err = malloc(130);;
    ERR_load_crypto_strings();
    ERR_error_string(ERR_get_error(), err);
    printf("%s ERROR: %s\n",msg, err);
    free(err);
}

//TODO: �������� ���� check input ���� ���߷��� input ���� �ٲ�. Ȯ�ν� �����a.

/*
    function: read X509cert.pem file & get pubkey from 'path'. RSA_public_encrypt 'data' to 'ret' with 'padding'
    input: 'ret': encrypted buf, 'data': data to encrypt
    output: length of encrypted data
*/
int public_encrypt(unsigned char * data, int data_len,  int padding, char * path, unsigned char *ret) 
{
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
    int result = RSA_public_encrypt(data_len, data, ret, rsa, padding);
    if(result == -1){ // RSA_public_encrypt() returns -1 on error
        print_last_error("Public Encrypt failed!\n");
        exit(0);
    }
    else{
        printf("Public Encryption Success!\n");
    }
    return result; // RSA_public_encrypt() returns the size of the encrypted data 
}

//TODO: �������� ���⵵ ���� �ٲ����

/*
    function: read PEM key from 'path'. RSA_Private_decrypt 'encrypted' and save in 'ret' with 'padding'
    input: 'ret': decrypted result buf, 'enc_data': data to decrypt
    output: return decrypted length
*/
int private_decrypt(unsigned char * enc_data, int enc_data_len, int padding, char * path, unsigned char *ret)
{
    FILE *keyfile = fopen(path, "rb"); 
    RSA *rsa = PEM_read_RSAPrivateKey(keyfile, NULL, NULL, NULL);
    RSA *PEM_read_RSAPublicKey(FILE *fp, RSA **x,
                                        pem_password_cb *cb, void *u);
    int result = RSA_private_decrypt(enc_data_len, enc_data, ret, rsa, padding);
    if(result == -1){  // RSA_private_decrypt() returns -1 on error
        print_last_error("Private Decrypt failed!");
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
void SHA256_sign(unsigned char *encrypted, unsigned int encrypted_length, char * path, unsigned char *sigret, unsigned int * sigret_length)
{
    FILE *keyfile = fopen(path, "rb"); 
    RSA *rsa = PEM_read_RSAPrivateKey(keyfile, NULL, NULL, NULL);
    unsigned char dig_enc[SHA256_DIGEST_LENGTH];
    make_digest_msg(dig_enc, encrypted, encrypted_length);

    int sign_result = RSA_sign(NID_sha256, dig_enc,SHA256_DIGEST_LENGTH,
          sigret, sigret_length, rsa);
    if(sign_result == 1)
        printf("Sign successed! \n");
    else
        print_last_error("Sign failed! \n");
}

/*
    function: Checks if sign and data verified. needs to digest message.
    input:
    output: error when verify fails
*/

void SHA256_verify(unsigned char * data, unsigned int data_length, unsigned char * sign, unsigned int sign_length, char * path)
{
    FILE *pemFile = fopen(path, "rb");
    X509 *cert = PEM_read_X509( pemFile, NULL, NULL, NULL );
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
    // verify! 
    unsigned char digest_buf[SHA256_DIGEST_LENGTH];
    make_digest_msg(data, data_length, digest_buf);
    // RSA * rsa2 = create_RSA(authPublicKey,true);   
    int verify_result = RSA_verify(NID_sha256, digest_buf,SHA256_DIGEST_LENGTH,
          sign, sign_length, rsa);

    if(verify_result ==1)
        printf("verify success\n\n");
    else{
        print_last_error("verify failed\n");
    }
}
/*
    function: make SHA256 digest message
    input:
    output:
*/
void SHA256_make_digest_msg(unsigned char *encrypted ,int encrypted_length, unsigned char *dig_enc)
{
    SHA256_CTX ctx;
    SHA256_Init(&ctx);
    SHA256_Update(&ctx, encrypted, encrypted_length); 
    SHA256_Final(dig_enc, &ctx);   
}

void AES_CBC_128_encrypt(unsigned char * plaintext, unsigned int plaintext_length, unsigned char * key, unsigned int key_length, unsigned char * iv, unsigned int iv_length, unsigned char * ret, unsigned int * ret_length)
{ 
    unsigned char iv_temp[AES_CBC_128_IV_SIZE];
    memcpy(iv_temp, iv, AES_CBC_128_IV_SIZE);
    //TODO: check iv changing. if not needed, erase.
    AES_KEY enc_key_128;
    if(AES_set_encrypt_key(key, AES_CBC_128_KEY_SIZE, &enc_key_128) < 0){
        error_handling("AES key setting failed!") ;
    }; 
    AES_cbc_encrypt(plaintext, ret, plaintext_length , &enc_key_128, iv_temp, AES_ENCRYPT);  //iv �� �ٲ��.
    *ret_length = ((plaintext_length) +iv_length)/iv_length *iv_length;
}

void AES_CBC_128_decrypt(unsigned char * encrypted, unsigned int encrypted_length, unsigned char * key, unsigned int key_length, unsigned char  * iv, unsigned int iv_length, unsigned char * ret, unsigned int * ret_length)
{ 
    AES_KEY enc_key_128;
    if(AES_set_decrypt_key(key, AES_CBC_128_KEY_SIZE, &enc_key_128) < 0){
        error_handling("AES key setting failed!") ;
    }; 
    AES_cbc_encrypt(encrypted, ret, encrypted_length, &enc_key_128, iv, AES_DECRYPT); //iv�� �ٲ��??
    *ret_length = ((encrypted_length) +iv_length)/iv_length *iv_length;
}

//encrypt buf to ret with mac_key, cipher_key
//iv16+encrypted_data+HMAC_tag32
/*
function: 

input:  buf: buf to encrypt
        mac_key: for hmac. Mostly will be session_key's mac_key.
        cipher_key: for encryption. Mostly will be session_key's cipher_key.
        mac_key_size, cipher_key_size, iv_size: put in from config.
        ret_length: the returning buffer's length.
return: unsigned char *. iv+encrypted_data+HMAC_tag ex)16 + n + 32

usage:
    unsigned int encrypted_length;
    unsigned char encrypted = symmetric_encrypt_authenticate(buf_to_encrypt, buf_to_encrypt_length, mac_key, MAC_KEY_SIZE, cipher_key, CIPHER_KEY_SIZE, AES_CBC_128_IV_SIZE, &encrypted_length);
    ~~ use 'encrypted' ~~
    free(encrypted); //never forget!!
*/

unsigned char * symmetric_encrypt_authenticate(unsigned char * buf, unsigned int buf_length, unsigned char * mac_key, unsigned int mac_key_size, unsigned char * cipher_key, unsigned int cipher_key_size, unsigned int iv_size, unsigned int * ret_length){
    unsigned char * iv = (unsigned char *) malloc(iv_size);
    generate_nonce(iv_size, iv);
    unsigned int encrypted_length = ((buf_length/iv_size)+1)*iv_size;
    unsigned char * encrypted = (unsigned char *) malloc(encrypted_length);
    AES_CBC_128_encrypt(buf, buf_length, cipher_key, CIPHER_KEY_SIZE, iv, iv_size, encrypted, &encrypted_length);

    unsigned int temp_length = ((buf_length/iv_size)+1)*iv_size + iv_size;
    unsigned char * temp = (unsigned char *) malloc(temp_length);
    memcpy(temp, iv, iv_size);
    memcpy(temp+iv_size, encrypted, encrypted_length);
    temp_length = iv_size + encrypted_length;
    unsigned char * hmac_tag = (unsigned char *) malloc(mac_key_size);
    HMAC(EVP_sha256(), mac_key, MAC_KEY_SIZE, temp, temp_length, hmac_tag, &mac_key_size );
    
    *ret_length = temp_length + mac_key_size;
    unsigned char * ret = (unsigned char *) malloc(*ret_length);
    memcpy(ret, temp, temp_length);
    memcpy(ret + temp_length, hmac_tag, mac_key_size);
    free(encrypted);free(temp);free(iv);free(hmac_tag);
    return ret;
}

void symmetric_decrypt_authenticate(unsigned char * buf, unsigned int buf_length, unsigned char * mac_key, unsigned char * cipher_key, unsigned char * ret, unsigned int *ret_length){ //TODO: add options.distributionCryptoSpec, TODO: may need to change sturct
    int mac_key_size = MAC_KEY_SIZE; //js code has get_mac_key_size()
    unsigned char enc[512]; //TODO: SIZE check
    unsigned int enc_length;
    memcpy(enc, buf, buf_length - mac_key_size);
    enc_length = buf_length - mac_key_size;
    unsigned char received_tag[MAC_KEY_SIZE];
    unsigned int received_tag_length = MAC_KEY_SIZE;
    memcpy(received_tag, buf + buf_length - mac_key_size, mac_key_size);
    received_tag_length = mac_key_size;
    unsigned char hmac_tag[MAC_KEY_SIZE];
    unsigned int hmac_tag_length = MAC_KEY_SIZE;
    HMAC(EVP_sha256(), mac_key, mac_key_size, enc, enc_length, hmac_tag, &hmac_tag_length );
    if(strncmp(received_tag, hmac_tag, mac_key_size) != 0){
        error_handling("Ivalid MAC error!");
    }
    else{
        printf("MAC verified!\n");
    }
    int iv_length = AES_CBC_128_IV_SIZE; //16  TODO: implement getCipherIvSize
    unsigned char iv[AES_CBC_128_IV_SIZE];
    memcpy(iv, enc, iv_length);

    unsigned char temp[512]; //TODO: SIZE check
    unsigned int temp_length;
    memcpy(temp, enc+iv_length, enc_length - iv_length);
    temp_length = enc_length - iv_length;
    AES_CBC_128_decrypt(temp, temp_length, cipher_key, CIPHER_KEY_SIZE, iv, iv_length, ret, ret_length);
}