#include "common.h"



void error_handling(char *message){
    fputs(message, stderr);
    fputc('\n', stderr);
    exit(1);
}

void print_in_hex(UCHAR * var, UINT length){
    for (int i = 0; i < length; i++){
        printf("%x ", var[i]);    
    }
    printf("\n");
}

void check_read_error(UINT length){
    if(length == -1){
        error_handling("read() error!");
    }
}

void generate_nonce(UCHAR * generated, UINT size){
    int rc = RAND_bytes(generated, size);
    if(rc == -1){
        printf("Failed to create randomNonce.");
        exit(1);
    }
}

void write_in_4bytes(UCHAR num, UCHAR * buf){
    buf[0] = (num >> 24) & 0xFF;
    buf[1] = (num >> 16) & 0xFF;
    buf[2] = (num >> 8) & 0xFF;
    buf[3] = num & 0xFF;
}

void write_in_8bytes(long int num, UCHAR * buf){
    buf[0] = (num >> 56) & 0xFF;
    buf[1] = (num >> 48) & 0xFF;
    buf[2] = (num >> 40) & 0xFF;
    buf[3] = (num >> 32) & 0xFF;
    buf[4] = (num >> 24) & 0xFF;
    buf[5] = (num >> 16) & 0xFF;
    buf[6] = (num >> 8) & 0xFF;
    buf[7] = num & 0xFF;
}

unsigned int read_uint_BE(unsigned char *buf, unsigned int offset, unsigned int byte_length){
    unsigned int ret = 0;
    for (int i = 0; i < byte_length; i ++){
        ret += buf[offset + i] * pow(16, (byte_length -1 -i)*2);
    }
    return ret;
}

//reads first 4bytes to UINT in big endian ( 12 34 56 78 => 12345678 => decimal)
UINT read_uint_32BE(UCHAR *buf){
    UINT ret;
    ret = buf[0] * pow(16, 3) + buf[1] * pow(16,2) +buf[2] * 16 + buf[3];
    return ret;
}

// parses received message into received (msg_type, payload_length, payload_buffer)
void parse_IoT_SP(received * received){
    received->message_type = received->received_buf[0];
    var_length_int_to_num(received->received_buf, received->received_buf_length, &received->payload_length, 1);
    memcpy(received->payload , received->received_buf + 1 + received->payload_length.buf_len , received->payload_length.num);
}

void parse_string_param(UCHAR *return_to, UINT * return_to_length, UCHAR * buf, UINT buf_length,int offset){
    payload_length_t ret;
    var_length_int_to_num(buf, buf_length, &ret ,offset);
    if(ret.buf_len == 0){
        *return_to_length = 1;
        memset(return_to, 0, *return_to_length);
    }
    memcpy(return_to, buf + offset+ ret.buf_len, ret.num);
    *return_to_length = ret.buf_len + ret.num ;
}

void * scan_command(){
    char str[MAX_MSG_LENGTH];
    while(1){       
        fgets(str, MAX_MSG_LENGTH, stdin);
        char * command;
        command = strtok (str," ");
        if(strcmp(command, "send") == 0){
            char * msg = str + strlen(command) + 1;
            for(int i = 0; i < client_list.client_list_length; i ++){
                send_message(msg, &client_list.client_list[i]);
            }
        }
    }
}

//make header + payload

void num_to_var_length_int(payload_length_t *buf){
    int num = buf->num;
    buf->buf_len= 1;
    while(num > 127)
    {
        buf->buf[buf->buf_len-1] = 128 | num & 127;
        buf->buf_len += 1;
        num >>=7;
    }
    buf->buf[buf->buf_len-1] = num;
}

void var_length_int_to_num(UCHAR * buf, UINT buf_length, payload_length_t * payload_length, int offset){
    UINT num = 0;
    for( int i = 0; i < buf_length && i < 5; i++) {
        num |= (buf[offset + i] & 127) << (7 * i);
        if ((buf[offset + i] & 128) == 0) {
            payload_length->num = num;
            payload_length->buf_len = i +1;
            break;
        }
    }
}

void make_buffer_header(UCHAR *header, UINT * header_length, UCHAR *payload, UINT payload_length, UCHAR MESSAGE_TYPE){
    payload_length_t payload_length_buf; //without struct, error
    payload_length_buf.num = payload_length;
    num_to_var_length_int(&payload_length_buf);
    *header_length = MSG_TYPE_SIZE + payload_length_buf.buf_len;
    header[0] = MESSAGE_TYPE;
    memcpy(header + MSG_TYPE_SIZE, payload_length_buf.buf, payload_length_buf.buf_len);
}

void concat_buffer_header_and_payload(UCHAR *ret, UINT * ret_length, UCHAR *header, UINT header_length, UCHAR *payload, UINT payload_length){
    memcpy(ret, header, header_length);
    memcpy(ret + header_length, payload, payload_length);
    *ret_length = header_length + payload_length;
}

void make_sender_buf(UCHAR *sender, UINT * sender_length, UCHAR *payload, UINT payload_length, UCHAR MESSAGE_TYPE){
    UCHAR header[5];
    UINT header_length;
    make_buffer_header(header, &header_length, payload, payload_length, MESSAGE_TYPE);
    concat_buffer_header_and_payload(sender, sender_length, header, header_length, payload, payload_length);
}


//crypto part



void print_Last_error(char *msg){
    char * err = malloc(130);;
    ERR_load_crypto_strings();
    ERR_error_string(ERR_get_error(), err);
    printf("%s ERROR: %s\n",msg, err);
    free(err);
}

int public_encrypt(UCHAR * data, int data_len, UCHAR *encrypted, int padding, char * path) {
    FILE *pemFile = fopen(path, "rb");
    X509 *cert = PEM_read_X509(pemFile, NULL, NULL, NULL );
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
    int result = RSA_public_encrypt(data_len,data,encrypted, rsa,padding);
    if(result == -1){ // RSA_public_encrypt() returns -1 on error
        print_Last_error("Public Encrypt failed!\n");
        exit(0);
    }
    else{
        printf("Public Encryption Success!\n");
    }
    return result; // RSA_public_encrypt() returns the size of the encrypted data 
}

int private_decrypt(UCHAR * enc_data,int data_len, UCHAR *decrypted, int padding, char * path){
    ///mnt/c/Users/user/project/iotauth/entity/credentials/keys/net1/Net1.ClientKey.pem
    //client�� ����Ű
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

void sign(UCHAR *sigret, UINT * sigret_length, UCHAR *encrypted, UINT encrypted_length, char * path){
    //TODO: input ����
    FILE *keyfile = fopen(path, "rb"); 
    RSA *rsa = PEM_read_RSAPrivateKey(keyfile, NULL, NULL, NULL);
    UCHAR dig_enc[SHA256_DIGEST_LENGTH];
    make_digest_msg(dig_enc, encrypted, encrypted_length);

    int sign_result = RSA_sign(NID_sha256, dig_enc,SHA256_DIGEST_LENGTH,
          sigret, sigret_length, rsa);
    if(sign_result == 1)
        printf("Sign successed! \n");
    else
        print_Last_error("Sign failed! \n");
}

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
    UCHAR distribution_key_buf_dig[SHA256_DIGEST_LENGTH];
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

void AES_CBC_128_encrypt(UCHAR * ret, UINT * ret_length,UCHAR * plaintext, UINT plaintext_length,UCHAR * key, UINT key_length,UCHAR  * iv,UINT iv_length){ 
    UCHAR iv_temp[16];
    memcpy(iv_temp, iv, 16);
    AES_KEY enc_key_128;
    if(AES_set_encrypt_key(key, 128, &enc_key_128) < 0){
        error_handling("AES key setting failed!") ;
    }; 
    AES_cbc_encrypt(plaintext, ret, plaintext_length , &enc_key_128, iv_temp, AES_ENCRYPT);  //iv �� �ٲ��.
    *ret_length = ((plaintext_length) +iv_length)/iv_length *iv_length;
}
void AES_CBC_128_decrypt(UCHAR * ret, UINT * ret_length, UCHAR * encrypted, UINT encrypted_length, UCHAR * key, UINT key_length, UCHAR  * iv, UINT iv_length){ 
    AES_KEY enc_key_128;
    if(AES_set_decrypt_key(key, 128, &enc_key_128) < 0){
        error_handling("AES key setting failed!") ;
    }; 
    AES_cbc_encrypt(encrypted, ret, encrypted_length, &enc_key_128, iv, AES_DECRYPT); //iv�� �ٲ��??
    *ret_length = ((encrypted_length) +iv_length)/iv_length *iv_length;
}

void make_digest_msg(UCHAR *dig_enc, UCHAR *encrypted ,int encrypted_length){
    SHA256_CTX ctx;
    SHA256_Init(&ctx);
    SHA256_Update(&ctx, encrypted, encrypted_length); 
    SHA256_Final(dig_enc, &ctx);   
}

//encrypt buf to ret with symmetric_key_set
//iv16+encrypted_data32+HMAC_tag
void symmetric_encrypt_authenticate(UCHAR * ret, UINT * ret_length, UCHAR * buf, UINT buf_length, key_set* symmetric_key_set){
    UCHAR iv[AES_BLOCK_SIZE];
    UINT iv_length;
    iv_length = AES_BLOCK_SIZE;
    generate_nonce(iv, iv_length);
    UCHAR encrypted[512];
    UINT encrypted_length;
    AES_CBC_128_encrypt(encrypted, &encrypted_length, buf, buf_length, symmetric_key_set->cipher_key_val, symmetric_key_set->cipher_key_val_length,iv, iv_length);
    UCHAR temp[512];
    UINT temp_length;
    memcpy(temp, iv, iv_length);
    memcpy(temp+iv_length, encrypted, encrypted_length);
    temp_length = iv_length + encrypted_length;
    int mac_size = 32;
    UCHAR tag[512];
    UINT tag_length;
    HMAC(EVP_sha256(), symmetric_key_set->mac_key_val, symmetric_key_set->mac_key_val_length, temp, temp_length, tag, &tag_length );
    memcpy(ret, temp, temp_length);
    memcpy(ret + temp_length, tag, tag_length);
    *ret_length = temp_length + tag_length;
}

void symmetric_decrypt_authenticate(UCHAR * ret, UINT *ret_length, UCHAR * buf, UINT buf_length, key_set* symmetric_key_set){ //TODO: add options.distributionCryptoSpec, TODO: may need to change sturct
    int mac_size = 32; //TODO: need to implement get_Mac_Size
    UCHAR enc[512];
    UINT enc_length;
    memcpy(enc, buf, buf_length - mac_size);
    enc_length = buf_length - mac_size;
    UCHAR received_tag[512];
    UINT received_tag_length;
    memcpy(received_tag, buf + buf_length - mac_size, mac_size);
    received_tag_length = mac_size;
    UCHAR hmac[512];
    UINT hmac_length;
    HMAC(EVP_sha256(), symmetric_key_set->mac_key_val, symmetric_key_set->mac_key_val_length, enc, enc_length, hmac, &hmac_length );
    if(strncmp(received_tag, hmac, mac_size) != 0){
        error_handling("Ivalid MAC error!");
    }
    else{
        // printf("MAC verified!\n");
    }
    int iv_size = AES_BLOCK_SIZE; //16  TODO: implement getCipherIvSize
    UCHAR iv[512];
    UINT iv_length;
    memcpy(iv, enc, iv_size);
    iv_length = iv_size;

    UCHAR temp[512];
    UINT temp_length;
    memcpy(temp, enc+iv_size, enc_length - iv_size);
    temp_length = enc_length - iv_size;
    AES_CBC_128_decrypt(ret, ret_length, temp, temp_length, symmetric_key_set->cipher_key_val, symmetric_key_set->cipher_key_val_length, iv, iv_length);
}

// RSA * create_RSA(UCHAR * key,bool public){
//     RSA *rsa= NULL;
//     BIO *keybio ;
//     keybio = BIO_new_mem_buf(key, -1); // �б� ���� �޸� ����� BIO
//     if (keybio==NULL){
//         printf( "Failed to create key BIO");
//         return 0;
//     }
//     /* PEM������ Ű ������ �о�ͼ� RSA ����ü �������� ��ȯ */
//     if(public){ // PEM public Ű�� RSA ����
//         rsa = PEM_read_bio_RSA_PUBKEY(keybio, &rsa, NULL, NULL);
//     }else{ // PEM private Ű�� RSA ����
//         rsa = PEM_read_bio_RSAPrivateKey(keybio, &rsa, NULL, NULL);
//     }
    
//     if(rsa == NULL){
//         printf( "Failed to create RSA");
//     }
//     return rsa;
// }

// server connection

void connection(int * sock, const char * ip_addr, const char * port_num){
    struct sockaddr_in serv_addr;
    received first_received;
    int str_len;

    //���� ����
    *sock = socket(PF_INET, SOCK_STREAM, 0);
    if(*sock == -1){
        error_handling("socket() error");
    }

    //�ش� �� 0���� �ʱ�ȭ, memset(�������ּ�, �ʱ�ȭ��, ����)
    memset(&serv_addr, 0, sizeof(serv_addr)); 
    serv_addr.sin_family = AF_INET; //�ּ� �йи�, IPv4�ǹ�

    //�����Ϸ��� ������ ip �ּ� ����, (command line ���� ����)
    //inet_addr( )�Լ��� ���ڿ� ���·� IP�ּҸ� �Է¹޾� 32��Ʈ ����(��Ʈ��ũ ����Ʈ ����)�� ����
    serv_addr.sin_addr.s_addr = inet_addr(ip_addr);

    //��Ʈ ��ȣ ���� 
    //atoi() -���� ��Ʈ���� ������ ��ȯ
    //htons() - ��Ʈ��ũ ����Ʈ ������ ��ȯ 
    serv_addr.sin_port = htons(atoi(port_num));

    /*
    ���� ��û �Լ� connect()
    int connect(
            int sockfd ���� ��ũ����, 
            const sockaddr *serv_addr ���� �ּ� ������ ���� ������ , 
            socklen_t addrlen �����Ͱ� ����Ű�� ����ü�� ũ��)   
    return: -1==����  0==����
    */
    
    if(connect(*sock, (struct sockaddr*)&serv_addr, sizeof(serv_addr)) == -1){
        error_handling("connect() error!");
    }
    printf("\n\n------------Connected-------------\n");
}

void connect_to_client(int * serv_sock, int * clnt_sock, const char * port_num){
    struct sockaddr_in serv_addr;
    struct sockaddr_in clnt_addr;
    socklen_t clnt_addr_size;
    *serv_sock = socket(PF_INET, SOCK_STREAM, 0);
    if(*serv_sock == -1){
        error_handling("socket() error");
    }
    memset(&serv_addr, 0, sizeof(serv_addr));
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_addr.s_addr = htonl(INADDR_ANY);
    serv_addr.sin_port=htons(atoi(port_num));

    if(bind(*serv_sock, (struct sockaddr*) &serv_addr, sizeof(serv_addr))==-1){
        error_handling("bind() error");
    }

    if(listen(*serv_sock, 5)==-1){
        error_handling("listen() error");
    }

    clnt_addr_size = sizeof(clnt_addr);
    *clnt_sock = accept(*serv_sock, (struct sockaddr*)&clnt_addr, &clnt_addr_size);
    if(*clnt_sock==-1){
        error_handling("accept() error");
    }
}

//handshake

void parse_handshake( parsed_handshake *ret, UCHAR *buf, UINT buf_length){
    int indicator = buf[0];
    if((indicator & 1) != 0){
        memcpy(ret->nonce, buf +1, HS_NONCE_SIZE);
    }
    if((indicator & 2) != 0){
        memcpy(ret->reply_nonce, buf +1 +HS_NONCE_SIZE, HS_NONCE_SIZE);
    }
    if((indicator & 4) != 0){
        memcpy(ret->nonce, buf +1 + HS_NONCE_SIZE*2, buf_length - (1 + HS_NONCE_SIZE*2));
    }
}

void serialize_handshake(UCHAR * ret, UINT * ret_length, UCHAR * nonce, UCHAR * reply_nonce ){
    // if(){} //TODO: common.js serializeHandshake
    *ret_length = 1 + HS_NONCE_SIZE *2;
    UCHAR indicator = 0;
    if(nonce != NULL){
        indicator += 1;
        memcpy(ret+1, nonce, HS_NONCE_SIZE);
    }
    if(reply_nonce != NULL){
        indicator += 2;
        memcpy(ret+1 +HS_NONCE_SIZE, reply_nonce, HS_NONCE_SIZE);
    }
    // if(nonce != NULL){
    //     indicator += 4;
    //     memcpy(ret, 1, HS_NONCE_SIZE);
    // }//TODO: common.js
    ret[0] = indicator;
}

//secure communication


void receive_message (UCHAR * ret, UINT * ret_length, UINT * seq_num, UCHAR * payload, UINT payload_length, parsed_session_key *parsed_session_key){
    UCHAR into[512];
    UINT into_length;
    memcpy(into, payload, payload_length);
    into_length = payload_length;
    UCHAR data[512];
    UINT data_length;
    symmetric_decrypt_authenticate(data, &data_length, into, into_length, &parsed_session_key->keys);
    parse_session_message(ret, ret_length, seq_num, data, data_length);
    printf("Received seq_num: %d\n", *seq_num);
    
}


void parse_session_message(UCHAR * ret, UINT * ret_length, UINT *seq_num, UCHAR * buf, UINT buf_length){
    *seq_num = read_uint_BE(buf, 0, SEQ_NUM_SIZE);
    memcpy(ret, buf+SEQ_NUM_SIZE, buf_length - SEQ_NUM_SIZE );
    *ret_length = buf_length - SEQ_NUM_SIZE;
}

//sends msg to client_list
void send_message(char * msg, connected_client_info * client){
    //iotSecureSocket.js 60 send
    //if() //TODO: check validity
    // if (!this.checkSessionKeyValidity()) {
    //     console.log('Session key expired!');
    //     return false;
    // }
    UCHAR seq_buf[SEQ_NUM_SIZE];
    write_in_8bytes((long) client->write_seq_num, seq_buf);
    UCHAR plaintext[SEQ_NUM_SIZE + MAX_MSG_LENGTH];
    UINT plaintext_length = SEQ_NUM_SIZE+strlen(msg);
    memcpy(plaintext, seq_buf, SEQ_NUM_SIZE);
    memcpy(plaintext+SEQ_NUM_SIZE, (UCHAR*) msg, strlen(msg));
    UCHAR encrypted[SEQ_NUM_SIZE + MAX_MSG_LENGTH];
    UINT encrypted_length;
    symmetric_encrypt_authenticate(encrypted, &encrypted_length, plaintext, plaintext_length, &client->session_key.keys);
    client->write_seq_num++;
    UCHAR sender_buf[5+ SEQ_NUM_SIZE + MAX_MSG_LENGTH];
    UINT sender_buf_length;
    make_sender_buf(sender_buf, &sender_buf_length, encrypted, encrypted_length, SECURE_COMM_MSG);
    write(client->socket, sender_buf,sender_buf_length);
}