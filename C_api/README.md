# Code Hiearchy
common -> crypto -> secure_server, secure_client -> main

# writing function rules

void function(input ..., return_pointer, return_length)

input buf, return_buf, return_buf_length: pointer
input length: unsigned int

void function(unsigned char * input_buf, unsigned int input_buf_length, unsigned char * ret, unsigned int * ret_length)

# C API

**void load_config()**

- �ٸ� �Լ��� input���� �� ������ sender, purpose, number of keys, crypto spec, pubkey path, privkey path ���� ������ config ���Ϸ� �ҷ����� �۾�
- config ����� user�� ����� �� �ְ� ������ ����
- �ٸ� �Լ����� load �ϰԵǸ� high computation, long running time�� �߻��ϹǷ� ���� �Լ��� ����
- return struct config

**void get_session_key()**
- entity client�� session key�� ��� ����
- input���δ� struct config
- return struct session_key

**void secure_connection()**
- entity server���� secure connection�� �ϱ����� ����
- input���δ� port, IP address, session key�� ����
- return secure socket

**void send_secure_message() **
- send secure message by encrypting with session key
- input���δ� session key, secure socket, message�� ����

**void wait_connection_message()**
- entity server�� client�� �Է��� ��ٸ��� ����
- input���δ� struct config
- return struct session_key


# git management
git pull (check if upstream commit exists) -> git add . , git commit -m "" (commit my work in local) -> git pull (auto merge. ctrl+x nano) -> code!

always commit at last.