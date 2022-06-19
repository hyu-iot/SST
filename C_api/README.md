# Code Hiearchy
common -> crypto -> secure_server, secure_client -> main

# writing function rules

void function(return_pointer, input ...)

every return and input buffers and lengths input with pointers

void function(unsigned char * ret, unsigned int * ret_length, unsigned char * input_buf, unsigned int * input_buf_length)

# C API

**void load_config()**

- 다른 함수의 input으로 들어갈 내용인 sender, purpose, number of keys, crypto spec, pubkey path, privkey path 등의 내용을 config 파일로 불러오는 작업
- config 양식은 user가 사용할 수 있게 제공할 예정
- 다른 함수에서 load 하게되면 high computation, long running time이 발생하므로 따로 함수를 만듦
- return은 struct config

**void get_session_key()**

return struct session_key

**void secure_connection()**

return secure socket

**void send_secure_message() **

**void wait_connection_message()**

return struct session_key
