/*
gcc -g server.c common.c -o server -lcrypto -lm
gcc -g server.c common.c secure_server.c auth.c -o server -lcrypto -lm -pthread

./server 21100
*/

#include "common.h"
#include "secure_server.h"

void initialize_server(int options);

int main(int argc, char * argv[]){
    client_list.client_list_length = 0;
    pthread_create(&p_thread[0], NULL, &scan_command, NULL);
    initialize_server(1); //TODO: options =1 
    return 0;
}

void initialize_server(int options){
    if(options == 1){ //TCP = 1
        initialize_TCP_server();
        return;
    }
    if(options == 2){ //UDP = 2
        initialize_UDP_server();
        return;
    }
    else{
        error_handling("check options");
    }
}
