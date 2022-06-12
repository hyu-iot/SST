#include "c_common.h"

void print_buf(unsigned char * buf, int n)
{
    for(int i=0 ; i<n; i++)
        printf("%x  ", buf[i]);
    printf("\n");
}

void generate_nonce(unsigned char * buf, int length)  // nonce generator;
{
    int x = RAND_bytes(buf, length);
    if(x == -1)
    {
        printf("Failed to create Random Nonce");
        exit(1);
    }
}   
// num: number to write in buf, n: buf size 
void write_in_n_bytes(unsigned char * buf, int num, int n)
{
        for(int i=0 ; i < n; i++)
        {
            buf[i] |=  num >> 8*(n-1-i);
        }
}

unsigned int read_variable_UInt(unsigned char * buf, int byte_length)
{
    int num =0;
    for(int i =0; i<byte_length;i++)
    {
        num |= buf[i]<< 8*(byte_length-1-i);
    }
    return num; 
}

/*  
    function: (0,127) = 1, [128, 128^2] = 2, [128^2, 128^3] = 3 ..... 
    input: integer buffer to change
    return: payload_buf_length
*/
unsigned int payload_buf_length(int b)
{   
    int n = 1;
    while(b > 127)
    {
        n += 1;
        b >>=7;
    }
    return n;
}
/*return: message length of the payload
input: buffer from after messagetype, 
buf_length: total read message length
*/
unsigned int var_length_int_to_num(unsigned char * buf, int buf_length)
{
    int num = 0;
    for (int i =0; i<buf_length; i++)
    {
        num |= (buf[i]& 127) <<(7 * i);
        if((buf[i]&128) == 0 )
        {
            break;
        }
    }
    return num;
}