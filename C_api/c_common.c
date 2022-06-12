void print_buf(unsigned char * print_buf, int n)
{
    for(int i=0 ; i<n; i++)
        printf("%x  ", print_buf[i]);
    printf("\n");
}

void generate_nonce(unsigned char * nonce_buf, int size_n)  // nonce generator;
{
    int x = RAND_bytes(nonce_buf,size_n);
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

unsigned int read_variable_UInt(unsigned char * buf, int byteLength)
{
    int num =0;
    for(int i =0; i<byteLength;i++)
    {
        num |= buf[i]<< 8*(byteLength-1-i);
    }
    return num; 
}

//  return: payload buf length
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