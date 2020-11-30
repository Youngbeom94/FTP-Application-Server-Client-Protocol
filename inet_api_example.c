#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <arpa/inet.h>

void error_handling(char* message)
{
    fputs(message, stderr);
    fputc('\b',stderr);
    exit(1);
}

int main(int argc, char* argv[])
{
    char *addr1 = "127.212.124.78";
    char *addr2 = "127.212.124.255";
    unsigned long conv_addr;
    struct sockaddr_in inet_addr1, inet_addr2, inet_addr3;
    char *str_ptr;
    char str_arr[32];

    conv_addr = inet_addr(addr1);
    
    if(conv_addr == INADDR_NONE)
    {
        fprintf(stderr,"Conversion Error\n");
    }
    else
    {
        fprintf(stdout,"Network ordered integer addr: %#lx\n",conv_addr);
    }
    
    if(!inet_aton(addr2,  &inet_addr1.sin_addr))
        error_handling("Conversion error with inet_addr");
    else
    {
        printf("Network ordered integer addr: %#x \n", inet_addr1.sin_addr.s_addr);
    }

    inet_addr2.sin_addr.s_addr = htonl(0x1020304); //Enter Big Endian ordering
    inet_addr3.sin_addr.s_addr = htonl(0x4e7cd47f);

    str_ptr = inet_ntoa(inet_addr2.sin_addr); // change Network ordering to Decimal ordering
    strcpy(str_arr,str_ptr);
    printf("Dotted-Decimal notation1: %s \n", str_ptr);

    str_ptr = inet_ntoa(inet_addr3.sin_addr);
    printf("Dotted-Decimal notation2: %s \n", str_ptr);
    printf("Dotted-Decimal notation3: %s \n", str_arr);
    

    return 0;
}

