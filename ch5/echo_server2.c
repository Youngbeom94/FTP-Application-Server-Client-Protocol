#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <memory.h>
#include <unistd.h>
#include <fcntl.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include "readnwrite.h"

#define BUF_SIZE 128
void error_handling(char * message);

void error_handling(char * message)
{
    fputs(message,stderr);
    fputc('\n',stderr);
    exit(1);
}

int main(int argc, char* argv[])
{
    int serv_sock; //listening socket
    int clint_sock; // data socket
    char message[BUF_SIZE + 1] = {0x00};
    int str_len,cnt_i;


    struct sockaddr_in serv_addr; //server's IP and Port
    struct sockaddr_in Clint_addr; //server's IP and Port
    socklen_t clint_addr_size;

    if(argc != 2)
    {
        fprintf(stderr, "Usage: %s <port>\n", argv[0]);
        fprintf(stderr, "oR Argument Error\n");
        exit(1);
    }

    serv_sock = socket(PF_INET, SOCK_STREAM, 0); //use TCP
    if(serv_sock == -1)
    {
        error_handling("socket() error");
    }

    memset(&serv_addr, 0 , sizeof(serv_addr)); //
    serv_addr.sin_family = AF_INET; //IPv4
    serv_addr.sin_addr.s_addr = htonl(INADDR_ANY); //host ordering -> network ordering //INADDR_ANY auto mapping
    serv_addr.sin_port = htons(atoi(argv[1]));

    if(bind(serv_sock, (struct sockaddr*)&serv_addr, sizeof(serv_addr)) == -1)
    {
        error_handling("bind() error");
    }

    if(listen(serv_sock, 5) == -1)
    {
        error_handling("listen() error");
    }

    //wait status for connection request from clients
    for(cnt_i = 0 ; cnt_i <5 ; cnt_i ++)
    {
        clint_addr_size = sizeof(Clint_addr);\
        clint_sock = accept(serv_sock, (struct sockaddr*)&Clint_addr, &clint_addr_size);

        if(clint_sock == -1)
        {
            error_handling("accept() error");
        }
        else
        {
            printf("Connected client: %d\n", cnt_i+1);
        }

        while((str_len = read(clint_sock,message, BUF_SIZE))!=0)
        {
            write(clint_sock,message,str_len);
        }

        close(clint_sock);
    }

    close(serv_sock);

    return 0;

}