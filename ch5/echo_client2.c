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
void error_handling(char *message);

int main(int argc, char *argv[])
{
    int sock;
    struct sockaddr_in serv_addr;
    char message[BUF_SIZE + 1] = {0x00};
    int str_len = 0x00, cnt_i = 0x00, recv_len = 0x00, recv_cnt = 0x00;;
    
 

    if (argc != 3)
    {
        printf("Usage : %s <IP> <port>\n", argv[0]);
        exit(1);
    }

    sock = socket(PF_INET, SOCK_STREAM, 0);

    if (sock == -1)
    {
        error_handling("socket() error");
    }

    memset(&serv_addr, 0, sizeof(serv_addr));
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_addr.s_addr = inet_addr(argv[1]);
    serv_addr.sin_port = htons(atoi(argv[2]));

    if (connect(sock, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) == -1)
    {
        error_handling("connect() error!");
    }
    else
    {
        puts("Connected.............");
    }//

    while(1)
    {
        fputs("Input message(Q to quit): ",stdout);
        fgets(message, BUF_SIZE, stdin);
        
        if(!strcmp(message,"q\n") || !strcmp(message,"Q\n")) // if message is 'q' or 'Q' then break
            break;


        str_len = strlen(message);
        if(str_len != writen(sock,message,strlen(message)))
        {
            error_handling("writen() error!");
        }

        recv_cnt = readn(sock, message, str_len);
        if(recv_cnt < 0)
        {
            error_handling("readn() error");
        }
        
        message[recv_cnt] = '\0';
        printf("Message from server: %s", message);
    }

    close(sock);

    return 0;
}

void error_handling(char *message)
{
    fputs(message, stderr);
    fputc('\n', stderr);
    exit(1);
}