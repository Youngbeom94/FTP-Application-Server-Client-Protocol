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

#define BUF_SIZE 1024
#define RLT_SIZE 4
#define OPSZ     4

void error_handling(char *message);

int main(int argc, char *argv[])
{
    int sock;
    struct sockaddr_in serv_addr;
    char opmsg[BUF_SIZE] = {0x00}; // numberof pi operator, pi operator, operator
    char IPAddr[] = "127.0.0.1";
    char opnd_cnt, result;
    int msglen;
    int operand;
    int temp;
    int cnt_i;
    
 

    if (argc != 2)
    {
        printf("Usage : %s <port>\n", argv[0]);
        exit(1);
    }

    sock = socket(PF_INET, SOCK_STREAM, 0);

    if (sock == -1)
    {
        error_handling("socket() error");
    }

    memset(&serv_addr, 0, sizeof(serv_addr));
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_addr.s_addr = inet_addr(IPAddr);
    serv_addr.sin_port = htons(atoi(argv[1]));

    if (connect(sock, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) == -1)
    {
        error_handling("connect() error!");
    }
    else
    {
        puts("Connected.............");
    }//

    fputs("Operand count: " , stdout);
    scanf("%d", &opnd_cnt);
    opmsg[0] = (char)opnd_cnt;

    for(cnt_i = 0 ; cnt_i < opnd_cnt ; cnt_i ++)
    {
        printf("Operand %d: ", cnt_i + 1);
        scanf("%d", &operand);
        temp = htonl(operand);
        memcpy(&opmsg[cnt_i * OPSZ + 1], &temp, sizeof(int));
    }

    fgetc(stdin);
    fprintf(stdout,"Operator\n");
    scanf("%c", &opmsg[opnd_cnt*OPSZ + 1]);
    msglen = opnd_cnt * OPSZ + 2;

    if(msglen != writen (sock, opmsg, msglen))
    {
        error_handling("writen( ) error");
    }


    if(readn(sock, &result, RLT_SIZE) < 0)
    {
        error_handling("readn() error");
    }

    result = ntohl(result);
    printf("Operation result: %d\n",result);

    close(sock);

    return 0;
}

void error_handling(char *message)
{
    fputs(message, stderr);
    fputc('\n', stderr);
    exit(1);
}
