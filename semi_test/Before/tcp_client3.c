#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <memory.h>
#include <unistd.h>
#include <fcntl.h>
#include <arpa/inet.h>
#include <sys/socket.h>

void error_handling(char *message);

int main(int argc, char *argv[])
{
    int sock;
    struct sockaddr_in serv_addr;
    char string_num1[sizeof(int)];
    char string_num2[sizeof(int)];
    int num1 = 0x00, num2 = 0x00, result = 0x00;
    int fd = -1;

    if (argc != 4)
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

    printf("executing connet() fucntion\n");
    int n = 0;

    fd = open(argv[3],O_RDONLY, S_IRWXU);
    if( fd == -1)
    {
        error_handling("file open() error");
    }
    read(fd, string_num1, sizeof(num1));
    read(fd, string_num2, sizeof(num2));

    num1 = (atoi(string_num1));
    num2 = (atoi(string_num2));

    printf("Two number are %d and %d\n",num1,num2);

    num1 = htonl(num1);
    num2 = htonl(num2);

    write(sock, &num1, sizeof(num1));
    write(sock, &num2, sizeof(num2));

    read(sock,&result, sizeof(result));
    result = ntohl(result);

    printf("result is %d\n",result);


    // while ((n = read(sock, buf, sizeof(buf)))>0)
    // {
    //    if(write(fd, buf, n) != n )
    //     {
    //         error_handling("wirte()3 error");
    //     }
    // }

    close(sock);
    close(fd);

    return 0;
}

void error_handling(char *message)
{
    fputs(message, stderr);
    fputc('\n', stderr);
    exit(1);
}
