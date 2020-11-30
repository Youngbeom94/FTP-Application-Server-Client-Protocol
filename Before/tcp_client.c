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
    char buf[1024];
    int str_len = 0, read_len = 0;
    int idx = 0;
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

    fd = open(argv[3],O_CREAT | O_RDWR | O_TRUNC, S_IRWXU);
    if( fd == -1)
    {
        error_handling("file open() error");
    }
    while ((n = read(sock, buf, sizeof(buf)))>0)
    {
       if(write(fd, buf, n) != n )
        {
            error_handling("wirte()3 error");
        }
    }

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
