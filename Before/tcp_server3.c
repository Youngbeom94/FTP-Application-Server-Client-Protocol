#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <memory.h>
#include <unistd.h>
#include <fcntl.h>
#include <arpa/inet.h>
#include <sys/socket.h>

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
    int num1, num2, result;
    int fd = -1;
    int n;
    char buf[1024];


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

    clint_addr_size = sizeof(Clint_addr);
    printf("before accept\n");
    clint_sock = accept(serv_sock, (struct sockaddr*)&Clint_addr, &clint_addr_size);

    if(clint_sock == -1)
    {
        error_handling("accept() error");
    }

    read(clint_sock, &num1, sizeof(num1));
    read(clint_sock, &num2, sizeof(num2));

    num1 = ntohl(num1);
    num2 = ntohl(num2);

    printf("server get two numbers %d and %d\n",num1,num2);

    result = num1 + num2;

    printf("server calcurates result : %d \n",(num1 + num2));

    result = htonl(result);

    write(clint_sock, &result, sizeof(result));
    
    // while((n = read(fd,buf, sizeof(buf))) > 0)
    // {
    //     if(write(clint_sock, buf, n) != n )
    //     {
    //         error_handling("wirte()3 error");
    //     }
    // }
    printf("after accept\n");

    if(fd != -1)
    {
        close(fd);
    }

    close(clint_sock);
    close(serv_sock);
    // fwirte 

    return 0;

}