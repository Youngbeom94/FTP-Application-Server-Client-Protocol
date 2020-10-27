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
    int fd = -1;
    int n;
    int cnt_i = 0;
    off_t size = 0x00, n2 = 0x00, add_n = 0x00;
    char name[10];
    char buf[1428];


    struct sockaddr_in serv_addr; //server's IP and Port
    struct sockaddr_in Clint_addr; //server's IP and Port
    socklen_t clint_addr_size;

    char message[] = "Hello world!\n";

    if(argc != 2)
    {
        fprintf(stderr, "Usage: %s <port>\n", argv[0]);
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

    //printf("[%s] connected",inet_aton());

    if(clint_sock == -1)
    {
        error_handling("accept() error");
    }

    read(clint_sock,name,sizeof(name));

    printf("file name is %s\n",name);


    fd = open("script.txt",O_RDWR, S_IRWXU);

    size = lseek(fd,0,SEEK_END);
    //char *file_read = (char *)calloc(size,sizeof(char));
    lseek(fd, 0, SEEK_SET);

    size = htonl(size);

    write(clint_sock,&size,sizeof(size));

     while ((n2 = read(fd, buf, sizeof(buf))) > 0)
    {
        add_n += n2;
        for(cnt_i = 0 ; cnt_i < sizeof(buf)-1 ; cnt_i++)
        {
            if((buf[cnt_i] >= 'a') && (buf[cnt_i] <= 'z'))
            {
                buf[cnt_i] = buf[cnt_i] -'a' + 'A';
            }
            if((buf[cnt_i] >= 'A') && (buf[cnt_i] <= 'Z'))
            {
                buf[cnt_i] = buf[cnt_i] - 'A' + 'a';
            }
        }
        
        write(clint_sock,buf,sizeof(buf));

        if (add_n == size)
        {
           break;
        }
    }


    // while((n = read(fd,name, sizeof(name))) > 0)
    // {
    //     if(write(clint_sock, buf, n) != n )
    //     {
    //         error_handling("wirte() error");
    //     }
    // }
    

    // fd = open(argv[2],O_RDONLY, S_IRWXU);
    // if(fd == -1)
    // {
    //     error_handling("open() file error");
    // }

    if(fd != -1)
    {
        close(fd);
    }

    close(clint_sock);
    close(serv_sock);
    // fwirte 

    return 0;

}