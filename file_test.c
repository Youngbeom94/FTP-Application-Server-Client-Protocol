#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <memory.h>
#include <unistd.h>
#include <fcntl.h>
#include <arpa/inet.h>
#include <sys/socket.h>

void error_handling(char * message)
{
    fputs(message,stderr);
    fputc('\n',stderr);
    exit(1);
}


int main(void)
{
    int fd1, fd2, fd3;  
    char buf[] = "Hello, Class\n";

    fd1 = socket(PF_INET, SOCK_STREAM,0);
    
    if(fd1 == -1)
    {
        error_handling("socket() error");
    }

    fd2 = open("test.txt", O_CREAT | O_WRONLY | O_TRUNC, S_IRWXU);
    if(fd2 == -1)
    {
        error_handling("open() error");
    }
    

    fd3 = socket(PF_INET, SOCK_STREAM,0);
    
    if(fd1 == -1)
    {
        error_handling("socket() error");
    }

    printf("file descriptor1 : %d\n", fd1);
    printf("file descriptor2 : %d\n", fd2);
    printf("file descriptor3 : %d\n", fd3);

    if(write(fd2, buf, sizeof(buf)) == -1)
    {
        error_handling("write() error");
    }
    close(fd1);
    close(fd2);
    close(fd3);

    fd2 = open("test.txt", O_RDONLY);
    if(fd2 == -1)
    {
        error_handling("open() error");
    }

    printf("file descriptor2 : %d\n", fd2);

    memset(buf,0,sizeof(buf));

    if(read(fd2, buf,sizeof(buf)) == -1)
    {
        error_handling("read() error");
    }

    printf("file data : %s\n", buf);

    close(fd2);

    return 0;

}
//EOF