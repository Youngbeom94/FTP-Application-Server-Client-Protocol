#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <memory.h>
#include <unistd.h>
#include <fcntl.h>
//#include <arpa/inet.h>
//#include <sys/socket.h>

void error_handling(char * message)
{
    fputs(message,stderr);
    fputc('\n',stderr);
    exit(1);
}


int main(int argc, char* argv[])
{
   int fd1 = -1, fd2 = -1;
   int n;
   char buf[1024];

   if(argc != 3)
   {
       fprintf(stderr, "argument error");
   }

    fd1 = open(argv[1], O_RDONLY, S_IRWXU);
    if(fd1 == -1)
    {
        error_handling("open()1 error");
    }

    fd2 = open(argv[2], O_CREAT | O_WRONLY | O_TRUNC, S_IRWXU);
    if(fd2 == -1)
    {
        error_handling("open()2 error");
    }

    while((n = read(fd1,buf, sizeof(buf))) > 0)
    {
        if(write(fd2, buf, n) != n )
        {
            error_handling("wirte()3 error");
        }
    }

    if(fd1 != -1)
    {
        close(fd1);
    }
    if(fd2 != -1)
    {
        close(fd2);
    }

    return 0;

}
//EOF