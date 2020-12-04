#include "readnwrite.h"

ssize_t readn(int fd, void* vptr, size_t n)
{
    ssize_t nleft;
    ssize_t nread;
    char* ptr = vptr;
    nleft = n;

    while (nleft > 0) // 읽을게 남음 
    {
        nread = read(fd, ptr, nleft);

        if (nread == -1) // 오류 알림
        {
            return -1;
        }
        else if (nread == 0) // 0이면 읽을거 없으니까 끝낸다.
        {
            break;
        }
        

        nleft -= nread; // 읽은만큼 감산
        ptr += nread; // 버퍼 시작주소니까 다음에 저장할 위치 
    }
    return (n-nleft); // 읽어들인 총 사이즈

}

// 라이트 함수는 정상 동작할때 버퍼에 들어있는 엔 바이트를 버퍼에 쓴다. 
// 출력 버퍼에 공간이 더작으면 그 일부만 쓴다.

ssize_t writen(int fd, const void* vptr, size_t n)
{
    ssize_t nleft;
    ssize_t nwritten;
    const char* ptr = vptr;
    nleft = n;

    while(nleft > 0)
    {
        nwritten = write(fd, ptr, nleft);
        
        if (nwritten == -1)
        {
            return -1;
        }

        nleft -= nwritten;
        ptr += nwritten;
    }
    return n;
}