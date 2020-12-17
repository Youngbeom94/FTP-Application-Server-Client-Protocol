#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>

#include <assert.h>
#include <openssl/aes.h>
#include <openssl/rand.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>

#include "readnwrite.h"
#include "aesenc.h"
#include "msg.h"


void error_handling(char *msg)
{
    fputs(msg, stderr);
    fputc('\n', stderr);
    exit(1);
}

int main(int argc, char *argv[])
{
    int cnt_i;
    int sock;
    struct sockaddr_in serv_addr;
    int len;
    
    APP_MSG msg_in;
    APP_MSG msg_out;
    
    char plaintext[BUFSIZE + AES_BLOCK_SIZE] = {0, };
    unsigned char encrypted_key[BUFSIZE] = {0, };

    unsigned char key[AES_KEY_128] = {0, };
    unsigned char iv[AES_KEY_128] = {0, };

    BIO *rpub = NULL;
    RSA *rsa_pubkey = NULL;

    int n;
    int plaintext_len;
    int ciphertext_len;

    RAND_poll();
    RAND_bytes(key, sizeof(key));

    for (cnt_i = 0; cnt_i < AES_KEY_128; cnt_i++)
    {
        iv[cnt_i] = (unsigned char)cnt_i;
    }

    if (argc != 3)
    {
        fprintf(stderr, "%s <IP> <port>\n", argv[0]);
        exit(1);
    }

    sock = socket(PF_INET, SOCK_STREAM, 0);

    if (sock == -1)
    {
        error_handling("socket() error");
    }

    memset(&serv_addr, 0, sizeof(serv_addr));
    serv_addr.sin_family = AF_INET; // 16비트 멤버 아이피버전4 주소체계
    serv_addr.sin_addr.s_addr = inet_addr(argv[1]); // 프로그램의 인자로 들어온 아이피주소의 문자열을 실제 32비트 아이피 주소값으로 만들어준다
    // inet_addr() : 문자열 형태의 아이피주소 받아서 32비트 네트워크 오더링 값으로 변환해 반환
    serv_addr.sin_port = htons(atoi(argv[2])); // atoi 문자열 형태의 10진수 수를 실제 10진수 정수로 반환

    if (connect(sock, (struct sockaddr*)&serv_addr, sizeof(serv_addr)) == -1)
    {
        error_handling("connect() error");
    }
    else
    {
        printf("Connected.............\n");
    }


    // setup process
    // sending PUBLIC_KEY_REQUEST msg
    // 서버로 공개키 요청 메시지 전송
    memset(&msg_out, 0, sizeof(msg_out));
    msg_out.type = PUBLIC_KEY_REQUEST;
    msg_out.type = htonl(msg_out.type);

    n = writen(sock, &msg_out, sizeof(APP_MSG));
    if (n == -1)
    {
        error_handling("writen() error");
    }

    //서버로부터의 공개키 메시지 수신
    //receiving PUBLIC_KEY msg
    memset(&msg_in, 0, sizeof(msg_in));
    n = readn(sock, &msg_in, sizeof(APP_MSG));
    msg_in.type = ntohl(msg_in.type);
    msg_in.msg_len = ntohl(msg_in.msg_len);
    printf("msg type %d\n", msg_in.type);

    if (n == -1)
    {
        error_handling("readn() error");
    }
    else if (n == 0)
    {
        error_handling("reading EOF");
    }

    if (msg_in.type != PUBLIC_KEY)
    {
        error_handling("message error");
    }
    else
    {
        BIO_dump_fp(stdout, (const char*)msg_in.payload, msg_in.msg_len);

        // 서버로부터의 공개키 메시지를 RSA 타입으로 변환
        rpub = BIO_new_mem_buf(msg_in.payload, -1); // 배열로부터 데이터 추출할때 사용
        BIO_write(rpub, msg_in.payload, msg_in.msg_len); // rpub로 쓴다고 생각하면된다. 페이로드 배열과 rpub와 연결고리를 만듬 rpub로 쓴다 페이로드안에있는걸
        
        if (!PEM_read_bio_RSAPublicKey(rpub, &rsa_pubkey, NULL, NULL))
        {
            error_handling("PEM_read_bio_RSAPublicKey() error");
        }
    }
    
    //sending ENCRYPTED_KEY msg
    //클라이언트는 랜덤하게 생성한 키를 서버의 공개키로 암호화하여 서버로 전송
    memset(&msg_out, 0, sizeof(APP_MSG));
    msg_out.type = ENCRYPTED_KEY;
    msg_out.type = htonl(msg_out.type);
    msg_out.msg_len = RSA_public_encrypt(sizeof(key), key, msg_out.payload, rsa_pubkey, RSA_PKCS1_OAEP_PADDING); // 암호화해서 보낸다.랜덤하게 생성한 세션 키를 페이로드에 저장, rsa 공개키 사용
    msg_out.msg_len = htonl(msg_out.msg_len);

    n = writen(sock, &msg_out, sizeof(APP_MSG));

    if (n == -1)
    {
        error_handling("writen() error");
    }

    getchar();

    while (1)
    {
        // input a message
        printf("Input a message > \n");
        if (fgets(plaintext, BUFSIZE + 1, stdin) == NULL)
            break;
        
        // removing '\n'
        len = strlen(plaintext);
        if (plaintext[len-1] == '\n')
            plaintext[len-1] = '\0';
        if (strlen(plaintext) == 0)
            break;
        
        memset(&msg_out, 0, sizeof(msg_out));

        ciphertext_len = encrypt((unsigned char*)plaintext, len, key, iv, msg_out.payload);
        msg_out.msg_len = htonl(ciphertext_len);
        msg_out.type = ENCRYPTED_MSG;
        msg_out.type = htonl(msg_out.type);
        
        // sending the inputed message
        n = writen(sock, &msg_out, sizeof(APP_MSG));
        if (n == -1)
        {
            error_handling("writen() error");
            break;
        }

        // receiving a message from the server
        n = readn(sock, &msg_in, sizeof(APP_MSG));

        if (n == -1)
        {
            error_handling("readn() error");
            break;
        }
        else if (n == 0)
            break;
        
        msg_in.type = ntohl(msg_in.type);
        msg_in.msg_len = ntohl(msg_in.msg_len);

        switch(msg_in.type)
        {
            case ENCRYPTED_MSG:
                printf("\n* encryptedMsg : \n");
                BIO_dump_fp(stdout, (const char *)msg_in.payload, msg_in.msg_len);
                plaintext_len = decrypt(msg_in.payload, msg_in.msg_len, key, iv, (unsigned char*)plaintext);

                printf("\n* decryptedMsg : \n");
                BIO_dump_fp(stdout, (const char *)plaintext, plaintext_len);
                break;
            default:
                break;
        }
        //print the received message
        plaintext[plaintext_len] = '\0';
        printf("%s\n", plaintext);
    }
    close(sock);

    return 0;
}