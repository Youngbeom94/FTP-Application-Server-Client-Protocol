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
    int serv_sock = -1;
    int clnt_sock = -1;

    struct sockaddr_in serv_addr; // 바인드함수용
    struct sockaddr_in clnt_addr; // 클라이언트 주소정보 저장
    socklen_t clnt_addr_size;

    APP_MSG msg_in;
    APP_MSG msg_out;   

    char plaintext[BUFSIZE + AES_BLOCK_SIZE] = {0, };
    int n;
    int len;
    int plaintext_len;
    int ciphertext_len;
    int publickey_len;
    int encryptedkey_len;

    unsigned char key[AES_KEY_128] = {0, };
    unsigned char iv[AES_KEY_128] = {0, };
    unsigned char buffer[BUFSIZE] = {0, };

    BIO *bp_public = NULL, *bp_private = NULL;
    BIO *pub = NULL;
    RSA *rsa_pubkey = NULL, *rsa_privkey = NULL;

    for (cnt_i = 0; cnt_i < AES_KEY_128; cnt_i++)
    {
        iv[cnt_i] = (unsigned char)cnt_i;
    }

    if (argc != 2)
    {
        fprintf(stderr, "%s <port>\n", argv[0]);
        exit(1);
    }

    serv_sock = socket(PF_INET, SOCK_STREAM, 0);
    if (serv_sock == -1)
    {
        error_handling("socket() error");
    }

    memset(&serv_addr, 0, sizeof(serv_addr));
    serv_addr.sin_family = AF_INET; // 16비트 멤버 아이피버전4 주소체계
    serv_addr.sin_addr.s_addr = htonl(INADDR_ANY); // 0으로 정의
    serv_addr.sin_port = htons(atoi(argv[1])); // atoi 문자열 형태의 10진수 수를 실제 10진수 정수로 반환

    if (bind(serv_sock, (struct sockaddr*)&serv_addr, sizeof(serv_addr)) == -1)
    {
        error_handling("bind() error");
    }

    if (listen(serv_sock, 5) == -1)
    {
        error_handling("listen() error");
    }

    //reading public key
    bp_public = BIO_new_file("public.pem", "r");
    if (!PEM_read_bio_RSAPublicKey(bp_public, &rsa_pubkey, NULL, NULL))
    {
        goto err;
    }

    //reading private key
    bp_private = BIO_new_file("private.pem", "r");
    if (!PEM_read_bio_RSAPrivateKey(bp_private, &rsa_privkey, NULL, NULL))
    {
        goto err;
    }

    while (1)
    {
        clnt_addr_size = sizeof(clnt_addr);
        clnt_sock = accept(serv_sock, (struct sockaddr*)&clnt_addr, &clnt_addr_size);
        if (clnt_sock == -1)
        {
            error_handling("accept() error");
        }
        printf("\n[TCP Server] Client connected : IP = %s, port = %d\n", inet_ntoa(clnt_addr.sin_addr), ntohs(clnt_addr.sin_port));

        // setup process
        // 클라이언트로부터의 공개키 요청 메시지를 수신
        memset(&msg_in, 0, sizeof(APP_MSG));
        n = readn(clnt_sock, &msg_in, sizeof(APP_MSG));
        msg_in.type = ntohl(msg_in.type);
        msg_in.msg_len = ntohl(msg_in.msg_len);
        if (n == -1)
        {
            error_handling("readn() error");
        }
        else if (n == 0)
        {
            error_handling("reading EOF");
        }
        ///////////////////////////////////////////////////

        if (msg_in.type != PUBLIC_KEY_REQUEST)
        {
            error_handling("message error 1");
        }
        else
        {
            // sending PUBLIC_KEY
            // 공개키를 메시지에 적재하여 클라이언트로 전송
            memset(&msg_out, 0, sizeof(APP_MSG));
            msg_out.type = PUBLIC_KEY;
            msg_out.type = htonl(msg_out.type);

            pub = BIO_new(BIO_s_mem()); //메시지 아웃 페이로드에 
            PEM_write_bio_RSAPublicKey(pub, rsa_pubkey); // rsa_pubkey에 들어있는  공개키 정보를 pub라는 출력을 위한 메모리로 쓴다.
            publickey_len = BIO_pending(pub);

            BIO_read(pub, msg_out.payload, publickey_len);
            msg_out.msg_len = htonl(publickey_len);

            n = writen(clnt_sock, &msg_out, sizeof(APP_MSG));
            if (n == -1)
            {
                error_handling("writen() error");
                break;
            }
        }

        memset(&msg_in, 0, sizeof(APP_MSG));
        n = readn(clnt_sock, &msg_in, sizeof(APP_MSG));
        msg_in.type = ntohl(msg_in.type);
        msg_in.msg_len = ntohl(msg_in.msg_len);
        printf("msg type %d\n", msg_in.type);
        // 클라이언트로부터의 암호화된 세션키 수신, 복호화하여 세션키 복원
        if (msg_in.type != ENCRYPTED_KEY)
        {
            error_handling("message error 2");
        } 
        else
        {
            encryptedkey_len = RSA_private_decrypt(msg_in.msg_len, msg_in.payload, buffer, rsa_privkey, RSA_PKCS1_OAEP_PADDING); // 버퍼에 복호화된 키가 들어감
            memcpy(key, buffer, encryptedkey_len);
        }
        getchar();

        while (1)
        {
            n = readn(clnt_sock, &msg_in, sizeof(APP_MSG));

            if (n == -1)
            {
                error_handling("readn() error");
                break;
            }
            else if (n == 0)
                break;

            msg_in.type = ntohl(msg_in.type);
            msg_in.msg_len = ntohl(msg_in.msg_len);

            // 클라이언트로부터 전송된 메시지를 복호화하여 출력
            switch (msg_in.type)
            {
            case ENCRYPTED_MSG:
                printf("\n* encryptedMsg : \n");
                BIO_dump_fp(stdout, (const char *)msg_in.payload, msg_in.msg_len);
                plaintext_len = decrypt(msg_in.payload, msg_in.msg_len, key, iv, (unsigned char *)plaintext);

                printf("\n* decryptedMsg : \n");
                BIO_dump_fp(stdout, (const char *)plaintext, plaintext_len);
                break;
            default:
                break;
            }
            //print the received message
            plaintext[plaintext_len] = '\0';
            printf("%s\n", plaintext);

            // input a message that you want to send
            printf("Input a message > \n");
            if (fgets(plaintext, BUFSIZE + 1, stdin) == NULL)
                break;

            // removing '\n'
            len = strlen(plaintext);
            if (plaintext[len - 1] == '\n')
                plaintext[len - 1] = '\0';
            if (strlen(plaintext) == 0)
                break;

            // 사용하자가 입력한 메시지를 암호화하여 클라이언트로 전송
            ciphertext_len = encrypt((unsigned char *)plaintext, len, key, iv, msg_out.payload);
            msg_out.type = ENCRYPTED_MSG;
            msg_out.type = htonl(msg_out.type);
            msg_out.msg_len = htonl(ciphertext_len);

            // sending the inputed message
            n = writen(clnt_sock, &msg_out, sizeof(APP_MSG));
            if (n == -1)
            {
                error_handling("writen() error");
                break;
            }
        }
        close(clnt_sock);
        printf("[TCP Server] Client close : IP = %s, port = %d\n", inet_ntoa(clnt_addr.sin_addr), ntohs(clnt_addr.sin_port));
    }
err:
    close(serv_sock);


    return 0;
}