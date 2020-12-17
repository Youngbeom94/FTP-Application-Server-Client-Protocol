#ifndef _FUNC_H_ 
#define _FUNC_H_

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <assert.h>
#include <fcntl.h> 
#include <sys/socket.h>
#include <arpa/inet.h>
#include <openssl/aes.h>
#include <openssl/rand.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>

#define BUF_SIZE 128
#define IDPW_SIZE 32
#define MAC_SIZE 32
#define FILE_NAME_LEN 20
#define COMMEND_LEN 20
#define SIGN_UP 1
#define SIGN_IN 2
#define BUFSIZE 512
#define AES_KEY_128 16
#define AES_BLOCK_LEN 16
#define TRUE 1
#define FALSE 0

#define Ch(x, y, z)			((x & y) ^ (~(x) & (z)))
#define Maj(x, y, z)		(((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)))
#define Sf(x, n)			(x >> n)

#define WE0(x)				(ROTR(x,  7) ^ ROTR(x, 18) ^ Sf(x, 3))
#define WE1(x)				(ROTR(x,  17) ^ ROTR(x, 19) ^ Sf(x, 10))

#define BS0(x)				((ROTR(x,  2)) ^ ROTR(x, 13) ^ ROTR(x,  22))
#define BS1(x)				(ROTR(x,  6) ^ ROTR(x, 11) ^ ROTR(x,  25))

#define BLOCKBYTE 64
#define SHA256_DIGEST_BLOCKLEN 64
#define SHA256_DIGEST_VALUELEN 32


#define IN 
#define OUT

#define ROTL(x, n)			(((x) << (n)) | ((x) >> (32 - (n))))
#define ROTR(x, n)			(((x) >> (n)) | ((x) << (32 - (n))))
#define ENDIAN_CHANGE(X)	((ROTL((X),  8) & 0x00ff00ff) | (ROTL((X), 24) & 0xff00ff00))
#define IPAD 0x36
#define OPAD 0x5c
#define BILLION 1000000000L

typedef unsigned char byte;
typedef unsigned int word;

enum TYPE_OF_MSG_AND_COMMAND
{
    PUBLIC_KEY,         // PUBLIC_KEY TYPE
    SECRET_KEY,         // SECRET_KEY TYPE
    PUBLIC_KEY_REQUEST, // FIRST_REQUEST
    IV,                 // IV TYPE
    ENCRYPTED_KEY,      // ENCRYPTED_KEY TYPE
    ENCRYPTED_MSG,      // ENCRYPTED_MSG TYPE
    CHECK_CLIENT,       // FIND_DB_FOR_CHECK_CLIENT
    REGISTER_MSG,       // REGISTER CLIENT
    REGISTER_SUCCESS,   // REGISTER SUCESS
    LOGIN_SUCCESS,      // LOGIN SUCESS
    LOGIN_FAIL,         // LOGIN FAILL
    CLIENT_ID_PW,       // ClIENT_ID and PW
    TYPE_ERROR,         // TYPE ERROR
    NOTTHING_MSG_TYPE,   // NOTHING

    UP,                 // UP to File
    LIST,               // SHOW List of server_file
    DOWN,               // DOWN file in server_file
    QUIT,               // END_SYSTEM
    SEND_LIST,          // SEND List of server_file
    SEND_FINISH,        // SEND List of server_file
    FILE_NAME,          // FILE NAME
    FILE_DATA,          // FILE DATA
    EXIST_FILE,         // Existing current File       
    NONE_FILE,          // None...
    DOWN_FILE,          // DOWN_TO_FILE
    NOTHING_SERVER_COMMAND,
    ERROR               //ERROR TYPE
};

typedef struct _APP_MSG_
{
    int type;
    unsigned char payload[BUFSIZE + AES_BLOCK_LEN];
    int msg_len;
}APP_MSG;

typedef struct
{
	word hash[8];
	word byte_msglen;
	byte buf[BLOCKBYTE];

}SHA256_INFO;

void M_SHA256_init(OUT SHA256_INFO* info);
void M_Block(IN word* const pt, OUT SHA256_INFO* info);
void M_SHA256_Process(IN byte* pt, IN word byte_msglen, OUT SHA256_INFO* info);
void M_SHA256_Final(OUT SHA256_INFO* info, OUT byte* hash_value);
void M_SHA256(IN byte* pt, IN unsigned long long byte_msglen, OUT byte* hash_value);
void HMAC_SHA256_Encrpyt(IN  byte * pszMessage, IN word uPlainTextLen, IN  byte * key, IN word keyLen, OUT byte * mac);

void handleErrors(void);
int encrypt(unsigned char *plaintext, int plaintext_len, unsigned char *key, unsigned char *iv, unsigned char *ciphertext);
int decrypt(unsigned char *ciphertext, int ciphertext_len, unsigned char *key, unsigned char *iv, unsigned char *plaintext);
void error_handling(char *msg);

#endif