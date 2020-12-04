/*
RSA 키 쌍을 생성하여 PEM 파일에 저장
암복호화를 수행하여 정상 동작 확인
*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

#include <openssl/err.h>
#include <openssl/rand.h>
#include <openssl/bn.h>
#include <openssl/crypto.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/evp.h>
#include <openssl/engine.h>

static int _pad_unknopwn(void);
int rsaes_simple_test();
int rsaes_simple_test2(); // 앞의 예제에서 저장한 RSA 키를 읽어 들여 암복호화 수행
void rsaes_evp_test();

int main(int argc, char* argv[])
{
    rsaes_simple_test();
    // rsaes_simple_test2();
    // rsaes_evp_test();


    return 0;
}

static int _pad_unknopwn(void)
{
    unsigned long l;

    while ((l = ERR_get_error()) != 0)
    {
        if (ERR_GET_REASON(l) == RSA_R_UNKNOWN_PADDING_TYPE)
            return (1);    
    }
    return (0);
}

int rsaes_simple_test()
{
    int ret = 1;
    RSA *rsa;
    unsigned char ptext[256] = {0, };
    unsigned char ctext[256] = {0, };
    unsigned char ptext_ex[] = "hello, world!!";
    unsigned char ctext_ex[256] = {0, };
    int plen = sizeof(ptext_ex);
    int clen = 0;
    int num;
    BIO *bp_public = NULL, *bp_private = NULL;
    unsigned long e_value = RSA_F4;
    BIGNUM *exponent_e = BN_new();

    rsa = RSA_new();

    BN_set_word(exponent_e, e_value);

    if (RSA_generate_key_ex(rsa, 2048, exponent_e, NULL))
    {
        fprintf(stderr, "RSA_generate_key_ex() error\n");
    }
    bp_public = BIO_new_file("public.pem", "w+");
    ret = PEM_write_bio_RSAPublicKey(bp_public, rsa);

    if (ret != 1)
    {
        goto err;
    }

    bp_private = BIO_new_file("private.pem", "w+");
    ret = PEM_write_bio_RSAPrivateKey(bp_private, rsa, NULL, NULL, 0, NULL, NULL);

    if (ret != 1)
    {
        goto err;
    }

    printf("\nplaintext\n");
    BIO_dump_fp(stdout, (const char*)ptext_ex, plen);

    num = RSA_public_encrypt(plen, ptext_ex, ctext, rsa, RSA_PKCS1_OAEP_PADDING);

    if (num == -1 && _pad_unknopwn)
    {
        fprintf(stderr, "No OAEP support\n");
        ret = 1;
        goto err;
    }

    printf("\nciphertext\n");
    BIO_dump_fp(stdout, (const char*)ctext, num);

    num = RSA_private_decrypt(num, ctext, ptext, rsa, RSA_PKCS1_OAEP_PADDING);

    if (num != plen || memcmp(ptext, ptext_ex, num) != 0)
    {
        fprintf(stderr, "OAEP decryption (encrypted data) failed!\n");
        ret = 1;
        goto err;
    }

    printf("\nrecovered\n");
    BIO_dump_fp(stdout, (const char*)ptext, num);

err:
    RSA_free(rsa);
    BIO_free_all(bp_public);
    BIO_free_all(bp_private);

    return ret;
}

int rsaes_simple_test2() // 저장한 RSA키를 읽어 들여 암복호화 수행
{
    int ret;
    BIO *bp_public = NULL, *bp_private = NULL;
    RSA *rsa_pubkey = NULL, *rsa_privkey = NULL;

    unsigned char ptext[256] = {0, };
    unsigned char ctext[256] = {0, };
    unsigned char ptext_ex[] = "hello, world!!";
    unsigned char ctext_ex[256] = {0, };
    int plen = sizeof(ptext_ex);
    int clen = 0;
    int num;

    bp_public = BIO_new_file("public.pem", "r");
    if (!PEM_read_bio_RSAPublicKey(bp_public, &rsa_pubkey, NULL, NULL))
    {
        goto err;
    }

    bp_private = BIO_new_file("private.pem", "r");
    if (!PEM_read_bio_RSAPrivateKey(bp_private, &rsa_privkey, NULL, NULL))
    {
        goto err;
    }

    printf("\nplaintext\n");
    BIO_dump_fp(stdout, (const char*)ptext_ex, plen);

    num = RSA_public_encrypt(plen, ptext_ex, ctext, rsa_pubkey, RSA_PKCS1_OAEP_PADDING);

    if (num == -1 && _pad_unknopwn)
    {
        fprintf(stderr, "No OAEP support\n");
        ret = 1;
        goto err;
    }

    printf("\nciphertext\n");
    BIO_dump_fp(stdout, (const char*)ctext, num);

    num = RSA_private_decrypt(num, ctext, ptext, rsa_privkey, RSA_PKCS1_OAEP_PADDING);

    if (num != plen || memcmp(ptext, ptext_ex, num) != 0)
    {
        fprintf(stderr, "OAEP decryption (encrypted data) failed!\n");
        ret = 1;
        goto err;
    }

    printf("\nrecovered\n");
    BIO_dump_fp(stdout, (const char*)ptext, num);
    
err:
    if (bp_public)
    {
        BIO_free(bp_public);
    }
    if (bp_private)
    {
        BIO_free(bp_private);
    }
    return ret;
}


// EVP함수를 이용하여 키쌍 생성 및 암복호화 수행
void rsaes_evp_test()
{
    RSA *rsa = NULL;
    EVP_PKEY *pubkey = NULL, *privkey = NULL;
    EVP_PKEY *pkey = NULL;
    EVP_PKEY_CTX * ctx = NULL;
    int ret;
    int rc;
    BIO *out = NULL;

    unsigned char msg[] = "hello, world";
    unsigned char *plaintext = msg;
    unsigned char *ciphertext = NULL;
    unsigned char *recovered = NULL;
    size_t outlen, inlen;

    unsigned long e_value = RSA_F4;
    BIGNUM *exponent_e = BN_new();

    out = BIO_new_fp(stdout, BIO_CLOSE); // allocate BIO for 'stdout'
    inlen = sizeof(msg);

    // RSA key generation
    pubkey = EVP_PKEY_new();
    assert(pubkey != NULL);

    privkey = EVP_PKEY_new();
    assert(privkey != NULL);

    rsa = RSA_new();

    BN_set_word(exponent_e, e_value);

    if (RSA_generate_key_ex(rsa, 2048, exponent_e, NULL))
    {
        fprintf(stderr, "RSA_generate_key_ex() error\n");
    }
    
    ret = EVP_PKEY_assign_RSA(privkey, RSAPrivateKey_dup(rsa));
    assert(ret == 1);

    ret = EVP_PKEY_assign_RSA(pubkey, RSAPublicKey_dup(rsa));
    assert(ret == 1);

    EVP_PKEY_print_private(out, privkey, 0, NULL);
    EVP_PKEY_print_public(out ,pubkey, 0, NULL);

    if (rsa)
    {
        RSA_free(rsa);
    }

    ctx = EVP_PKEY_CTX_new(pubkey, NULL);
    assert(ctx != NULL);

    if (EVP_PKEY_encrypt_init(ctx) <= 0)
    {
        fprintf(stderr, "EVP_PKEY_encrypt_init() error\n");
    }

    if (EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_OAEP_PADDING) <= 0)
    {
        fprintf(stderr, "EVP_PKEY_CTX_set_rsa_padding() error\n");
    }

    printf("\nplaintext\n");
    BIO_dump_fp(stdout, (const char*)plaintext, inlen);

    // encrypt
    if (EVP_PKEY_encrypt(ctx, NULL, &outlen, plaintext, inlen) <= 0)
    {
        fprintf(stderr, "EVP_PKEY_encrypt() 1 error\n");
    }

    ciphertext = OPENSSL_malloc(outlen);
    assert(ciphertext != NULL);
    memset(ciphertext, 0, outlen);

    if (ret = EVP_PKEY_encrypt(ctx, ciphertext, &outlen, plaintext, inlen) <= 0)
    {
        fprintf(stderr, "EVP_PKEY_encrypt() 2 error\n");
    }

    printf("\nciphertext\n");
    BIO_dump_fp(stdout, (const char*)ciphertext, outlen);

    EVP_PKEY_CTX_free(ctx);

    // decrypt
    ctx = EVP_PKEY_CTX_new(privkey, NULL);
    assert(ctx != NULL);

    if (EVP_PKEY_decrypt_init(ctx) <= 0)
    {
        fprintf(stderr, "EVP_PKEY_encrypt_init() error\n");
    }
    if (EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_OAEP_PADDING) <= 0)
    {
        fprintf(stderr, "EVP_PKEY_CTX_set_rsa_padding() error\n");
    }

    inlen = outlen;

    if (EVP_PKEY_decrypt(ctx, NULL, &outlen, ciphertext, inlen) <= 0)
    {
        fprintf(stderr, "evp_pkey_decrypt() 1 error\n");
    }

    recovered = OPENSSL_malloc(outlen);
    assert(recovered != NULL);
    memset(recovered, 0, outlen);

    if (ret = EVP_PKEY_decrypt(ctx, recovered, &outlen, ciphertext, inlen) <= 0)
    {
        fprintf(stderr, "EVP_PKEY_decrypt() 2 error\n");
    }

    printf("\nrecovered\n");
    BIO_dump_fp(stdout, (const char*)recovered, outlen);

    EVP_PKEY_CTX_free(ctx);

err:
    if (ciphertext)
    {
        OPENSSL_free(ciphertext);
    }

    if (recovered)
    {
        OPENSSL_free(recovered);
    }

}