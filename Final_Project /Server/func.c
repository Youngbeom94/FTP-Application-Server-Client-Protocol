#include "func.h"

const word cont[64] =
{
	0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1,
	0x923f82a4, 0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
	0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786,
	0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
	0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147,
	0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
	0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
	0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
	0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a,
	0x5b9cca4f, 0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
	0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};


void M_SHA256_init(OUT SHA256_INFO* info)
{
	info->hash[0] = 0x6a09e667;
	info->hash[1] = 0xbb67ae85;
	info->hash[2] = 0x3c6ef372;
	info->hash[3] = 0xa54ff53a;
	info->hash[4] = 0x510e527f;
	info->hash[5] = 0x9b05688c;
	info->hash[6] = 0x1f83d9ab;
	info->hash[7] = 0x5be0cd19;

	info->byte_msglen = 0;

	memset((byte*)info->buf, 0, BLOCKBYTE);
}


void M_Block(IN word* const pt, OUT SHA256_INFO* info)
{
	word W[64], a, b, c, d, e, f, g, h, temp1 = 0, temp2 = 0;
	int i = 0;

	for (i = 0; i < 16; i++)
	{	
		W[i] = ENDIAN_CHANGE(pt[i]);
	}


	for (i = 16; i < 64; i++)
		W[i] = W[i - 16] + W[i - 7] + WE0(W[i - 15]) + WE1(W[i - 2]);

	a = info->hash[0];
	b = info->hash[1];
	c = info->hash[2];
	d = info->hash[3];
	e = info->hash[4];
	f = info->hash[5];
	g = info->hash[6];
	h = info->hash[7];

	for (i = 0; i < 64; i++)
	{
		temp1 = h + BS1(e) + Ch(e, f, g) + cont[i] + W[i];
		temp2 = (BS0(a)) + (Maj(a, b, c));
		h = g;
		g = f;
		f = e;
		e = d + temp1;
		d = c;
		c = b;
		b = a;
		a = temp1 + temp2;
	}

	info->hash[0] += a;
	info->hash[1] += b;
	info->hash[2] += c;
	info->hash[3] += d;
	info->hash[4] += e;
	info->hash[5] += f;
	info->hash[6] += g;
	info->hash[7] += h;

}


void M_SHA256_Process(IN byte* pt, IN word byte_msglen, OUT SHA256_INFO* info)
{
	info->byte_msglen += byte_msglen;
	
	while (byte_msglen >= BLOCKBYTE)
	{
		memcpy((byte*)info->buf, pt, (BLOCKBYTE));
		M_Block((word*)info->buf, info);
		pt += BLOCKBYTE;
		byte_msglen -= BLOCKBYTE;
	}
	
	memcpy((byte*)info->buf, pt, (byte_msglen));
}

void M_SHA256_Final(OUT SHA256_INFO* info, OUT byte* hash_value)
{
	word final_byte = 0;

	word *asd;

	final_byte = (info->byte_msglen) % BLOCKBYTE;
	
	info->buf[final_byte++] = 0x80;

	if (final_byte > BLOCKBYTE - 8)
	{
		memset((byte*)info->buf + final_byte, 0, BLOCKBYTE - final_byte);
		M_Block((word*)info->buf, info);
		memset((byte*)info->buf, 0, BLOCKBYTE - 8);	
	}

	else
		memset((byte*)info->buf + final_byte, 0, BLOCKBYTE - final_byte - 8);

	((word*)info->buf)[BLOCKBYTE / 4 - 2] = ENDIAN_CHANGE(((info->byte_msglen) >> 29));
	((word*)info->buf)[BLOCKBYTE / 4 - 1] = ENDIAN_CHANGE(((info->byte_msglen) << 3) & 0xffffffff);
	M_Block((word*)info->buf, info);

	hash_value[0] = (info->hash[0] >> 24) & 0xff;
	hash_value[1] = (info->hash[0] >> 16) & 0xff;
	hash_value[2] = (info->hash[0] >> 8) & 0xff;
	hash_value[3] = (info->hash[0]) & 0xff;

	hash_value[4] = (info->hash[1] >> 24) & 0xff;
	hash_value[5] = (info->hash[1] >> 16) & 0xff;
	hash_value[6] = (info->hash[1] >> 8) & 0xff;
	hash_value[7] = (info->hash[1]) & 0xff;

	hash_value[8] = (info->hash[2] >> 24) & 0xff;
	hash_value[9] = (info->hash[2] >> 16) & 0xff;
	hash_value[10] = (info->hash[2] >> 8) & 0xff;
	hash_value[11] = (info->hash[2]) & 0xff;

	hash_value[12] = (info->hash[3] >> 24) & 0xff;
	hash_value[13] = (info->hash[3] >> 16) & 0xff;
	hash_value[14] = (info->hash[3] >> 8) & 0xff;
	hash_value[15] = (info->hash[3]) & 0xff;

	hash_value[16] = (info->hash[4] >> 24) & 0xff;
	hash_value[17] = (info->hash[4] >> 16) & 0xff;
	hash_value[18] = (info->hash[4] >> 8) & 0xff;
	hash_value[19] = (info->hash[4]) & 0xff;

	hash_value[20] = (info->hash[5] >> 24) & 0xff;
	hash_value[21] = (info->hash[5] >> 16) & 0xff;
	hash_value[22] = (info->hash[5] >> 8) & 0xff;
	hash_value[23] = (info->hash[5]) & 0xff;

	hash_value[24] = (info->hash[6] >> 24) & 0xff;
	hash_value[25] = (info->hash[6] >> 16) & 0xff;
	hash_value[26] = (info->hash[6] >> 8) & 0xff;
	hash_value[27] = (info->hash[6]) & 0xff;

	hash_value[28] = (info->hash[7] >> 24) & 0xff;
	hash_value[29] = (info->hash[7] >> 16) & 0xff;
	hash_value[30] = (info->hash[7] >> 8) & 0xff;
	hash_value[31] = (info->hash[7]) & 0xff;

}

void M_SHA256(IN byte* pt, IN unsigned long long byte_msglen, OUT byte* hash_value)
{

	SHA256_INFO info;
	M_SHA256_init(&info);
	M_SHA256_Process(pt, byte_msglen, &info);
	M_SHA256_Final(&info, hash_value);
}


void HMAC_SHA256_Encrpyt(IN  byte * pszMessage, IN word uPlainTextLen, IN  byte * key, IN word keyLen, OUT byte * mac)
{
   int cnt_i;
   int updatedKeyLen;

   SHA256_INFO info;
   byte K0[32] = { 0x00, };
   byte K1[SHA256_DIGEST_BLOCKLEN] = { 0x00, };    
   byte K2[SHA256_DIGEST_BLOCKLEN] = { 0x00, };      
   byte firsOut[SHA256_DIGEST_VALUELEN] = { 0x00, };

   if (keyLen > SHA256_DIGEST_BLOCKLEN)
   {
      M_SHA256_init(&info);
      M_SHA256_Process(key, keyLen, &info);
      M_SHA256_Final(&info, K0);
      updatedKeyLen = SHA256_DIGEST_VALUELEN;
   }
   else
   {
      memcpy(K0, key, keyLen);
      updatedKeyLen = keyLen;
   }

   memset(K1, IPAD, 64);
   memset(K2, OPAD, 64);

   for (cnt_i = 0; cnt_i < updatedKeyLen; cnt_i++)
   {
      K1[cnt_i] = IPAD ^ K0[cnt_i];
      K2[cnt_i] = OPAD ^ K0[cnt_i];
   }

   M_SHA256_init(&info);
   M_SHA256_Process(K1, sizeof(K1), &info);
   M_SHA256_Process(pszMessage, uPlainTextLen, &info);
   M_SHA256_Final(&info, firsOut);

   M_SHA256_init(&info);
   M_SHA256_Process(K2, sizeof(K2), &info);
   M_SHA256_Process(firsOut, sizeof(firsOut), &info);
   M_SHA256_Final(&info, mac);
}


void handleErrors(void)
{
    ERR_print_errors_fp(stderr);
    abort();
}

int encrypt(unsigned char *plaintext, int plaintext_len, unsigned char *key, unsigned char *iv, unsigned char *ciphertext)
{
    EVP_CIPHER_CTX *ctx;
    int len;
    int ciphertext_len;

    if (!(ctx = EVP_CIPHER_CTX_new()))
    {
        handleErrors();
    }

    if (1 != EVP_EncryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, key, iv))
    {
        handleErrors();
    }

    if (1 != EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len))
    {
        handleErrors();
    }
    ciphertext_len = len;

    if (1 != EVP_EncryptFinal_ex(ctx, ciphertext+len, &len))
    {
        handleErrors();
    }
    ciphertext_len += len;

    EVP_CIPHER_CTX_free(ctx);

    return ciphertext_len;
}

int decrypt(unsigned char *ciphertext, int ciphertext_len, unsigned char *key, unsigned char *iv, unsigned char *plaintext)
{
    EVP_CIPHER_CTX *ctx;
    int len;
    int plaintext_len;

    if (!(ctx = EVP_CIPHER_CTX_new()))
    {
        handleErrors();
    }

    if (1 != EVP_DecryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, key, iv))
    {
        handleErrors();
    }

    if (1 != EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len))
    {
        handleErrors();
    }
    plaintext_len = len;

    if (1 != EVP_DecryptFinal_ex(ctx, plaintext+len, &len))
    {
        handleErrors();
    }
    plaintext_len += len;

    EVP_CIPHER_CTX_free(ctx);

    return plaintext_len;
}
