#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/aes.h>
#include <openssl/rand.h>
#include <string.h>
#include <ctype.h>
#include <openssl/sha.h>
#include <openssl/bn.h>
#include <openssl/dh.h>

typedef unsigned char U8;
typedef struct
{
	BIGNUM *d; 
	BIGNUM *x;
	BIGNUM *y;
}BN_dxy;

BN_dxy BN_dxy_new(const BIGNUM *d, const BIGNUM *x, const BIGNUM *y) {
	BN_dxy dxy;
	dxy.d = BN_new(); dxy.x = BN_new(); dxy.y = BN_new();
	if (d == NULL)
		return dxy;
	BN_copy(dxy.d, d);
	BN_copy(dxy.x, x);
	BN_copy(dxy.y, y);
	return dxy;
}

int BN_dxy_copy(BN_dxy * dxy, BIGNUM *d, BIGNUM *x, BIGNUM *y)
{
	BN_copy(dxy->d, d);
	BN_copy(dxy->x, x);
	BN_copy(dxy->y, y);
}

void BN_dxy_free(BN_dxy * dxy)
{
	BN_free(dxy->d);
	BN_free(dxy->x);
	BN_free(dxy->y);
}

BIGNUM* BN_Square_Multi(BIGNUM *x, BIGNUM *a, BIGNUM *n)
{
	/* your code here */
	BIGNUM *result;
	BN_CTX *bn_ctx;
	
	result = BN_new();
	bn_ctx = BN_CTX_new();
	
	int a_bitlen = BN_num_bits(a);
	
	BN_one(result);
	
	for(int i = a_bitlen-1; i>=0;i--)
	{
		BN_mod_mul(result, result, result , n, bn_ctx);
		if(BN_is_bit_set(a,i))
		{
			BN_mod_mul(result, result, x, n ,bn_ctx);
		}
	}
	return result;
}

BN_dxy BN_Ext_Euclid(BIGNUM* a, BIGNUM* b) {
	BN_dxy dxy;
	if (BN_is_zero(b)) {
		dxy = BN_dxy_new(a, BN_value_one(), b);
		return dxy;
	}
	else {
		/* your code here */
		BIGNUM *div, *rem, *tmp;
		BN_CTX *bn_ctx;
		
		div = BN_new(); rem = BN_new(), tmp = BN_new();
		bn_ctx = BN_CTX_new();
		
		BN_div(div,rem,a,b,bn_ctx);
		dxy = BN_Ext_Euclid(b,rem);
		
		BN_mul(tmp,div,dxy.y,bn_ctx);
		BN_sub(tmp,dxy.x,tmp);
		
		BN_dxy_copy(&dxy,dxy.d,dxy.y, tmp);
		BN_free(div);
		BN_free(rem);
		BN_free(tmp);
		BN_CTX_free(bn_ctx);
		
		return dxy;
	}
}

void RSA_setup(BIGNUM *pub_e, BIGNUM* pub_N, BIGNUM* priv)
{   
    BN_CTX *bn_ctx = BN_CTX_new();
    BIGNUM *p = BN_new();
    BIGNUM *q = BN_new();
    BN_dxy dxy; 
    BIGNUM *N = BN_new();
    BIGNUM *e = BN_new();
    BIGNUM *ord = BN_new(); // order of group -> 파이랑 같음.
    BN_set_word(e, 3);

    while(1)
	{
        BN_generate_prime_ex(p, 1024, 0, NULL, NULL, NULL);
        BN_generate_prime_ex(q, 1024, 0, NULL, NULL, NULL);

        BN_mul(N, p, q, bn_ctx); // N 계산

        // ord = (p-1) * (q-1)
        BN_sub(p, p, BN_value_one()); // p-1
        BN_sub(q, q, BN_value_one()); // q-1
        BN_mul(ord, p, q, bn_ctx); // ord = (p-1) * (q-1)

        dxy = BN_Ext_Euclid(e,ord);
		if(BN_is_one(dxy.d))
			break;
    }

    // Calculate private key using Extended Euclidean algorithm
    BN_copy(priv, dxy.x);

    // Set values of pub_e, pub_N
    BN_copy(pub_e, e);
    BN_copy(pub_N, N);
    
    printf("e\t : %s\n", BN_bn2hex(pub_e));
    printf("N\t : %s\n", BN_bn2hex(pub_N));
    printf("dxy.y\t : %s\n", BN_bn2hex(dxy.y));
    printf("dxy.x\t : %s\n", BN_bn2hex(dxy.x));
    printf("dxy.d\t : %s\n\n", BN_bn2hex(dxy.d));

    BN_CTX_free(bn_ctx);
    BN_free(p);
    BN_free(q);
    BN_free(N);
    BN_free(e);
    BN_free(ord);
    BN_dxy_free(&dxy);
}

U8* RSA_enc(const U8* msg, BIGNUM* pub_e, BIGNUM* pub_N) 
{
    BIGNUM *C = BN_new();
    BIGNUM *M = BN_new();
    BN_bin2bn(msg, strlen(msg), M);
	BN_CTX *bn_ctx = BN_CTX_new();
	
    BN_mod_exp(C, M, pub_e, pub_N, bn_ctx); // C를 구함

	int cipher_len = BN_num_bytes(C);
    U8* cipher = (U8*)malloc(cipher_len);
   	BN_bn2binpad(C, cipher, cipher_len-1);

    BN_free(C);
    BN_free(M);
    BN_CTX_free(bn_ctx);
	
    return cipher;
}


int RSA_dec(U8 *dec_msg, const BIGNUM *priv, const BIGNUM *pub_N, const U8 *cipher) {
    BIGNUM *C = BN_new();
    BIGNUM *M = BN_new();
	BN_CTX *bn_ctx = BN_CTX_new();

	BN_bin2bn(cipher, strlen((const char*)cipher), C); // cipher text를 C로 바꿈
	
	BN_mod_exp(M, C, priv, pub_N, bn_ctx); // M을 구함
	
	int msg_len = BN_num_bytes(M);
    BN_bn2binpad(M, dec_msg, msg_len);

    BN_free(C);
    BN_free(M);
    BN_CTX_free(bn_ctx);

    return msg_len;
}

int main() {
	U8 *msg = "hello";
	BIGNUM * e = BN_new();
	BIGNUM * d = BN_new();
	BIGNUM * N = BN_new();
	RSA_setup(e, N, d);
	U8 * cipher = RSA_enc(msg, e, N);
	printf("Cipher text : %s\n", cipher);
	U8 dec_msg[1024] = { 0 };
	int dec_len = RSA_dec(dec_msg, d, N, cipher);
	printf("dec : %s\n", dec_msg);

	BN_free(e);
	BN_free(N);
	BN_free(d);
	return 0;
}
