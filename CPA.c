#include <stdio.h>
#include <openssl/bn.h>
#include <openssl/aes.h>
#include <stdlib.h>
#include <string.h>
#include <malloc.h>
#include <math.h>
#include <ctype.h>
typedef unsigned char U8;
typedef unsigned int U32;
#define BYTES 16
#define BITS 128
int BN_xor(BIGNUM *b_r, int bits, const BIGNUM *b_a, const BIGNUM *b_b)
{
	//error
	if(b_r==NULL || b_a == NULL || b_b == NULL) 
		return 0;
	//bytes = bits / 8
	int i, bytes = bits >> 3;
	//calloc for type casting(BIGNUM to U8)
	U8 *r = (U8*)calloc(bytes,sizeof(U8));
	U8 *a = (U8*)calloc(bytes,sizeof(U8));
	U8 *b = (U8*)calloc(bytes,sizeof(U8));
	//BN_num_bytes(a) : return a's bytes 
	int byte_a = BN_num_bytes(b_a);
	int byte_b = BN_num_bytes(b_b);
	//difference between A and B
	int dif = abs(byte_a-byte_b);
	//minimum
	int byte_min = (byte_a < byte_b)? byte_a : byte_b;
	//type casting(BIGNUM to U8)
	BN_bn2bin(b_a,a);
	BN_bn2bin(b_b,b);
	//xor compute
	for(i=1;i<=byte_min;i++)
		r[bytes - i] = a[byte_a - i] ^ b[byte_b - i];
	for(i=1;i<=dif;i++)
		r[bytes - byte_min - i] = (byte_a>byte_b)? a[dif-i] : b[dif-i];
	//type casting(U8 to BIGNUM)
	BN_bin2bn(r,bytes,b_r);
	//Free memory
	free(a);
	free(b);
	free(r);
	return 1;//correct
}
int Gen(AES_KEY *enckey, int bits)
{
	if (enckey == NULL || bits <= 0) return 0;
	int bytes = bits >> 3;

	//*** write your code from here

	//choose uniform BN key
	BIGNUM *k = BN_new();
    BN_rand(k, bits, -1, 0);


	//type casting BN key -> U8(binary) key
	U8 *k_bytes = (U8 *)calloc(bytes, sizeof(U8));
    BN_bn2bin(k, k_bytes);
	
	//AES encrpytion key setting
	AES_set_encrypt_key(k_bytes, bits, enckey);

	BN_free(k);
    free(k_bytes);
	//*** end

	return 1;

}
U8 ** Enc(AES_KEY *k, int bits, U8 *m)
{
	int i, bytes = bits >> 3;
	U8 **c = (U8 **)calloc(2, sizeof(U8*)); // C = [r, F_k(r)]
	for (i = 0; i < 2; i++)
		c[i] = (U8 *)calloc(bytes, sizeof(U8));

	//*** write your code from here

	//choose uniform BN r
	BIGNUM *r = BN_new();
    BN_rand(r, bits, -1, 0);
	
    //print BN r
	printf("BN r: %s\n", BN_bn2hex(r));
	
    //setting C1
	BN_bn2bin(r, c[0]);
	
	//AES Encryption F_k(r)
	AES_encrypt(c[0], c[1], k);
	
	//type casting U8 F_k(r)-> BN F_k(r)    for F_k(r) xor m
	BIGNUM *bn_fk_r = BN_new();
	BN_bin2bn(c[1], bytes, bn_fk_r);
	
    //print F_k(r)
	printf("F_k(r): %s\n", BN_bn2hex(bn_fk_r));


	//type casting U8 m -> BN m       		for F_k(r) xor m
	BIGNUM *bn_m = BN_new();
	BN_bin2bn(m, bytes, bn_m);

	//C2 = F_k(r) xor m
	BN_xor(bn_fk_r, bits, bn_fk_r, bn_m);
	
    //setting C2
	BN_bn2bin(bn_fk_r, c[1]);

	
	BN_free(r);
    BN_free(bn_fk_r);
    BN_free(bn_m);
	//*** end

	return c;
}
U8 *Dec(AES_KEY *k, int bits, U8 **C)
{
	int bytes = bits >> 3;
	U8 *M = (U8*)calloc(bytes, sizeof(U8));

	//*** write your code from here

    //compute F_k(C1)
    U8 F_k_C1[BYTES];
    AES_encrypt(C[0], F_k_C1, k);
	
    //type casting U8 F_k(C1) -> BN F_k(C1)       for  F_k(C1) xor C2
    BIGNUM *F_k_C1_bn = BN_new();
    BN_bin2bn(F_k_C1, bytes, F_k_C1_bn);
	
	//print F_k(C1)
	printf("F_k(C1): %s\n", BN_bn2hex(F_k_C1_bn));

    //type casting U8 C[1] -> BN C2                for  F_k(C1) xor C2
    BIGNUM *C2_bn = BN_new();
    BN_bin2bn(C[1], bytes, C2_bn);
	
	//compute F_k(C1) xor C2 = m   and   type casting  BN m -> U8 M
	
	BN_xor(F_k_C1_bn, bits, F_k_C1_bn, C2_bn);
	BN_bn2bin(F_k_C1_bn, M);
	
	BN_free(F_k_C1_bn);
    BN_free(C2_bn);
	
	//*** end

	return M;
}
int main(int argc, char* argv[]) {
	int i;
	AES_KEY enckey; // AES encryption key
	U8 *m = (U8*)"CPA-secure";
	U8 *dec = (U8*)calloc(BYTES,sizeof(U8));
	
	Gen(&enckey,BITS);
	U8 **c = Enc(&enckey,BITS,m);
	U8 *d_m = Dec(&enckey,BITS,c);
	
	printf("C1 : ");
	for(i=0;i<BYTES;i++)
		printf("%02X",c[0][i]);
	printf("\n");
	printf("C2 : ");
	for(i=0;i<BYTES;i++)
		printf("%02X",c[1][i]);
	printf("\n");
	printf("Dec : %s\n", d_m);
	
	free(c[0]);
	free(c[1]);
	free(c);
	return 0;
}