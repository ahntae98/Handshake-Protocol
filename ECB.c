#include <stdio.h>
#include <openssl/bn.h>
#include <openssl/aes.h>
#include <openssl/rand.h>
#include <stdlib.h>
#include <string.h>
#include <malloc.h>
#include <math.h>
#include <ctype.h>
typedef unsigned char U8;
typedef unsigned int U32;
#define BYTES 16
#define BITS 128

// Electronic Code Block Mode
int Gen(U8 * key)
{
	if (key == NULL) return 0;
	RAND_bytes(key, BYTES);
	return 1;
}

int ecbEnc(U8 *key, const U8* msg , U8 *ecb){
	int i, j, msg_len = strlen(msg);
	// block size setting
	int block_size = (msg_len % BYTES==0) ?(msg_len/BYTES): (msg_len/BYTES+1);
	U8 *msg_block = (U8 *)calloc(BYTES*block_size, sizeof(U8));
	U8 *tmp = (U8 *)calloc(BYTES,sizeof(U8)), CT[BYTES]; 	// msg 1block을 카피하기위한 변수

	// AES encryp key setting [ TODO ]
	
	AES_KEY enckey; // ecnryption key setting
	AES_set_encrypt_key(key,BITS,&enckey);
	
	// copy msg to msg_block
	memcpy(msg_block, msg, msg_len + 1);
	
	// calculate pad num
	int pad = block_size*BYTES - msg_len;
	for(int j = 0; j < pad; j++)
		msg_block[msg_len + j] = pad;
	
	// print padded message
	printf("m_t\t\t: ");
	for(int j=0; j<BYTES; j++)
		printf("%02X", msg_block[(block_size-1)*BYTES + j]);
	printf("\n");
	
	for(i=0; i<block_size; i++)
	{	
		
		memcpy(tmp, &msg_block[i*BYTES], BYTES);
		// msg_block 1 block copy
		
        AES_encrypt(tmp, CT, &enckey);
		// enc(msg_block) = CT
		
		memcpy(ecb+i*BYTES, CT, BYTES);
		// CT를 ecb에 copy
		
	}
	
	free(msg_block);
	free(tmp);
	
	return (block_size)*BYTES;
}

int ecbDec(U8 *key, const U8 *ecb, int ct_len, U8* dec_msg) {
	U8 tmp[BYTES] = {0}, Message[BYTES] = { 0 };
	int i, j;
	
	// AES decrypt key setting [ TODO ]
	
		AES_KEY deckey;
		AES_set_decrypt_key(key,BITS,&deckey);

	
	for (i = 0; i < ct_len/BYTES; i++) {
		
		memcpy(tmp, &ecb[(i)*BYTES],BYTES);
		// ecb 1 block copy
		AES_decrypt(tmp, Message, &deckey);
		// dec(ecb 1 block) = msg
		memcpy(dec_msg + i*BYTES, Message, BYTES);
		//msg 를 dec_msg에 copy

	}
	
	U8 pad = dec_msg[ct_len - 1];
	
	// print padded decrypt message
	printf("pad num \t: %02X \n", pad);
	printf("Dec m_t \t: ");
   	for(j=0; j<BYTES;j++)
      	printf("%02X",dec_msg[(i - 1)*BYTES + j]);
   	printf("\n");
	
	
	for (int j=0; j<pad ;j++){
		dec_msg[ct_len - 1 - j] = 0;
	}
	
	return (strlen(dec_msg));
}

int main(int argc, char* argv[]) {
	
	// random seed
	RAND_status();
	
	// PRF key
	U8 key[BYTES];
	
	// Message
	U8 m[] = "Despite F is a pseudorandom function, ECB mode is not CPA-secure!";
		
	// Cipher
	int ecb_len = (strlen(m)%BYTES==0)? BYTES*(strlen(m)/BYTES) : BYTES*(strlen(m)/BYTES + 1); // BYTE = 한 블럭의 크기
	U8 *ecb = (U8 *)calloc(ecb_len,sizeof(U8)); //메모리 할당
	
	// generate key
	Gen(key);
	
	// ECB cnrypt
	ecb_len = ecbEnc(key,m,ecb);
	
	// Decrypt message
	U8 * dec_msg = (U8 *)calloc(ecb_len, sizeof(U8));
	
	// ECB decrypt
	int m_len = ecbDec(key, ecb, ecb_len, dec_msg);
	
	// print Enc
	printf("Enc \t\t: ");
	for(int i =0; i<ecb_len;i++)
		printf("%02X",ecb[i]);
	printf("\n");
	
	// print Dec
	if(m_len>0)
		printf("Decryption \t: %s\n",dec_msg);
	else
		printf("Error!!!\n");
	
	//free -> 부여된 메모리 해제
	free(ecb);
	free(dec_msg);
	return 0;
}
