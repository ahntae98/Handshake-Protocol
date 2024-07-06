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

int Gen(U8 * key)
{
   if (key == NULL) return 0;
	
   RAND_bytes(key, BYTES);
	
   return 1;
}

int cbcEnc(U8 *key, const U8* msg , U8 *cbc)
{
   int i, j, msg_len = strlen(msg), mb_len =((msg_len/BYTES) + 1) * BYTES, bottom = BYTES - 1;
   U8 IV[BYTES], *msg_block = (U8 *)calloc(mb_len,sizeof(U8)), cxorm[17] = {0};
	
   AES_KEY enckey;
   AES_set_encrypt_key(key,BITS,&enckey);
	
   if (RAND_bytes(IV, 16) <= 0)
      printf("random error\n");
	
   memcpy(cbc, IV, BYTES);
   memcpy(msg_block,msg,msg_len);
	
   int pad = mb_len-msg_len;
   for(j=0; j < pad; j++)
      msg_block[msg_len+j] = pad;
   printf("m_t \t\t: ");
   for(j= 0;j<BYTES; j++)
      printf("%02X",msg_block[mb_len-BYTES + j]);
   printf("\n");
	
   for(i=0; i<mb_len/BYTES; i++)
   {  
	  /***************Your Code Here*****************/
      //cxorm =m_i xor c_{i-1}
      for(j=0; j<BYTES; j++)
         cxorm[j] = msg_block[i*BYTES+j] ^ cbc[i*BYTES+j];

      //c_{i} = AES_encrypt(cxorm)
      AES_encrypt(cxorm, &cbc[(i+1)*BYTES], &enckey);
   }
   free(msg_block);
	
   return (i + 1)*BYTES;
}

int cbcDec(U8 *key, const U8 *cbc, int ct_len, U8* dec_msg) {
   U8 IV[BYTES] = { 0 }, cxorm[17] = {0};
   int i, j, bottom = BYTES - 1;
   /***************Your Code Here*****************/
	//AES set decrypt key
	AES_KEY deckey;
	AES_set_decrypt_key(key, BITS, &deckey);
	
   	for(i = 1; i < ct_len/16; i++) {
      /***************Your Code Here*****************/
	  //cxorm = AES_decrypt(c_{i-1})
    AES_decrypt(&cbc[i*BYTES], cxorm, &deckey);

      // m_i = cxorm  xor  c_{i-1}
	for(j=0; j<BYTES; j++)
			dec_msg[(i-1)*BYTES+j] = cxorm[j] ^ cbc[(i-1)*BYTES+j];
   	}
	
   	U8 pad = dec_msg[ct_len - 17];
   	if(pad<=0 || pad>BYTES) return 0;
   	printf("Dec m_t \t: ");
   	for(j=0; j<BYTES;j++)
      printf("%02X",dec_msg[(i - 2)*BYTES + j]);
   	printf("\n");
   	for (j = 0; j<pad ; j++)
      dec_msg[ct_len - 17 - j] = 0;
   	return (strlen(dec_msg));
}

int main(int argc, char* argv[]) {
   RAND_status();
   U8 key[BYTES];
   U8 m[] = "If F is a pseudorandom function, then CBC mode is CPA-secure";
   int cbc_len = BYTES*(strlen(m)/BYTES + 2);
   U8 * cbc = (U8 *)calloc(cbc_len,sizeof(U8));
   Gen(key);
   cbc_len = cbcEnc(key,m,cbc);
   U8 * dec_msg = (U8 *)calloc(cbc_len - BYTES, sizeof(U8));
   int m_len = cbcDec(key,cbc,cbc_len,dec_msg);
   printf("Enc \t\t: ");
   for(int i =0; i<cbc_len;i++)
      printf("%02X",cbc[i]);
   printf("\n");
   if(m_len>0)
      printf("Decryption \t: %s\n",dec_msg);
   else
      printf("Error!!!\n");
    free(cbc);
   free(dec_msg);
   return 0;
}
