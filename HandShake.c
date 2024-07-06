#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <ctype.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <netinet/in.h>
#include <fcntl.h>
#include <openssl/aes.h>
#include <openssl/bn.h>
#include <openssl/rand.h>
#include <json-c/json.h>
#include <openssl/sha.h>
#include <openssl/hmac.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>

static struct sockaddr_in client_addr;
static int client_fd, n, n2, state = 1;
static char recv_data[6000];
static char chat_data[6000];

BIGNUM* BN_Square_Multi(const BIGNUM *x, const BIGNUM *a, const BIGNUM *n)
{
	BIGNUM *z, *temp;
    z = BN_new();
    temp = BN_new();
    BN_one(z);

    unsigned char *binary_a=(unsigned char *)malloc(BN_num_bytes(a));
	BN_bn2bin(a,binary_a);
    
    for (int i = BN_num_bits(a)-1; i >= 0; i--) 
	{
        BN_mod_sqr(z, z, n, BN_CTX_new());
        if (BN_is_bit_set(a,i)==1) {
            BN_mod_mul(temp, z, x, n, BN_CTX_new());
            BN_copy(z, temp);
        }
    }
    free(binary_a);
    BN_free(temp);

    return z;
}

int RSA_vrfy(unsigned char *msg,int msg_len,BIGNUM * CERT,BIGNUM *P_N,BIGNUM *P_E)
{
	//Hash(p_n||p_e)
	BIGNUM *Msg = BN_new();
	BIGNUM *X = BN_new();
	BIGNUM *Y = BN_new();
	BIGNUM *one = BN_new();
	BN_CTX *ctx = BN_CTX_new();

	BN_bin2bn(msg,msg_len,Msg); // binary msg를 BN M 로
	BN_one(one);
	X = BN_Square_Multi(CERT,P_E,P_N); // cert^e mod N
	Y = BN_Square_Multi(Msg,one,P_N); // M ^ one mod N
	int k = BN_cmp(X,Y); // compare A, B
	if(k == 0){ // 일치하면
		BN_free(Msg);
		BN_free(X);
		BN_free(Y);
		BN_CTX_free(ctx);
		return 1;
	}
	else{
		printf("\n\n%d\n",k);
		BN_free(Msg);
		BN_free(X);
		BN_free(Y);
		BN_CTX_free(ctx);
		return 0;
	}
}

void sha256_hash(const char *input1, const char *input2,int msg_len1,int msg_len2, unsigned char *output) {
    SHA256_CTX sha256;
    SHA256_Init(&sha256);
    SHA256_Update(&sha256, input1, msg_len1);
    SHA256_Update(&sha256, input2, msg_len2);
    SHA256_Final(output, &sha256);
}

unsigned char *RSA_enc(const unsigned char *msg, int msg_len, BIGNUM * pub_E, BIGNUM * pub_N)
{	
	BIGNUM *C = BN_new();
    BIGNUM *Msg = BN_new();
	BN_bin2bn(msg, msg_len, Msg);
    unsigned * cipher;

    C = BN_Square_Multi(Msg, pub_E, pub_N);
	cipher = BN_bn2hex(C);
	
	return cipher;
}

int main(int argc, char *argv[])
{
	char *IP = argv[1];
	in_port_t PORT = atoi(argv[2]);

	if (argc != 3)
	{
		printf("Useage : ./client [IP] [PORT]\n");
		exit(0);
	}

	client_fd = socket(PF_INET, SOCK_STREAM, 0);
	client_addr.sin_addr.s_addr = inet_addr(IP);
	client_addr.sin_family = AF_INET;
	client_addr.sin_port = htons(PORT);

	if (connect(client_fd, (struct sockaddr *)&client_addr, sizeof(client_addr)) == -1)
	{
		printf("Can't Connect\n");
		close(client_fd);
		return -1;
	}printf("Connect Sucess ! \n\n");
	//랜덤 256bit N 생성
	BIGNUM *Rand_Num = BN_new();
	BN_rand(Rand_Num,256,-1,0);
	// Hash 입력을 위해 랜덤 값 Nc을 binary로 바꿔줘야 함. 따라서 변수 새로 선언 후 동적할당.
	unsigned char *Nc_bin = (unsigned char *)malloc(BN_num_bytes(Rand_Num));
	unsigned char *Rand_Num_str = BN_bn2hex(Rand_Num);
	BN_bn2bin(Rand_Num,Nc_bin);
	
	//c_trans1 생성
	json_object *c_trans1 = json_object_new_object();
	json_object_object_add(c_trans1, "scheme", json_object_new_string("RSA_SCHEME"));
	json_object_object_add(c_trans1, "N", json_object_new_string(Rand_Num_str));
	//c_trans1 송신
	unsigned char * send_data = json_object_to_json_string(c_trans1);
	if ((n = send(client_fd, send_data, strlen(send_data)+1, 0)) == -1){
		printf("send fail \n");
		return 0;
	}
	//s_trans1 수신
	if((n = recv(client_fd, recv_data, sizeof(recv_data), 0))== -1){
		printf("recv error\n");
		return 0;
	}
	json_object *token = json_tokener_parse(recv_data);
	json_object *s_trans1 = json_object_get_string(token);
    printf("json : %s\n\n", s_trans1);
	//recv data 저장
	json_object *P_N = json_object_object_get(token,"P_N");
	json_object *P_E = json_object_object_get(token,"P_E");
	json_object *CA_N = json_object_object_get(token,"CA_N");
	json_object *CA_E = json_object_object_get(token,"CA_E");
	json_object *CERT = json_object_object_get(token,"CERT");
	json_object *N_s = json_object_object_get(token,"N");
	
	unsigned char * pn_str = json_object_get_string(P_N);
	unsigned char * pe_str = json_object_get_string(P_E);
	unsigned char * can_str = json_object_get_string(CA_N);
	unsigned char * cae_str = json_object_get_string(CA_E);
	unsigned char * cert_str = json_object_get_string(CERT);
	unsigned char * ns_str = json_object_get_string(N_s);
	
	printf("p_n : %s\n\np_e:%s\n\n",pn_str,pe_str);
	printf("ca_n : %s\n\nca_e:%s\n\n",can_str,cae_str);
	printf("cert : %s\n\n",cert_str);
	printf("n_s : %s\n\n",ns_str);
	// hash(p_n||p_e)
	BIGNUM *PN_bn = BN_new();
	BIGNUM *PE_bn = BN_new();
	BIGNUM *CERT_bn = BN_new();
	BIGNUM *CAN_bn = BN_new();
	BIGNUM *CAE_bn = BN_new();
	BIGNUM *Ns_bn = BN_new();
	
	BN_hex2bn(&PN_bn,pn_str);
	BN_hex2bn(&PE_bn,pe_str);
	BN_hex2bn(&CERT_bn,cert_str);
	BN_hex2bn(&CAN_bn,can_str);
	BN_hex2bn(&CAE_bn,cae_str);
	BN_hex2bn(&Ns_bn,ns_str);
	
	// Hash에 들어가는 변수들 동적할당
	unsigned char * pn_bin = (unsigned char *)malloc(BN_num_bytes(PN_bn));
	unsigned char * pe_bin = (unsigned char *)malloc(BN_num_bytes(PE_bn));
	unsigned char * Ns_bin = (unsigned char *)malloc(BN_num_bytes(Ns_bn));
	
	BN_bn2bin(PN_bn,pn_bin);
	BN_bn2bin(PE_bn,pe_bin);
	BN_bn2bin(Ns_bn,Ns_bin);
	
	unsigned char H[SHA256_DIGEST_LENGTH];
	sha256_hash(pn_bin,pe_bin,BN_num_bytes(PN_bn),BN_num_bytes(PE_bn),H);
	printf("H : ");
	for (int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
    	printf("%02x", H[i]);
	}
	printf("\n\n");
	//RSA Vrfy ==1?
	unsigned char H2[SHA256_DIGEST_LENGTH];
	SHA256_CTX hs2;
    SHA256_Init(&hs2);
    SHA256_Update(&hs2, H, SHA256_DIGEST_LENGTH);
    SHA256_Final(H2, &hs2);
	 if(RSA_vrfy(H2,SHA256_DIGEST_LENGTH,CERT_bn,CAN_bn,CAE_bn)){
	 	printf("cert verify ok!\n\n");
	 }
	 else{
	 	printf("cert verify fail !\n\n");
	 }
		 
	//랜덤 pmk 생성
	BIGNUM *PMK_bn = BN_new();
	BN_rand(PMK_bn,256,-1,0); // 256 pmk 생성
	
	unsigned char *pmk = (unsigned char *)malloc(BN_num_bytes(PMK_bn));
	BN_bn2bin(PMK_bn,pmk);
	printf("pmk : %s\n\n",BN_bn2hex(PMK_bn));
	
	//HASH Mk
	unsigned char Mk[SHA256_DIGEST_LENGTH];
	SHA256_CTX hs3;
    SHA256_Init(&hs3);
    SHA256_Update(&hs3, pmk, SHA256_DIGEST_LENGTH);
	SHA256_Update(&hs3, Nc_bin, SHA256_DIGEST_LENGTH);
	SHA256_Update(&hs3, Ns_bin, SHA256_DIGEST_LENGTH);
    SHA256_Final(Mk, &hs3); // Mk 해쉬로 생성 완료
	
	
	//RSA enc C
	unsigned char *C = RSA_enc(pmk,SHA256_DIGEST_LENGTH,PE_bn,PN_bn); // C를 만듬
	printf("C : %s\n\n",C);
	
	//c_trans2 생성
	json_object *c_trans2 = json_object_new_object();
	json_object_object_add(c_trans2, "C", json_object_new_string(C));
	
	//c_trans2 보냄
	unsigned char *send_data_2 = json_object_to_json_string(c_trans2);
	if ((n = send(client_fd, send_data_2, strlen(send_data_2)+1, 0)) == -1){
		printf("send fail \n");
		return 0;
	}
	
	//C_MAC
	int mdLen;
	EVP_MD* evpmd;
	evpmd = EVP_get_digestbyname("SHA256");
	unsigned char md[EVP_MAX_MD_SIZE];
	
	HMAC_CTX *hctx = HMAC_CTX_new(); // CTX 할당
	HMAC_CTX_reset(hctx);
	HMAC_Init(hctx,Mk,SHA256_DIGEST_LENGTH,evpmd);
	HMAC_Update(hctx,send_data,strlen(send_data));
	HMAC_Update(hctx,send_data_2,strlen(send_data_2));
	HMAC_Final(hctx,md,&mdLen);
	
	//MAC 보냄
	BIGNUM *CMAC = BN_new();
    BN_bin2bn(md, mdLen, CMAC);
	
	json_object *c_trans_mac = json_object_new_object();

    json_object_object_add(c_trans_mac, "MAC", json_object_new_string(BN_bn2hex(CMAC)));
    unsigned char *send_data3 = json_object_to_json_string(c_trans_mac);

    if ((n = send(client_fd, send_data3, strlen(send_data3)+1, 0)) == -1)
	{
            printf("send fail \n");
            return 0;
    }
	if((n = recv(client_fd, recv_data, sizeof(recv_data),0))== -1)
	{
            printf("recv error\n");
            return 0;
    }
    token = json_tokener_parse(recv_data);

	json_object *MAC_server = json_object_object_get(token,"MAC");
	unsigned char * MAC_server_str = json_object_get_string(MAC_server);
	
    //MAC` <- HMAC_mk(s_trans1)
	int mdLen2;
	EVP_MD* evpmd2;
	evpmd2=EVP_get_digestbyname("SHA256"); //해쉬함수 선택
	unsigned char md2[EVP_MAX_MD_SIZE]; 
	
	HMAC_CTX *hctx2 = HMAC_CTX_new(); //HMAC_CTX 할당
	HMAC_CTX_reset(hctx2);
	HMAC_Init(hctx2, Mk, SHA256_DIGEST_LENGTH, evpmd2); //선택한 해쉬함수와 key로 초기 세팅
	HMAC_Update(hctx2, s_trans1, strlen(s_trans1)); // s_trans1을 받아와서 Mac에 넣어준게 Mac`
	HMAC_Final(hctx2, md2, &mdLen2); //결과물을 md에 return (binary_string)
	
	printf("MAC` : " );
	for(int i=0;i<mdLen2;i++){
		printf("%02x", md2[i]);
	}
	printf("\n");
	
	json_object *S_MAC = json_object_object_get(token, "MAC"); // S_MAC = MAC
	unsigned char* s_mac= json_object_get_string(S_MAC); // 받아온 S_MAC을 hex로 바꿔줌
	printf("MAC : %s\n\n", s_mac); // 
	
	BIGNUM* BN_MAC = BN_new(); // 받아온 MAC을 선언
	BN_hex2bn(&BN_MAC, s_mac); // hex를 bn으로 
	unsigned char* bs_mac = (unsigned char *)malloc(BN_num_bytes(BN_MAC)); // 
	BN_bn2bin(BN_MAC, bs_mac);

	if(memcmp(md2, bs_mac, BN_num_bytes(BN_MAC)) == 0)
	{
		printf("Mac Verification Success!!\n\n");
	}
	else
	{
		printf("Mac Verification Fail!\n\n");
	}
	// Mac verifycation Fin.
	//char *input1, const char *input2,int msg_len1,int msg_len2, unsigned char *output)
	unsigned char k_c[SHA256_DIGEST_LENGTH] = {0};
	unsigned char zero = 0x00;
    sha256_hash(&zero,Mk,1,SHA256_DIGEST_LENGTH, k_c);
    printf("k_c : ");
    for(int i=0;i<SHA256_DIGEST_LENGTH;i++){
        printf("%02x", k_c[i]);
    }
    printf("\n");
	
	unsigned char k_c1[SHA256_DIGEST_LENGTH] = {0};
    unsigned char one = 0x01;
    sha256_hash(&one,Mk,1,SHA256_DIGEST_LENGTH, k_c1);
    printf("k_c1 : ");
    for(int i=0;i<SHA256_DIGEST_LENGTH;i++){
        printf("%02x", k_c1[i]);
    }
    printf("\n");
	
	unsigned char k_s[SHA256_DIGEST_LENGTH] = {0};
    unsigned char two = 0x02;
    sha256_hash(&two,Mk,1,SHA256_DIGEST_LENGTH, k_s);
    printf("k_s : ");
    for(int i=0;i<SHA256_DIGEST_LENGTH;i++){
        printf("%02x", k_s[i]);
    }
    printf("\n");
	
	unsigned char k_s1[SHA256_DIGEST_LENGTH] = {0};
    unsigned char three = 0x03;
    sha256_hash(&three,Mk,1,SHA256_DIGEST_LENGTH, k_s1);
    printf("k_s1 : \n");
    for(int i=0;i<SHA256_DIGEST_LENGTH;i++){
        printf("%02x", k_s1[i]);
    }
    printf("\n\n");
	
	// MSG = "How are u?"
	unsigned char Msg[16] = "How are u?";
    AES_KEY s_enc_key; // key 생성
    AES_set_encrypt_key(k_s,128,&s_enc_key);
	printf("send Msg : %s\n\n",Msg);
	// AES encrypt로 CT 생성
	unsigned char CT[16]; 
    AES_encrypt(Msg, CT, &s_enc_key);
	printf("C : ");
	for(int i =0;i<16;i++)
	{
		printf("%02x",C[i]);	
	}
	printf("\n\n");
	
	BIGNUM *BN_CT = BN_new(); // BN CT
    BN_bin2bn(CT, SHA256_DIGEST_LENGTH, BN_CT); // binary -> bn
	
	//CT_MAC = HMAC_k_s_(CT)  --->md3 = CT_MAC
    int mdLen3;
    EVP_MD* evpmd3;
    evpmd3 = EVP_get_digestbyname("SHA256");
    unsigned char md3[EVP_MAX_MD_SIZE]; 
    
    HMAC_CTX *hctx3 = HMAC_CTX_new(); //HMAC_CTX 할당
    HMAC_CTX_reset(hctx3); //CTX 초기화
    HMAC_Init(hctx3, k_s1, SHA256_DIGEST_LENGTH, evpmd3); // 
    HMAC_Update(hctx3, CT, 16); // update str
    HMAC_Final(hctx3, md3, &mdLen3); //결과물을 md3에 return (binary_string)
    printf("CT_MAC : " );
    for(int i=0;i<mdLen3;i++){
        printf("%02x", md3[i]);
    }
    printf("\n"); 
	
	
    BIGNUM *BN_CT_MAC = BN_new(); 
    BN_bin2bn(md3, mdLen3, BN_CT_MAC); // binary 를 bn으로 바꿔

    //CT, CT_MAC 보냄
    json_object *c_trans_ct = json_object_new_object();
    json_object_object_add(c_trans_mac, "CT", json_object_new_string(BN_bn2hex(BN_CT))); // hex로 바꿔 송신
    json_object_object_add(c_trans_mac, "MAC", json_object_new_string(BN_bn2hex(BN_CT_MAC))); // hex로 바꿔 송신
    unsigned char *send_data4 = json_object_to_json_string(c_trans_mac);

    printf("send data : %s\n\n", send_data4);

    if((n = send(client_fd, send_data4, strlen(send_data4)+1, 0)) == -1){
            printf("send fail \n");
            return 0;
    }
	
	if((n = recv(client_fd, recv_data, sizeof(recv_data), 0))== -1){
			printf("recv error\n");
			return 0;
	}
	token = json_tokener_parse(recv_data);
	json_object *S_CT = json_object_object_get(token, "CT");
	unsigned char* s_ct= json_object_get_string(S_CT);
	printf("CT : %s\n\n", s_ct);
	
	json_object *S_CT_MAC = json_object_object_get(token, "MAC");
	unsigned char* s_ct_mac= json_object_get_string(S_CT_MAC);
	printf("MAC : %s\n\n", s_ct_mac);
	
	BIGNUM *BN_s_ct = BN_new();
	BN_hex2bn(&BN_s_ct, s_ct);
	unsigned char* bin_s_ct = (unsigned char*)malloc(BN_num_bytes(BN_s_ct));
	BN_bn2bin(BN_s_ct, bin_s_ct);
	
	BIGNUM *BN_s_mac = BN_new();
	BN_hex2bn(&BN_s_mac, s_ct_mac);
	unsigned char* bin_s_mac = (unsigned char*)malloc(BN_num_bytes(BN_s_mac));
	BN_bn2bin(BN_s_mac, bin_s_mac);
	
	// MAC` = HMAC(CT) -> key : kc1
	int mdLen4;
	EVP_MD* evpmd4;
	evpmd4=EVP_get_digestbyname("SHA256"); //해쉬함수 선택 
	unsigned char md4[EVP_MAX_MD_SIZE];   
	
	HMAC_CTX *hctx4 = HMAC_CTX_new(); //HMAC_CTX 할당
	HMAC_CTX_reset(hctx4); //CTX 초기화
	HMAC_Init(hctx4, k_c1, SHA256_DIGEST_LENGTH, evpmd4); //선택한 해쉬함수와 key로 초기 세팅
	HMAC_Update(hctx4, bin_s_ct, 16); // update str 
	HMAC_Final(hctx4, md4, &mdLen4); //결과물을 md에 return (binary_string)
	printf("MAC` : " );
	for(int i=0;i<mdLen4;i++){
		printf("%02x", md4[i]);
	}
	printf("\n\n");
	
	unsigned char dec[16]={0};
	AES_KEY c_dec_key;
	//MAC’ == CT_MAC
	if(memcmp(md4, bin_s_mac, mdLen4)==0){
		printf("Mac Verification Success!!\n\n");
		//AES_set_decrypt_key(kc, 128, c_dec_key);
		AES_set_decrypt_key(k_c, 128, &c_dec_key);
		AES_decrypt(bin_s_ct, dec, &c_dec_key);
		printf("received msg : %s\n", dec);
	}
	else{
		printf("Mac Verification Fail!\n");
	}
	close(client_fd);
	return 0;
}