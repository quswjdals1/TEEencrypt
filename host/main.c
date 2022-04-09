/*
 * Copyright (c) 2016, Linaro Limited
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 * this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 * this list of conditions and the following disclaimer in the documentation
 * and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

#include <err.h>
#include <stdio.h>
#include <string.h>

/* OP-TEE TEE client API (built by optee_client) */
#include <tee_client_api.h>

/* To the the UUID (found the the TA's h-file(s)) */
#include <TEEencrypt_ta.h>

int main(int argc, char *argv[])
{
	TEEC_Result res;
	TEEC_Context ctx;
	TEEC_Session sess;
	TEEC_Operation op;
	TEEC_UUID uuid = TA_TEEencrypt_UUID;
	uint32_t err_origin;
	

	
	char *command=argv[1];
	char *fname=argv[2];
	char *ekeyname=argv[3];
	
if(strcmp(command,"-e")==0)
{	
	
	

	char PATHNAME[40]="/root/";
	strcat(PATHNAME,fname);
	

	res = TEEC_InitializeContext(NULL, &ctx);
	if (res != TEEC_SUCCESS)
		errx(1, "TEEC_InitializeContext failed with code 0x%x", res);

	res = TEEC_OpenSession(&ctx, &sess, &uuid,
			       TEEC_LOGIN_PUBLIC, NULL, NULL, &err_origin);
	if (res != TEEC_SUCCESS)
		errx(1, "TEEC_Opensession failed with code 0x%x origin 0x%x",
			res, err_origin);

	memset(&op, 0, sizeof(op));
	op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_OUTPUT, TEEC_NONE,
					 TEEC_NONE, TEEC_NONE);
	

	printf("========================Encryption========================\n");
	FILE *fp;
	fp = fopen(PATHNAME, "r");
	fseek(fp, 0, SEEK_END);
	int size = ftell(fp);
	char *content = malloc(size + 1);
	memset(content, 0, size + 1);
	char *enccontent = malloc(size + 1);
	memset(enccontent, 0, size + 1);
	int len=size+1;
	char enckey[3]={0,};
	fseek(fp, 0, SEEK_SET);
	op.params[0].tmpref.buffer = content;
	op.params[0].tmpref.size = len+3;
	if(fp == NULL){ printf("open failed"); return 1;}
	else{
		fread(content,size,1,fp);}
	fclose(fp);
	memcpy(op.params[0].tmpref.buffer, content, len);

	res = TEEC_InvokeCommand(&sess, TA_TEEencrypt_CMD_ENC_VALUE, &op,
				 &err_origin);
	if (res != TEEC_SUCCESS)
		errx(1, "TEEC_InvokeCommand failed with code 0x%x origin 0x%x",
			res, err_origin);
	memset(enccontent, 0, size + 1);
	memcpy(enccontent, op.params[0].tmpref.buffer, len-2);
	memcpy(enckey,op.params[0].tmpref.buffer+len-1, 3);

	fp = fopen("encrypted.txt", "w");
	if(fp == NULL){ printf("open failed"); return 1;}
	else{fwrite(enccontent, strlen(enccontent), 1, fp);}
	fclose(fp);
	fp = fopen("enc_key.txt", "w");
	if(fp == NULL){ printf("open failed"); return 1;}
	else{fwrite(enckey, strlen(enckey), 1, fp);}
	fclose(fp);
	

	free(content);
	free(enccontent);
	TEEC_CloseSession(&sess);
	TEEC_FinalizeContext(&ctx);
	
	return 0;
}






else if(strcmp(command,"-d")==0){
	
	char PATHNAME[40]="/root/";
	char KEYPATH[40]="/root/";
	strcat(PATHNAME,fname);
	strcat(KEYPATH,ekeyname);

	res = TEEC_InitializeContext(NULL, &ctx);
	if (res != TEEC_SUCCESS)
		errx(1, "TEEC_InitializeContext failed with code 0x%x", res);

	res = TEEC_OpenSession(&ctx, &sess, &uuid,
			       TEEC_LOGIN_PUBLIC, NULL, NULL, &err_origin);
	if (res != TEEC_SUCCESS)
		errx(1, "TEEC_Opensession failed with code 0x%x origin 0x%x",
			res, err_origin);

	memset(&op, 0, sizeof(op));
	op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_OUTPUT, TEEC_NONE,
					 TEEC_NONE, TEEC_NONE);
	

	printf("========================Decryption========================\n");
	
	FILE *fp;
	


	fp = fopen(KEYPATH, "r");
	fseek(fp, 0, SEEK_END);
	int ksize = ftell(fp);
	char *enckey = malloc(ksize + 1);
	memset(enckey, 0, ksize + 1);
	fseek(fp, 0, SEEK_SET);
	if(fp == NULL){ printf("open failed"); return 1;}
	else{fread(enckey, ksize, 1, fp);}
	fclose(fp);


	fp = fopen(PATHNAME, "r");
	fseek(fp, 0, SEEK_END);
	int fsize = ftell(fp);
	char *content = malloc(fsize + 1);
	memset(content, 0, fsize + 1);
	fseek(fp, 0, SEEK_SET);
	if(fp == NULL){ printf("open failed"); return 1;}
	else{fread(content, fsize, 1, fp);}
	fclose(fp);
	
	
	
	int len=fsize+ksize+ 2;
	char *conkey = malloc(len);
	memset(conkey, 0, len);
	memcpy(conkey, content, fsize+1);
	memcpy(conkey+strlen(content)+1, enckey, ksize+1);
	
	op.params[0].tmpref.buffer = conkey;
	op.params[0].tmpref.size = len;
	memcpy(op.params[0].tmpref.buffer, conkey, len);
	
	res = TEEC_InvokeCommand(&sess, TA_TEEencrypt_CMD_DEC_VALUE, &op,
				 &err_origin);
	if (res != TEEC_SUCCESS)
		errx(1, "TEEC_InvokeCommand failed with code 0x%x origin 0x%x",
			res, err_origin);




	memset(content, 0, fsize + 1);
	memcpy(content, op.params[0].tmpref.buffer, len);
	memset(enckey, 0, ksize + 1);
	memcpy(enckey, op.params[0].tmpref.buffer+strlen(content)+1, ksize+1);
	
	

	fp = fopen("decrypted.txt", "w");
	if(fp == NULL){ printf("open failed"); return 1;}
	else{fwrite(content, strlen(content), 1, fp);}
	fclose(fp);

	fp = fopen("dec_key.txt", "w");
	if(fp == NULL){ printf("open failed"); return 1;}
	else{fwrite(enckey, strlen(enckey), 1, fp);}
	fclose(fp);
	
	free(enckey);
	free(content);
	free(conkey);
	TEEC_CloseSession(&sess);
	TEEC_FinalizeContext(&ctx);

	return 0;
}
}
