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
#include <stdlib.h>
#include <tee_internal_api.h>
#include <tee_internal_api_extensions.h>
#include <stdio.h>
#include <string.h>
#include <TEEencrypt_ta.h>
int key;
int rootkey=3;
/*
 * Called when the instance of the TA is created. This is the first call in
 * the TA.
 */
TEE_Result TA_CreateEntryPoint(void)
{
	DMSG("has been called");

	return TEE_SUCCESS;
}

/*
 * Called when the instance of the TA is destroyed if the TA has not
 * crashed or panicked. This is the last call in the TA.
 */
void TA_DestroyEntryPoint(void)
{
	DMSG("has been called");
}

/*
 * Called when a new session is opened to the TA. *sess_ctx can be updated
 * with a value to be able to identify this session in subsequent calls to the
 * TA. In this function you will normally do the global initialization for the
 * TA.
 */
TEE_Result TA_OpenSessionEntryPoint(uint32_t param_types,
		TEE_Param __maybe_unused params[4],
		void __maybe_unused **sess_ctx)
{
	uint32_t exp_param_types = TEE_PARAM_TYPES(TEE_PARAM_TYPE_NONE,
						   TEE_PARAM_TYPE_NONE,
						   TEE_PARAM_TYPE_NONE,
						   TEE_PARAM_TYPE_NONE);

	DMSG("has been called");

	if (param_types != exp_param_types)
		return TEE_ERROR_BAD_PARAMETERS;

	/* Unused parameters */
	(void)&params;
	(void)&sess_ctx;

	/*
	 * The DMSG() macro is non-standard, TEE Internal API doesn't
	 * specify any means to logging from a TA.
	 */
	IMSG("Hello World!\n");

	/* If return value != TEE_SUCCESS the session will not be created. */
	return TEE_SUCCESS;
}

/*
 * Called when a session is closed, sess_ctx hold the value that was
 * assigned by TA_OpenSessionEntryPoint().
 */
void TA_CloseSessionEntryPoint(void __maybe_unused *sess_ctx)
{
	(void)&sess_ctx; /* Unused parameter */
	IMSG("Goodbye!\n");
}



static TEE_Result dec_value(uint32_t param_types,
	TEE_Param params[4])
{
	uint32_t exp_param_types = TEE_PARAM_TYPES(TEE_PARAM_TYPE_VALUE_INOUT,
						   TEE_PARAM_TYPE_NONE,
						   TEE_PARAM_TYPE_NONE,
						   TEE_PARAM_TYPE_NONE);

	IMSG("============================================");
	char * in = (char *)params[0].memref.buffer;
	int in_len = strlen (params[0].memref.buffer);
	char *decrypted = malloc(in_len);
	memset(decrypted, 0, in_len);
	memcpy(decrypted, in, in_len);
	char *deckey = malloc(3);
	memset(deckey, 0, 3);
	memcpy(deckey, in+in_len+1, 3);

	IMSG("incontent : %s\n inkey : %s", decrypted, deckey);
	
	int cnt=0;
	int reskey=0;
	for(int i=0; i<=strlen(deckey)+1; i++ ){
		if(deckey[i]=='\0'){break;}
		cnt++;
	}
	

	int temp[2];
	if(cnt==2){

		for(int i=0; i<2; i++){
			temp[i] = deckey[i] - '0';
			temp[i] = temp[i] - rootkey;
			if(temp[i]<0){
				temp[i] = 		10+temp[i];		
			}		
			deckey[i] = temp[i]+'0';
		}

	}
	else if(cnt==1){
		
		temp[0] = deckey[0] - '0';
		temp[0] = temp[0] - rootkey;
		if(temp[0]<0){
			temp[0] = 10+temp[0];		
		}		
		deckey[0] = temp[0]+'0';

	}
	for(int i=0; i<cnt; i++ ){
	reskey=reskey*10+(deckey[i]-'0');
	}
	









	for(int i=0; i<in_len;i++){
		if(decrypted[i]>='a' && decrypted[i] <='z'){
			decrypted[i] -= 'a';
			decrypted[i] -= reskey;
			decrypted[i] += 26;
			decrypted[i] = decrypted[i] % 26;
			decrypted[i] += 'a';
		}
		else if (decrypted[i] >= 'A' && decrypted[i] <= 'Z') {
			decrypted[i] -= 'A';
			decrypted[i] -= reskey;
			decrypted[i] += 26;
			decrypted[i] = decrypted[i] % 26;
			decrypted[i] += 'A';
		}
	}
	IMSG("deckey : %d", reskey);
	DMSG ("decrypted content :  %s\n", decrypted);
	memcpy(in, decrypted, in_len);
	memcpy(in+in_len+1, deckey, strlen(deckey));
	DMSG ("in :  %s\n", in);
	free(deckey);
	free(decrypted);
	return TEE_SUCCESS;

}


static TEE_Result enc_value(uint32_t param_types,
	TEE_Param params[4])
{
	uint32_t exp_param_types = TEE_PARAM_TYPES(TEE_PARAM_TYPE_VALUE_INOUT,
						   TEE_PARAM_TYPE_NONE,
						   TEE_PARAM_TYPE_NONE,
						   TEE_PARAM_TYPE_NONE);

	char * in = (char *)params[0].memref.buffer;
	int in_len = strlen (params[0].memref.buffer);
	char *encrypted = malloc(in_len);
	memset(encrypted, 0, in_len);
	char enckey[64]={0,};
	
	DMSG ("inkey :  %d", key);
	DMSG ("incontent :  %s", in);
	memcpy(encrypted, in, in_len);

	for(int i=0; i<in_len;i++){
		if(encrypted[i]>='a' && encrypted[i] <='z'){
			encrypted[i] -= 'a';
			encrypted[i] += key;
			encrypted[i] = encrypted[i] % 26;
			encrypted[i] += 'a';
		}
		else if (encrypted[i] >= 'A' && encrypted[i] <= 'Z') {
			encrypted[i] -= 'A';
			encrypted[i] += key;
			encrypted[i] = encrypted[i] % 26;
			encrypted[i] += 'A';
		}
		
		
	}
		


	DMSG ("encrypted content :  %s", encrypted);
	memcpy(in, encrypted, in_len);
	free(encrypted);
	
	char enc_key[3]={0,};
	if(key>=10){
		enc_key[0]=(key/10)+'0';
		enc_key[1]=(key%10)+'0';

		enc_key[0] -= '0';
		enc_key[0] += rootkey;
		enc_key[0] = enc_key[0] % 10;
		enc_key[0] += '0';

		enc_key[1] -= '0';
		enc_key[1] += rootkey;
		enc_key[1] = enc_key[1] % 10;
		enc_key[1] += '0';
			
}
	else{
		enc_key[0]=key+'0';
		enc_key[0] -= '0';
		enc_key[0] += rootkey;
		enc_key[0] = enc_key[0] % 10;
		enc_key[0] += '0';
	}

	
	DMSG ("inkey :  %d enckey : %s", key, enc_key);
	memcpy(in+in_len, enc_key, 3);
	DMSG ("result : %s", in);
	return TEE_SUCCESS;
}




/*
 * Called when a TA is invoked. sess_ctx hold that value that was
 * assigned by TA_OpenSessionEntryPoint(). The rest of the paramters
 * comes from normal world.
 */
TEE_Result TA_InvokeCommandEntryPoint(void __maybe_unused *sess_ctx,
			uint32_t cmd_id,
			uint32_t param_types, TEE_Param params[4])
{
	(void)&sess_ctx; /* Unused parameter */
	TEE_GenerateRandom(&key,1);
	 key=(key/10)+1;
	switch (cmd_id) {
	case TA_TEEencrypt_CMD_ENC_VALUE:
		return enc_value(param_types, params);
	case TA_TEEencrypt_CMD_DEC_VALUE:
		return dec_value(param_types, params);
	default:
		return TEE_ERROR_BAD_PARAMETERS;
	}
}
