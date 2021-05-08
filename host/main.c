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
	char plaintext[64] = {0,};
	char ciphertext[64] = {0,};
	char path[100] = "/root/";
	int len=64;
	int cipherkey = 0;

	res = TEEC_InitializeContext(NULL, &ctx);
	if (res != TEEC_SUCCESS)
		errx(1, "TEEC_InitializeContext failed with code 0x%x", res);

	res = TEEC_OpenSession(&ctx, &sess, &uuid,
			       TEEC_LOGIN_PUBLIC, NULL, NULL, &err_origin);
	if (res != TEEC_SUCCESS)
		errx(1, "TEEC_Opensession failed with code 0x%x origin 0x%x",
			res, err_origin);

	memset(&op, 0, sizeof(op));

	op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_OUTPUT, 
					 TEEC_VALUE_INOUT,		//param for encrypted key
					 TEEC_NONE, TEEC_NONE);
	op.params[0].tmpref.buffer = plaintext;
	op.params[0].tmpref.size = len;
	
	/******************************Encryption******************************/
	if(strcmp(argv[1], "-e") == 0)
	{	
		strcat(path, argv[2]);
		FILE *fp = fopen(path, "r");
		fgets(plaintext, sizeof(plaintext), fp);
		memcpy(op.params[0].tmpref.buffer, plaintext, len);

		fclose(fp);

		res = TEEC_InvokeCommand(&sess, TA_TEEencrypt_CMD_ENC_VALUE, &op,
					 &err_origin);

		FILE *fp_encrypted = fopen("/root/encrypted.txt", "w");

		memcpy(ciphertext, op.params[0].tmpref.buffer, len);
		fputs(ciphertext, fp_encrypted);
		fclose(fp_encrypted);

		FILE *fp_key = fopen("/root/key.txt", "w");
		cipherkey = op.params[1].value.a;
		fprintf(fp_key, "%d", cipherkey);
		fclose(fp_key);

	}

	/******************************Decryption******************************/
	else if(strcmp(argv[1], "-d") == 0)
	{	
		strcat(path, argv[3]);
		FILE *fp_key = fopen(path, "r");
		fscanf(fp_key, "%d", &cipherkey);
		op.params[1].value.a = cipherkey;
		fclose(fp_key);
		
		char path2[100] = "/root/";

		strcat(path2, argv[2]);
		FILE *fp = fopen(path2, "r");
		fgets(ciphertext, sizeof(ciphertext), fp);
		memcpy(op.params[0].tmpref.buffer, ciphertext, len);
		fclose(fp);
		res = TEEC_InvokeCommand(&sess, TA_TEEencrypt_CMD_DEC_VALUE, &op,
				 &err_origin);

		FILE *fp_decrypted = fopen("/root/decrypted.txt", "w");

		memcpy(plaintext, op.params[0].tmpref.buffer, len);
		fputs(plaintext, fp_decrypted);
		fclose(fp_decrypted);
		
	}
	

	if (res != TEEC_SUCCESS)
		errx(1, "TEEC_InvokeCommand failed with code 0x%x origin 0x%x",
			res, err_origin);


	TEEC_CloseSession(&sess);

	TEEC_FinalizeContext(&ctx);

	return 0;
}
