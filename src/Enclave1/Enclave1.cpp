#include <stdlib.h>
#include <assert.h>
#include <string.h>
#include <stdarg.h>
#include <stdio.h>

#include "sgx_trts.h"
#include "sgx_tseal.h"
#include "Enclave1.h"
#include "Vault.h"
#include "Enclave1_t.h"


Vault* _vault = NULL;


/*
 * Just a printf
 */

void enclavePrintf(const char *fmt, ...)
{
    char buf[BUFSIZ] = {'\0'};
    va_list ap;

    va_start(ap, fmt);
    (void)vsnprintf(buf, BUFSIZ, fmt, ap);
    va_end(ap);
    ocall_e1_print_string(buf);
}

/*
 * Ecall interface
 */

int ecallCreateVault(const char *vaultName, size_t vaultNameSize, const char *fileName, size_t fileNameSize,
                     const char *psw, size_t pswSize, const char *author, size_t authorSize)
{
    _vault = (Vault*)malloc(sizeof(Vault));
    setupVault(_vault);
    enclavePrintf("Vault created successfully");


    char* sealedData;

    //int siz = sealData(&sealedData, "text\n", sizeof("text\n"));
    //ocallSaveDataToFile(sealedData, siz, "vault");
    //uint8_t* plaintext = (uint8_t*) malloc(64); 
    //unsealData(sealedData, plaintext);
    //unsealDataFromFile("vault", plaintext); // this does not work
    //enclavePrintf((char*) plaintext);

    return 0;
}

int ecallOpenVault(const char *fileName, size_t fileNameSize, const char *psw, size_t pswSize)
{
    enclavePrintf("Hello from create vault\n");
    return 0;
}

// We need to make sure that the assetName is unique
int ecallInsertFileAsset(const char *assetName, size_t assetNameSize, const char *fileName, size_t fileNameSize)
{

    enclavePrintf("Hello from insert file asset\n");
    return 0;
}

int ecallInsertAsset(const char *assetName, size_t assetNameSize, const char *assetData, int assetDataSize)
{
    enclavePrintf("Hello from insert asset\n");
    return 0;
}

// To add value, maybe we can add some parameters to this
int ecallListAssets()
{
    if(getState(_vault) != VALID) {
        enclavePrintf("Unable to list assets, vault is not in a valid state\n");
        return -1;
    }
    
    enclavePrintf("Vault asset list: ");

    VaultAsset* node = _vault->asset;

    while(node != NULL) {
        enclavePrintf("%s [%s]\n", node->name, node->hash);
        node = node->next;
    }

    return 0;
}

int ecallGetAsset(char *name, size_t nameSize)
{
    enclavePrintf("Hello from get asset\n");
    return 0;
}

// maybe the digest argument can be changed to a more appropiate type
char ecallCheckDigest(const char *assetName, size_t assetNameSize, const char *digest)
{
    enclavePrintf("Hello from check digest\n");
    return 0;
}

int ecallChangePassword(const char *newPsw, size_t newPswSize)
{
    enclavePrintf("Hello from change password\n");
    return 0;
}

// we need to had the clone feature, but lets forget that for now

/*
 * Internal methods
 */

int sealData(char** sealedData, char* data, size_t dataSize)
{
    sgx_status_t res;
    uint32_t plaintext_len = dataSize;
    uint8_t* plaintext = (uint8_t*) malloc(plaintext_len);
    memcpy(plaintext, data, plaintext_len);

    uint32_t ciph_size = sgx_calc_sealed_data_size(0, plaintext_len);
    *sealedData = (char*) malloc(ciph_size);

    res = sgx_seal_data(0, NULL, plaintext_len, plaintext, ciph_size, (sgx_sealed_data_t *) *sealedData);

    return ciph_size;
}

sgx_status_t unsealData(char* sealedData, uint8_t* plaintext)
{
    sgx_status_t res;
    uint32_t size = 6;

    res = sgx_unseal_data((sgx_sealed_data_t *) sealedData, NULL, NULL, plaintext, &size);
    return res;
}

void unsealDataFromFile(char* fileName, uint8_t* plaintext)
{
    char* sealedData = (char*) malloc(256);
    if (sealedData == NULL) {
        enclavePrintf("Error 1\n");
        return;
    }

    ocallLoadSealedData(sealedData, fileName);

    sgx_status_t res = unsealData(sealedData, plaintext);

    if (res != SGX_SUCCESS) {
        enclavePrintf("Error 2\n");
    }

    free(sealedData);
}


