#include <stdlib.h>
#include <assert.h>
#include <string.h>
#include <stdarg.h>
#include <stdio.h>

#include "sgx_trts.h"
#include "sgx_tseal.h"
#include "Enclave1.h"
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
    createVault(_vault);
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


static VaultState getState(Vault *vault) { return vault->state; }

static void createVault(Vault *vault)
{
    vault->state = NOT_YET_PARSED;
    vault->header = NULL;
    vault->asset = NULL;
}

static void createVaultAsset(VaultAsset *vaultAsset, char *name)
{
    memcpy(vaultAsset->name, name, sizeof(vaultAsset->name));
    memcpy(vaultAsset->hash, "", sizeof(vaultAsset->name));
    vaultAsset->size = 0;
    vaultAsset->content = NULL;
    vaultAsset->next = NULL;
    vaultAsset->previous = NULL;
}

static void createVaultHeader(VaultHeader *vaultHeader, char *name, char *password)
{
    memcpy(vaultHeader->name, name, sizeof(vaultHeader->name));
    memcpy(vaultHeader->nonce, "", sizeof(vaultHeader->nonce)); // mudar para colocar um numero random
    memcpy(vaultHeader->password, password, sizeof(vaultHeader->password));
    vaultHeader->numberOfFiles = 0;
}

static int copyWithoutNeighborsDeeply(VaultAsset *src, VaultAsset *dst)
{
    if (src == NULL || dst == NULL)
        return -1;

    memcpy(dst->hash, src->hash, sizeof(src->hash));
    memcpy(dst->name, src->name, sizeof(src->name));

    dst->size = src->size;

    if (src->content != NULL)
    {
        dst->content = (char *)malloc(sizeof(char) * src->size);
        memcpy(dst->content, src->content, src->size);
    }
    else
    {
        dst->content = NULL;
    }

    dst->next = NULL;
    dst->previous = NULL;

    return 0;
}

static int pushAsset(Vault *vault, VaultAsset *asset)
{
    // check if it's possible to throw exceptions inside enclave (maybe send errors to unsafe world such as printf)
    if (getState(vault) != VALID)
    {
        return -1;
    }
    // make a copy of the asset and store in Vault::asset

    return 1;
}

static int changePassword(Vault *vault, char *newPswd)
{
    memcpy(vault->header->password, newPswd, sizeof(vault->header->password));
    return 1;
}

static int fetchAsset(Vault *vault, char name[32], VaultAsset *asset)
{
    if (getState(vault) != VALID)
        return -1;

    VaultAsset *curr = vault->asset;
    while (curr != NULL)
    {
        if (strcmp(name, curr->name) == 0)
        {
            copyWithoutNeighborsDeeply(curr, asset);
            return 0;
        }
        curr = curr->next;
    }

    return -2;
}

static int loadVault(Vault *vault, const char *data, char *pw)
{
    // if hash fails set corrupted State
    // ...

    vault->state = VALID;

    return 0;
}

static int destroyVault(Vault *vault)
{
    if (vault->state == NOT_YET_PARSED)
        return 1;

    free(vault->header);
    VaultAsset *curr = vault->asset;
    VaultAsset *next;
    while (curr != NULL)
    {
        if (curr->content)
        {
            free(curr->content);
            curr->content = NULL;
        }
        next = curr->next;
        free(curr);
        curr = next;
    }

    return 1;
}


