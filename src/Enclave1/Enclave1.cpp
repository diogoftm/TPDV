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

Vault *_vault = NULL;

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

int ecallCreateVault(const char *vaultName, const char *fileName, const char *psw, const char *author)
{
    _vault = (Vault *)malloc(sizeof(Vault));
    setupVault(_vault);

    setupVaultHeader(&_vault->header, (char *)vaultName, (char *)psw, (char *)author);

    enclavePrintf("Vault created successfully\n");

    // TODO
    // char *sealedData;
    // int siz = sealData(&sealedData, "text\n", sizeof("text\n"));
    // ocallSaveDataToFile(sealedData, siz, "vault");
    // uint8_t* plaintext = (uint8_t*) malloc(64);
    // unsealData(sealedData, plaintext);
    // unsealDataFromFile("vault", plaintext); // this does not work
    // enclavePrintf((char*) plaintext);

    return 0;
}

int ecallOpenVault(const char *fileName, size_t fileNameSize, const char *psw, size_t pswSize)
{
    enclavePrintf("Hello from create vault\n");
    return 0;
}

int ecallInsertAsset(const char *assetName, size_t assetNameSize, const char *assetData, int assetDataSize)
{
    int err = 0;
    VaultAsset *newAsset = (VaultAsset *)malloc(sizeof(VaultAsset));
    setupVaultAsset(newAsset, (char *)assetName, (unsigned char *)assetData, assetDataSize);
    err = pushAsset(_vault, newAsset);
    if(err != 0) {
        
        if (err == -1) {
            enclavePrintf("Unable to insert asset, vault is not in a valid state\n");
        } else if (err == -2) {
            enclavePrintf("Unable to insert asset, asset name is repeated\n");
        }
        
        return -1;
    }
    return 0;
}

// To add value, maybe we can add some parameters to this
int ecallListAssets()
{
    if (getState(_vault) != VALID)
    {
        enclavePrintf("Unable to list assets, vault is not in a valid state\n");
        return -1;
    }

    enclavePrintf("Vault asset list:\n");

    VaultAsset *node = _vault->asset;

    int i = 1;
    while (node != NULL)
    {
        enclavePrintf("%d - name: %s , size: %d \n", i, node->name, node->size);
        node = node->next;
        i++;
    }

    return 0;
}

int ecallPrintAsset(char *name)
{
    VaultAsset *node = _vault->asset;

    while (node != NULL && strcmp(node->name, name) != 0)
        node = node->next;

    if (node != NULL)
    {
        enclavePrintf("-----------\n'%s' content \n-----------\n%s\n-----------\n", name, node->content);
        return 0;
    }

    return 1;
}

int ecallSaveAssetToFile(char *assetName, char *fileName)
{
    VaultAsset *node = _vault->asset;

    while (node != NULL && strcmp(node->name, assetName) != 0)
        node = node->next;

    if (node != NULL)
    {
        ocallSaveDataToFile((const char *)node->content, node->size, fileName);
        return 0;
    }

    return 1;
}

// maybe the digest argument can be changed to a more appropiate type
char ecallCheckDigest(const char *assetName, const char *digest)
{
    VaultAsset *node = _vault->asset;

    while (node != NULL && strcmp(node->name, assetName) != 0)
        node = node->next;

    if (node != NULL)
        return strcmp((char *)node->hash, digest);

    return -2;
}

int ecallChangePassword(const char *newPsw, size_t newPswSize)
{
    if (newPswSize > 32)
    {
        enclavePrintf("Password size exceeded max size (max := %d, received %d)\n", 32, newPswSize);
        return -1;
    }

    changePassword(_vault, (char *)newPsw);
    enclavePrintf("Sucessfully changed vault password\n");

    return -1;
}

// we need to had the clone feature, but lets forget that for now

/*
 * Internal methods
 */

int sealData(char **sealedData, char *data, size_t dataSize)
{
    sgx_status_t res;
    uint32_t plaintext_len = dataSize;
    uint8_t *plaintext = (uint8_t *)malloc(plaintext_len);
    memcpy(plaintext, data, plaintext_len);

    uint32_t ciph_size = sgx_calc_sealed_data_size(0, plaintext_len);
    *sealedData = (char *)malloc(ciph_size);

    res = sgx_seal_data(0, NULL, plaintext_len, plaintext, ciph_size, (sgx_sealed_data_t *)*sealedData);

    return ciph_size;
}

sgx_status_t unsealData(char *sealedData, uint8_t *plaintext)
{
    sgx_status_t res;
    uint32_t size = 6;

    res = sgx_unseal_data((sgx_sealed_data_t *)sealedData, NULL, NULL, plaintext, &size);
    return res;
}

void unsealDataFromFile(char *fileName, uint8_t *plaintext)
{
    char *sealedData = (char *)malloc(256);
    if (sealedData == NULL)
    {
        enclavePrintf("Error 1\n");
        return;
    }

    ocallLoadSealedData(sealedData, fileName);

    sgx_status_t res = unsealData(sealedData, plaintext);

    if (res != SGX_SUCCESS)
    {
        enclavePrintf("Error 2\n");
    }

    free(sealedData);
}
