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

int ecallCreateVault(const char *vaultName, const char *psw, const char *author)
{
    _vault = (Vault *)malloc(sizeof(Vault));
    setupVault(_vault);

    setupVaultHeader(&_vault->header, (char *)vaultName, (char *)psw, (char *)author);

    enclavePrintf("Vault created successfully\n");

    saveVault();

    return 0;
}

int ecallOpenVault(const char *fileName, const char *psw)
{
    _vault = (Vault *)malloc(sizeof(Vault));

    int status = loadVault();

    if (status == 1 || strcmp(_vault->header.password, psw) != 0)
        return 1;
    
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

    loadVault();

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
 * Sealing methods
 */

void saveVault()
{
    sgx_status_t ret = SGX_ERROR_UNEXPECTED;
    sgx_sealed_data_t* sealed_data = NULL;
    size_t sealed_size = 0;
    char *input_string = (char*)&_vault->header;

    sealed_size = sizeof(sgx_sealed_data_t) + sizeof(VaultHeader);
    sealed_data = (sgx_sealed_data_t*)malloc(sealed_size);
    if (!sealed_data) {
        enclavePrintf("error 1\n");
        return;
    }

    ret = sgx_seal_data(0, NULL, sizeof(VaultHeader), (uint8_t*)input_string, sealed_size, sealed_data);
    if (ret != SGX_SUCCESS) {
        free(sealed_data);
        enclavePrintf("error 2\n");
        return;
    }

    ocallSaveSealedData((uint8_t*)sealed_data, sealed_size, "vault.dat");

    free(sealed_data);
}

int loadVault()
{
    sgx_status_t ret = SGX_ERROR_UNEXPECTED;
    size_t sealed_size = sizeof(sgx_sealed_data_t) + sizeof(VaultHeader);
    sgx_sealed_data_t* sealed_data = (sgx_sealed_data_t*)malloc(sealed_size);
    VaultHeader* unsealed_data = (VaultHeader*) malloc(sizeof(VaultHeader));

    ocallLoadSealedData((uint8_t*)sealed_data, &sealed_size, "vault.dat");
    if (!sealed_data) {
        return 1;
    }

    ret = sgx_unseal_data(sealed_data, NULL, NULL, (uint8_t*)unsealed_data, (uint32_t*) &sealed_size);
    if (ret != SGX_SUCCESS) {
        enclavePrintf("ups!");
        return 1;
    }

    _vault->header = *unsealed_data;
    _vault->state = VALID;

    return 0;
}
