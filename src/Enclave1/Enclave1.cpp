#include <stdlib.h>
#include <assert.h>
#include <string.h>
#include <stdarg.h>
#include <stdio.h>

#include "sgx_tcrypto.h"
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
    setupVault(_vault);

    int status = loadVault(fileName);

    if (status == 1 || strcmp(_vault->header.password, psw) != 0)
        return 1;

    return 0;
}

int ecallInsertAsset(const char *assetName, size_t assetNameSize, const uint8_t *assetData, int assetDataSize)
{
    int err = 0;
    VaultAsset *newAsset = (VaultAsset *)malloc(sizeof(VaultAsset));
    setupVaultAsset(newAsset, (char *)assetName, assetDataSize, (unsigned char *)assetData);
    err = pushAsset(_vault, newAsset);
    if (err != 0)
    {

        if (err == -1)
        {
            enclavePrintf("Unable to insert asset, vault is not in a valid state\n");
        }
        else if (err == -2)
        {
            enclavePrintf("Unable to insert asset, asset name is repeated\n");
        }

        return -1;
    }

    saveVault();

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

    saveVault();

    return 0;
}

// we need to had the clone feature, but lets forget that for now

/*
 * Sealing methods
 */

void saveVault()
{
    int totalAssetsSize = 0;
    VaultAsset *node = _vault->asset;
    while (node != NULL)
    {
        totalAssetsSize += 32 + sizeof(node->name) + sizeof(node->size) + node->size + sizeof(node->hash);
        node = node->next;
    }

    char *data = (char *)malloc(sizeof(VaultHeader) + totalAssetsSize);
    if (data == NULL)
    {
        enclavePrintf("Error: Memory allocation failed.\n");
        return;
    }

    memcpy(data, (char *)&_vault->header, sizeof(VaultHeader));

    size_t offset = sizeof(VaultHeader);
    node = _vault->asset;
    while (node != NULL)
    {
        size_t assetSize = 32 + sizeof(node->name) + sizeof(node->size) + node->size + sizeof(node->hash); // TESTING: Saving hash

        memcpy(data + offset, node->hash, 32);
        memcpy(data + offset + 32, node->name, sizeof(node->name));
        memcpy(data + offset + 32 + sizeof(node->name), &node->size, sizeof(node->size));

        memcpy(data + offset + 32 + sizeof(node->name) + sizeof(node->size), &node->hash, sizeof(node->hash)); // TESTING: Saving hash
        memcpy(data + offset + 32 + sizeof(node->name) + sizeof(node->size) + sizeof(node->hash), node->content, node->size);

        offset += assetSize;
        node = node->next;
    }

    sgx_status_t ret;
    sgx_sealed_data_t *sealed_data = NULL;
    size_t sealed_size = sizeof(sgx_sealed_data_t) + sizeof(VaultHeader) + totalAssetsSize;
    sealed_data = (sgx_sealed_data_t *)malloc(sealed_size);
    if (sealed_data == NULL)
    {
        enclavePrintf("Error: Memory allocation failed.\n");
        free(data);
        return;
    }

    ret = sgx_seal_data(0, NULL, sizeof(VaultHeader) + totalAssetsSize, (uint8_t *)data, sealed_size, sealed_data);
    if (ret != SGX_SUCCESS)
    {
        enclavePrintf("Error: Sealing failed (%#x).\n", ret);
        free(data);
        free(sealed_data);
        return;
    }

    ocallSaveSealedData((uint8_t *)sealed_data, sealed_size, _vault->header.name);

    free(sealed_data);
}

int loadVault(const char *fileName)
{
    sgx_status_t ret = SGX_ERROR_UNEXPECTED;
    int sealed_size;

    // This size can be considered de maximum size of the vault
    sgx_sealed_data_t *sealed_data = (sgx_sealed_data_t *)malloc(1024 * 16);
    char *unsealed_data = (char *)malloc(1024 * 16);

    ocallLoadSealedData(&sealed_size, (uint8_t *)sealed_data, fileName);
    if (!sealed_data)
    {
        return 1;
    }

    ret = sgx_unseal_data(sealed_data, NULL, NULL, (uint8_t *)unsealed_data, (uint32_t *)&sealed_size);
    if (ret != SGX_SUCCESS)
    {
        enclavePrintf("Error: Unsealing failed\n");
        return 1;
    }

    setupVaultHeader(&_vault->header, &unsealed_data[32], &unsealed_data[64], &unsealed_data[96]);

    enclavePrintf("Loading assets...\n");
    int i = sizeof(VaultHeader);
    while (i < sealed_size)
    {
        VaultAsset *newAsset = (VaultAsset *)malloc(sizeof(VaultAsset));

        // TODO: extract hash

        setupVaultAsset(newAsset, &unsealed_data[i + 32], unsealed_data[i + 64], (unsigned char *)&unsealed_data[i + 100]);
        // TODO: Comparing hash
        // ---
        pushAsset(_vault, newAsset);
        i += 68 + newAsset->size;
    }

    return 0;
}
