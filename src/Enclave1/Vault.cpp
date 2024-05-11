
// we need to had the clone feature, but lets forget that for now

/*
 * Internal methods
 */

#include "Vault.h"

#include <stdlib.h>
#include <assert.h>
#include <string.h>
#include <stdarg.h>
#include <stdio.h>
#include <sgx_trts.h>

VaultState getState(Vault *vault) { return vault->state; }

void setupVault(Vault *vault)
{
    vault->state = VALID;
    vault->asset = NULL;
}

int setupVaultAsset(VaultAsset *vaultAsset, char *name, size_t contentSize, unsigned char *content)
{
    size_t nameSize = strlen(name) + 1;

    if (nameSize > 32)
        return -1;

    memcpy(vaultAsset->name, name, nameSize * sizeof(char));

    vaultAsset->size = contentSize;

    vaultAsset->content = (unsigned char *)malloc(contentSize * sizeof(unsigned char));
    memcpy(vaultAsset->content, content, contentSize * sizeof(unsigned char));

    sgx_sha256_msg(vaultAsset->content, (uint32_t)contentSize - 1, vaultAsset->hash);

    vaultAsset->next = NULL;
    vaultAsset->previous = NULL;

    return 0;
}

void setupVaultHeader(VaultHeader *vaultHeader, char *name, char *password, char *author)
{
    memcpy(vaultHeader->name, name, sizeof(vaultHeader->name));
    sgx_read_rand(vaultHeader->nonce, sizeof(vaultHeader->nonce));
    memcpy(vaultHeader->password, password, sizeof(vaultHeader->password));
    memcpy(vaultHeader->author, author, sizeof(vaultHeader->author));
    vaultHeader->numberOfFiles = 0;
}

int copyWithoutNeighborsDeeply(VaultAsset *src, VaultAsset *dst)
{
    if (src == NULL || dst == NULL)
        return -1;

    memcpy(dst->hash, src->hash, sizeof(src->hash));
    memcpy(dst->name, src->name, sizeof(src->name));

    dst->size = src->size;

    if (src->content != NULL)
    {
        dst->content = (unsigned char *)malloc(sizeof(unsigned char) * src->size);
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

int pushAsset(Vault *vault, VaultAsset *asset)
{
    if (getState(vault) != VALID)
        return -1;

    VaultAsset *currentAsset = vault->asset;

    if (currentAsset == NULL)
    {
        vault->asset = asset;
        return 0;
    }

    while (currentAsset->next != NULL)
    {
        if (strcmp(currentAsset->name, asset->name) == 0) // prevent equal file names
            return -2;

        currentAsset = currentAsset->next;
    }

    if (strcmp(currentAsset->name, asset->name) == 0)
        return -2;

    currentAsset->next = asset;
    asset->previous = currentAsset;

    vault->header.numberOfFiles += 1;

    return 0;
}

int changePassword(Vault *vault, char *newPswd)
{
    memcpy(vault->header.password, newPswd, sizeof(vault->header.password));
    return 0;
}

int fetchAsset(Vault *vault, char name[32], VaultAsset *asset)
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

int destroyVault(Vault *vault)
{
    if (vault->state == NOT_YET_PARSED)
        return 1;

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

int findPasswordHash(char* psw, sgx_sha256_hash_t* dst) {
    int len = strlen(psw);
    sgx_sha256_msg((uint8_t*)psw, len, dst);
    return len;
}