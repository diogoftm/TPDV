
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


VaultState getState(Vault *vault) { return vault->state; }

void setupVault(Vault *vault)
{
    vault->state = NOT_YET_PARSED;
    vault->header = NULL;
    vault->asset = NULL;
}

int setupVaultAsset(VaultAsset *vaultAsset, char *name, unsigned char* content, size_t contentSize)
{
    size_t nameSize = strlen(name) + 1;

    if(nameSize > 32)
        return -1;
    
    memcpy(vaultAsset->name, name, nameSize * sizeof(char));

    sgx_sha256_msg(vaultAsset->content, (uint32_t)contentSize, vaultAsset->hash);
    
    vaultAsset->size = contentSize;

    vaultAsset->content = (unsigned char*)malloc(contentSize * sizeof(unsigned char));
    memcpy(vaultAsset->content, content, contentSize * sizeof(unsigned char));

    vaultAsset->next = NULL;
    vaultAsset->previous = NULL;
}

void createVaultHeader(VaultHeader *vaultHeader, char *name, char *password)
{
    memcpy(vaultHeader->name, name, sizeof(vaultHeader->name));
    memcpy(vaultHeader->nonce, "", sizeof(vaultHeader->nonce)); // TODO: mudar para colocar um numero random
    memcpy(vaultHeader->password, password, sizeof(vaultHeader->password));
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
    // TODO: check if it's possible to throw exceptions inside enclave (maybe send errors to unsafe world such as printf)
    if (getState(vault) != VALID)
    {
        return -1;
    }
    // TODO: make a copy of the asset and store in Vault::asset

    return 1;
}

int changePassword(Vault *vault, char *newPswd)
{
    memcpy(vault->header->password, newPswd, sizeof(vault->header->password));
    return 1;
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

int loadVault(Vault *vault, const char *data, char *pw)
{
    // TODO: if hash fails set corrupted State
    // ...

    vault->state = VALID;

    return 0;
}

int destroyVault(Vault *vault)
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
