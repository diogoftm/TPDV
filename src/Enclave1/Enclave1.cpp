#include <stdlib.h>
#include <assert.h>
#include <string.h>
#include <stdarg.h>
#include <stdio.h>

#include "Enclave1.h"
#include "Enclave1_t.h"

VaultState getState(Vault* vault) { return vault->state; }

void enclavePrintf(const char *fmt, ...){
    char buf[BUFSIZ] = { '\0' };
    va_list ap;

    va_start(ap, fmt);
    (void)vsnprintf(buf,BUFSIZ,fmt, ap);
    va_end(ap);
    ocall_e1_print_string(buf);

}

void printOptions(){
    enclavePrintf("Hello from enclave 1\n");
}

void createVault(Vault* vault)
{
    vault->state = NOT_YET_PARSED;
    vault->header = NULL;
    vault->asset = NULL;
}

void createVaultAsset(VaultAsset* vaultAsset, char* name)
{
    memcpy(vaultAsset->name, name, sizeof(vaultAsset->name));
    memcpy(vaultAsset->hash, "", sizeof(vaultAsset->name));
    vaultAsset->size = 0;
    vaultAsset->content = NULL;
    vaultAsset->next = NULL;
    vaultAsset->previous = NULL;
}

void createVaultHeader(VaultHeader* vaultHeader, char* name, char* password)
{
    memcpy(vaultHeader->name, name, sizeof(vaultHeader->name));
    memcpy(vaultHeader->nonce, "", sizeof(vaultHeader->nonce)); // mudar para colocar um numero random
    memcpy(vaultHeader->password, password, sizeof(vaultHeader->password));
    vaultHeader->numberOfFiles = 0;
}

int copyWithoutNeighborsDeeply(VaultAsset* src, VaultAsset* dst) {
    if(src == NULL || dst == NULL)
        return -1;

    memcpy(dst->hash, src->hash, sizeof(src->hash));
    memcpy(dst->name, src->name, sizeof(src->name));

    dst->size = src->size;

    if(src->content != NULL) {
        dst->content = (char*) malloc(sizeof(char) * src->size);
        memcpy(dst->content, src->content, src->size);
    } else {
        dst->content = NULL;
    }

    dst->next = NULL;
    dst->previous = NULL;

    return 0;
}


int pushAsset(Vault* vault, VaultAsset *asset)
{
    // check if it's possible to throw exceptions inside enclave (maybe send errors to unsafe world such as printf)
    if (getState(vault) != VALID)
    {
        return -1;
    }
    // make a copy of the asset and store in Vault::asset

    return 1;
}

int changePassword(Vault* vault, char* newPswd) {
    memcpy(vault->header->password, newPswd, sizeof(vault->header->password));
    return 1;
}

int fetchAsset(Vault* vault, char name[32], VaultAsset* asset) {
    if(getState(vault) != VALID)
        return -1;

    VaultAsset* curr = vault->asset;
    while(curr != NULL) {
        if(strcmp(name, curr->name) == 0) {
            copyWithoutNeighborsDeeply(curr, asset);
            return 0;
        }
        curr = curr->next;
    }

    return -2;
}

int loadVault(Vault *vault, const char *data, char* pw)
{
    // if hash fails set corrupted State
    // ...

    vault->state = VALID;

    return 0;
}

int destroyVault(Vault *vault)
{
    if(vault->state == NOT_YET_PARSED)
        return 1;

    free(vault->header);
    VaultAsset* curr = vault->asset;
    VaultAsset* next;
    while(curr != NULL) {
        if(curr->content) {
            free(curr->content);
            curr->content = NULL;
        }
        next = curr->next;
        free(curr);
        curr = next;
    }

    return 1;
}