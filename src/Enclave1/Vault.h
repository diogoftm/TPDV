#ifndef _VAULT_H_
#define _VAULT_H_

#include <stdlib.h>
#include "sgx_tcrypto.h"


#if defined(__cplusplus)
extern "C" {
#endif

enum VaultState
{
    NOT_YET_PARSED = 0,
    VALID = 1,
    CORRUPTED = 2
};

struct VaultHeader
{
    unsigned char nonce[32];
    char name[32];
    char password[32];
    char author[64];
    int numberOfFiles;
};


struct VaultAsset
{
    sgx_sha256_hash_t hash[SGX_SHA256_HASH_SIZE];
    char name[32];
    int size;
    unsigned char *content;
    VaultAsset *next;
    VaultAsset *previous;
};

struct Vault
{
    VaultHeader header;
    VaultAsset *asset;
    VaultState state;
};

VaultState getState(Vault* vault);
void setupVault(Vault *vault);
int setupVaultAsset(VaultAsset *vaultAsset, char *name, size_t contentSize, unsigned char *content);
void setupVaultHeader(VaultHeader *vaultHeader, char *name, char *password, char *author);
int copyWithoutNeighborsDeeply(VaultAsset *src, VaultAsset *dst);
int pushAsset(Vault *vault, VaultAsset *asset);
int changePassword(Vault *vault, char *newPswd);
int fetchAsset(Vault *vault, char name[32], VaultAsset *asset);
int destroyVault(Vault *vault);
int findPasswordHash(char* psw, sgx_sha256_hash_t* dst);

#if defined(__cplusplus)
}
#endif

#endif /* !_ENCLAVE1_H_ */
