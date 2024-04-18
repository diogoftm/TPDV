#ifndef _VAULT_H_
#define _VAULT_H_

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
    char nonce[32];
    char name[32];
    char password[32];
    int numberOfFiles;
};

struct VaultAsset
{
    char hash[32];
    char name[32];
    int size;
    char *content;
    VaultAsset *next;
    VaultAsset *previous;
};

struct Vault
{
    VaultHeader *header;
    VaultAsset *asset;
    VaultState state;
};

VaultState getState(Vault* vault);
void createVault(Vault *vault);
void createVaultAsset(VaultAsset *vaultAsset, char *name);
void createVaultHeader(VaultHeader *vaultHeader, char *name, char *password);
int copyWithoutNeighborsDeeply(VaultAsset *src, VaultAsset *dst);
int pushAsset(Vault *vault, VaultAsset *asset);
int changePassword(Vault *vault, char *newPswd);
int fetchAsset(Vault *vault, char name[32], VaultAsset *asset);
int loadVault(Vault *vault, const char *data, char *pw);
int destroyVault(Vault *vault);



#if defined(__cplusplus)
}
#endif

#endif /* !_ENCLAVE1_H_ */
