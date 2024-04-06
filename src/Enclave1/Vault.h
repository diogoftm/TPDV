#pragma once

#include "VaultState.h"
#include <string.h>
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
    char *content = nullptr; // for large vaults content may be loaded / unloaded in runtime to avoid an excess of ram usage (not a priority right now)
    // these two pointers will help navigating between assets
    VaultAsset *next = nullptr;
    VaultAsset *previous = nullptr;

    static int copyWithoutNeighborsDeeply(VaultAsset* src, VaultAsset* dst) {
        if(src == nullptr || dst == nullptr)
            return -1;

        memcpy(dst->hash, src->hash, sizeof(src->hash));
        memcpy(dst->name, src->name, sizeof(src->name));

        dst->size = src->size;

        if(src->content != nullptr) {
            dst->content = new char[src->size];
            memcpy(dst->content, src->content, src->size);
        } else {
            dst->content = nullptr;
        }

        dst->next = nullptr;
        dst->previous = nullptr;
    }
};

struct Vault
{
    VaultHeader *header = nullptr;
    VaultAsset *asset = nullptr;

    Vault()
    {
        this->state = VaultState::NOT_YET_PARSED;
    }

    void setupEmptyVault()
    {
        this->header = new VaultHeader();
        // ...
        this->state = VaultState::VALID;
    }

    int loadVault(const char *data, char* pw)
    {
        // if hash fails set corrupted State

        this->state = VaultState::VALID;
    }

    ~Vault()
    {
        if(this->state == VaultState::NOT_YET_PARSED)
            return;

        delete this->header;
        VaultAsset* curr = this->asset;
        VaultAsset* next;
        while(curr != nullptr) {
            if(curr->content) {
                delete curr->content;
                curr->content = nullptr;
            }
            next = curr->next;
            delete curr;
            curr = next;
        }
    }

    int pushAsset(VaultAsset &asset)
    {

        // check if it's possible to throw exceptions inside enclave (maybe send errors to unsafe world such as printf)
        if (this->getState() != VaultState::VALID)
        {
            return -1;
        }
        // make a copy of the asset and store in Vault::asset
    }

    int changePassword() {

    }

    int fetchAsset(char name[32], VaultAsset* asset) {
        if(this->getState() != VaultState::VALID)
            return -1;

        VaultAsset* curr = this->asset;
        while(curr != nullptr) {
            if(strcmp(name, curr->name) == 0) {
                VaultAsset::copyWithoutNeighborsDeeply(curr, asset);
                return 0;
            }
            curr = curr->next;
        }

        return -2;
    }

    VaultState getState() { return this->state; }

private:
    VaultState state = VaultState::NOT_YET_PARSED;
};