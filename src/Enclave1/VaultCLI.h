#pragma once

#include "Vault.h"

// Define CLI interaction here
class VaultCLI
{
public:
    VaultCLI();

    // TODO: Connect with enclave printf functions
    void printOptions();

    void loadVault();
    void extractAsset();
    void extractAllAssets();
    void compareDigest();
    void createVault();
    void changePassword();
    void listAssets();

private:
    Vault vault;
};