#pragma once

struct VaultHeader {
    char nonce[32];
    char name[32];
    char password[32];
    int  numberOfFiles;

};

struct VaultAsset {
    char hash[32];
    char name[32];
    int size;
    char* content = nullptr;

    //these two pointers will help navigating between assets
    VaultAsset* next = nullptr;
    VaultAsset* previous = nullptr;
};

enum class VaultState {
    NOT_YET_PARSED,
    VALID,
    CORRUPTED
};

struct Vault {
    VaultHeader* header = nullptr;
    VaultAsset* asset = nullptr;
    VaultState state = VaultState::NOT_YET_PARSED;


    Vault() {
        this->header = new VaultHeader();
    }

    ~Vault() {
        delete this->header;
    }

    void pushAsset(VaultAsset& asset) {
        //make a copy of the asset and store in Vault::asset safely
    }
};


// Define CLI interaction here 
class VaultCLI {
    public:

        VaultCLI();

        //TODO: Connect with enclave print functions 
        void printOptions();

        void loadVault();
        void extractAsset();
        void extractAllAssets();
        void compareDigest();
        void createVault();
        void changePassword();

    private:

        Vault vault;
};