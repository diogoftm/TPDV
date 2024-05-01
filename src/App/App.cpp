/*
 * Copyright (C) 2011-2018 Intel Corporation. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 *   * Redistributions of source code must retain the above copyright
 *     notice, this list of conditions and the following disclaimer.
 *   * Redistributions in binary form must reproduce the above copyright
 *     notice, this list of conditions and the following disclaimer in
 *     the documentation and/or other materials provided with the
 *     distribution.
 *   * Neither the name of Intel Corporation nor the names of its
 *     contributors may be used to endorse or promote products derived
 *     from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 */

#include <time.h>
#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <errno.h>
#include <regex.h>
#include "AppSocket.h"
#include "sgx_urts.h"
#include "App.h"
#include "Enclave1_u.h"
#include <functional>

#define MAX_DATA_SIZE 256

/*
 * Error reporting
 */

typedef struct _sgx_errlist_t
{
  sgx_status_t error_number;
  const char *message;
} sgx_errlist_t;

static sgx_errlist_t sgx_errlist[] =
    {/* error list extracted from /opt/intel/sgxsdk/include/sgx_error.h */
     {SGX_SUCCESS, "All is well!"},
     {SGX_ERROR_UNEXPECTED, "Unexpected error"},
     {SGX_ERROR_INVALID_PARAMETER, "The parameter is incorrect"},
     {SGX_ERROR_OUT_OF_MEMORY, "Not enough memory is available to complete this operation"},
     {SGX_ERROR_ENCLAVE_LOST, "Enclave lost after power transition or used in child process created by linux:fork()"},
     {SGX_ERROR_INVALID_STATE, "SGX API is invoked in incorrect order or state"},
     {SGX_ERROR_FEATURE_NOT_SUPPORTED, "Feature is not supported on this platform"},
     {SGX_PTHREAD_EXIT, "Enclave is exited with pthread_exit()"},
     {SGX_ERROR_MEMORY_MAP_FAILURE, "Failed to reserve memory for the enclave"},
     {SGX_ERROR_INVALID_FUNCTION, "The ecall/ocall index is invalid"},
     {SGX_ERROR_OUT_OF_TCS, "The enclave is out of TCS"},
     {SGX_ERROR_ENCLAVE_CRASHED, "The enclave is crashed"},
     {SGX_ERROR_ECALL_NOT_ALLOWED, "The ECALL is not allowed at this time, e.g. ecall is blocked by the dynamic entry table, or nested ecall is not allowed during initialization"},
     {SGX_ERROR_OCALL_NOT_ALLOWED, "The OCALL is not allowed at this time, e.g. ocall is not allowed during exception handling"},
     {SGX_ERROR_STACK_OVERRUN, "The enclave is running out of stack"},
     {SGX_ERROR_UNDEFINED_SYMBOL, "The enclave image has undefined symbol"},
     {SGX_ERROR_INVALID_ENCLAVE, "The enclave image is not correct"},
     {SGX_ERROR_INVALID_ENCLAVE_ID, "The enclave id is invalid"},
     {SGX_ERROR_INVALID_SIGNATURE, "The signature is invalid"},
     {SGX_ERROR_NDEBUG_ENCLAVE, "The enclave is signed as product enclave, and can not be created as debuggable enclave"},
     {SGX_ERROR_OUT_OF_EPC, "Not enough EPC is available to load the enclave"},
     {SGX_ERROR_NO_DEVICE, "Can't open SGX device"},
     {SGX_ERROR_MEMORY_MAP_CONFLICT, "Page mapping failed in driver"},
     {SGX_ERROR_INVALID_METADATA, "The metadata is incorrect"},
     {SGX_ERROR_DEVICE_BUSY, "Device is busy, mostly EINIT failed"},
     {SGX_ERROR_INVALID_VERSION, "Metadata version is inconsistent between uRTS and sgx_sign or uRTS is incompatible with current platform"},
     {SGX_ERROR_MODE_INCOMPATIBLE, "The target enclave 32/64 bit mode or sim/hw mode is incompatible with the mode of current uRTS"},
     {SGX_ERROR_ENCLAVE_FILE_ACCESS, "Can't open enclave file"},
     {SGX_ERROR_INVALID_MISC, "The MiscSelct/MiscMask settings are not correct"},
     {SGX_ERROR_INVALID_LAUNCH_TOKEN, "The launch token is not correct"},
     {SGX_ERROR_MAC_MISMATCH, "Indicates verification error for reports, sealed datas, etc"},
     {SGX_ERROR_INVALID_ATTRIBUTE, "The enclave is not authorized, e.g., requesting invalid attribute or launch key access on legacy SGX platform without FLC"},
     {SGX_ERROR_INVALID_CPUSVN, "The cpu svn is beyond platform's cpu svn value"},
     {SGX_ERROR_INVALID_ISVSVN, "The isv svn is greater than the enclave's isv svn"},
     {SGX_ERROR_INVALID_KEYNAME, "The key name is an unsupported value"},
     {SGX_ERROR_SERVICE_UNAVAILABLE, "Indicates aesm didn't respond or the requested service is not supported"},
     {SGX_ERROR_SERVICE_TIMEOUT, "The request to aesm timed out"},
     {SGX_ERROR_AE_INVALID_EPIDBLOB, "Indicates epid blob verification error"},
     {SGX_ERROR_SERVICE_INVALID_PRIVILEGE, " Enclave not authorized to run, .e.g. provisioning enclave hosted in an app without access rights to /dev/sgx_provision"},
     {SGX_ERROR_EPID_MEMBER_REVOKED, "The EPID group membership is revoked"},
     {SGX_ERROR_UPDATE_NEEDED, "SGX needs to be updated"},
     {SGX_ERROR_NETWORK_FAILURE, "Network connecting or proxy setting issue is encountered"},
     {SGX_ERROR_AE_SESSION_INVALID, "Session is invalid or ended by server"},
     {SGX_ERROR_BUSY, "The requested service is temporarily not available"},
     {SGX_ERROR_MC_NOT_FOUND, "The Monotonic Counter doesn't exist or has been invalided"},
     {SGX_ERROR_MC_NO_ACCESS_RIGHT, "Caller doesn't have the access right to specified VMC"},
     {SGX_ERROR_MC_USED_UP, "Monotonic counters are used out"},
     {SGX_ERROR_MC_OVER_QUOTA, "Monotonic counters exceeds quota limitation"},
     {SGX_ERROR_KDF_MISMATCH, "Key derivation function doesn't match during key exchange"},
     {SGX_ERROR_UNRECOGNIZED_PLATFORM, "EPID Provisioning failed due to platform not recognized by backend server"},
     {SGX_ERROR_UNSUPPORTED_CONFIG, "The config for trigging EPID Provisiong or PSE Provisiong&LTP is invalid"},
     {SGX_ERROR_NO_PRIVILEGE, "Not enough privilege to perform the operation"},
     {SGX_ERROR_PCL_ENCRYPTED, "trying to encrypt an already encrypted enclave"},
     {SGX_ERROR_PCL_NOT_ENCRYPTED, "trying to load a plain enclave using sgx_create_encrypted_enclave"},
     {SGX_ERROR_PCL_MAC_MISMATCH, "section mac result does not match build time mac"},
     {SGX_ERROR_PCL_SHA_MISMATCH, "Unsealed key MAC does not match MAC of key hardcoded in enclave binary"},
     {SGX_ERROR_PCL_GUID_MISMATCH, "GUID in sealed blob does not match GUID hardcoded in enclave binary"},
     {SGX_ERROR_FILE_BAD_STATUS, "The file is in bad status, run sgx_clearerr to try and fix it"},
     {SGX_ERROR_FILE_NO_KEY_ID, "The Key ID field is all zeros, can't re-generate the encryption key"},
     {SGX_ERROR_FILE_NAME_MISMATCH, "The current file name is different then the original file name (not allowed, substitution attack)"},
     {SGX_ERROR_FILE_NOT_SGX_FILE, "The file is not an SGX file"},
     {SGX_ERROR_FILE_CANT_OPEN_RECOVERY_FILE, "A recovery file can't be opened, so flush operation can't continue (only used when no EXXX is returned)"},
     {SGX_ERROR_FILE_CANT_WRITE_RECOVERY_FILE, "A recovery file can't be written, so flush operation can't continue (only used when no EXXX is returned)"},
     {SGX_ERROR_FILE_RECOVERY_NEEDED, "When openeing the file, recovery is needed, but the recovery process failed"},
     {SGX_ERROR_FILE_FLUSH_FAILED, "fflush operation (to disk) failed (only used when no EXXX is returned)"},
     {SGX_ERROR_FILE_CLOSE_FAILED, "fclose operation (to disk) failed (only used when no EXXX is returned)"},
     {SGX_ERROR_UNSUPPORTED_ATT_KEY_ID, "platform quoting infrastructure does not support the key"},
     {SGX_ERROR_ATT_KEY_CERTIFICATION_FAILURE, "Failed to generate and certify the attestation key"},
     {SGX_ERROR_ATT_KEY_UNINITIALIZED, "The platform quoting infrastructure does not have the attestation key available to generate quote"},
     {SGX_ERROR_INVALID_ATT_KEY_CERT_DATA, "TThe data returned by the platform library's sgx_get_quote_config() is invalid"},
     {SGX_ERROR_PLATFORM_CERT_UNAVAILABLE, "The PCK Cert for the platform is not available"},
     {SGX_INTERNAL_ERROR_ENCLAVE_CREATE_INTERRUPTED, "The ioctl for enclave_create unexpectedly failed with EINTR"}};

void print_error_message(sgx_status_t ret, const char *sgx_function_name)
{
  size_t ttl = sizeof(sgx_errlist) / sizeof(sgx_errlist[0]);
  size_t idx;

  if (sgx_function_name != NULL)
    printf("Function: %s\n", sgx_function_name);
  for (idx = 0; idx < ttl; idx++)
  {
    if (ret == sgx_errlist[idx].error_number)
    {
      printf("Error: %s\n", sgx_errlist[idx].message);
      break;
    }
  }
  if (idx == ttl)
    printf("Error code is 0x%X. Please refer to the \"Intel SGX SDK Developer Reference\" for more details.\n", ret);
}

/*
 * Enclave1 stuff
 */

sgx_enclave_id_t global_eid1 = 0;

/*
 * ocalls
 */
void ocall_e1_print_string(const char *str)
{
  printf("%s", str);
}

void ocallSaveDataToFile(const char *data, int siz, const char *fileName)
{
  FILE *file = fopen(fileName, "w");

  if (file == NULL)
  {
    fprintf(stderr, "Error opening the file.\n");
    return;
  }

  size_t numBytesWritten = fwrite(data, sizeof(char), siz, file);

  fclose(file);
}

int ocallLoadSealedData(uint8_t *sealed_data, const char *fileName)
{
  FILE* file = fopen(fileName, "rb");
  if (file == NULL) {
    printf("Error opening file for reading.\n");
    return 0;
  }

  fseek(file, 0, SEEK_END);
  int file_size = ftell(file);
  fseek(file, 0, SEEK_SET);

  fread(sealed_data, 1, file_size, file);
  fclose(file);

  return file_size;
}

void ocallSaveSealedData(uint8_t* sealed_data, size_t sealed_size, const char *fileName) 
{
  FILE* file = fopen(fileName, "wb");
  if (file == NULL) {
    printf("Error opening file for writing.\n");
    return;
  }

  fwrite(sealed_data, 1, sealed_size, file);
  fclose(file);
}

/*
 * IO helpers
 */

int readStdin(char *value, int maxSize)
{
  if (fgets(value, maxSize, stdin) == NULL)
  {
    fprintf(stderr, "Error reading input.\n");
    return -1;
  }

  size_t len = strlen(value);
  if (len > 0 && value[len - 1] == '\n')
  {
    value[len - 1] = '\0';
  }

  fflush(stdin);

  return 0;
}

char *readFile(char *filename)
{
  FILE *file = fopen(filename, "r");
  if (file == NULL)
  {
    fprintf(stderr, "Error opening file.\n");
    return NULL;
  }

  fseek(file, 0, SEEK_END);
  long file_size = ftell(file);
  fseek(file, 0, SEEK_SET);

  char *buffer = (char *)malloc(file_size + 1);
  if (buffer == NULL)
  {
    fprintf(stderr, "Memory allocation failed.\n");
    fclose(file);
    return NULL;
  }

  size_t bytes_read = fread(buffer, 1, file_size, file);
  if (bytes_read != file_size)
  {
    fprintf(stderr, "Error reading file.\n");
    fclose(file);
    free(buffer);
    return NULL;
  }

  buffer[file_size] = '\0';

  fclose(file);
  return buffer;
}

void hexStringToCharArray(const char *hexString, char **output)
{
  size_t len = strlen(hexString);

  *output = (char *)malloc((len / 2) + 1);
  if (*output == NULL)
  {
    fprintf(stderr, "Memory allocation failed.\n");
    exit(1);
  }

  for (size_t i = 0; i < len; i += 2)
  {
    sscanf(hexString + i, "%2hhx", *output + i / 2);
  }

  (*output)[len / 2] = '\0';
}

/*
 * Handlers
 */

int initialize_enclave1(void)
{
  sgx_status_t ret;
  sgx_launch_token_t token = {0};

  if ((ret = sgx_create_enclave(ENCLAVE1_FILENAME, SGX_DEBUG_FLAG, &token, NULL, &global_eid1, NULL)) != SGX_SUCCESS)
  {
    print_error_message(ret, "sgx_create_enclave");
    return -1;
  }
  return 0;
}

void handleKillEnclaveAndExit()
{
  sgx_status_t ret;
  if ((ret = sgx_destroy_enclave(global_eid1)) != SGX_SUCCESS)
  {
    print_error_message(ret, "sgx_destroy_enclave");
    exit(0);
  }
  else
    exit(1);
}

void handleCreateVault(char *vaultName, char *password, char *author)
{
  int returnVal;
  ecallCreateVault(global_eid1, &returnVal, vaultName, password, author);
}

void handleChangePassword()
{
  int ret_val;

  char buffer[128];

  printf("New password: ");

  readStdin(buffer, 32);

  int len = strlen(buffer);

  ecallChangePassword(global_eid1, &ret_val, buffer, len);
}

void handleSaveAsset()
{
  sgx_status_t ret;
  int ret_val;
  char assetName[32];
  char fileName[32];

  printf("Asset name: ");
  readStdin(assetName, 32);
  printf("File name: ");
  readStdin(fileName, 32);
  if ((ret = ecallSaveAssetToFile(global_eid1, &ret_val, assetName, fileName)) != SGX_SUCCESS)
  {
    print_error_message(ret, "ecallSaveAssetToFile");
    handleKillEnclaveAndExit();
  }
  if (ret != 0)
  {
    printf("Error: invalid asset");
    return;
  }
}

void handleAddAssetFromKeyboard()
{
  sgx_status_t ret;
  int ret_val;
  char assetName[32];
  char content[256];

  printf("Asset name: ");
  readStdin(assetName, 32);
  printf("Asset content: ");
  readStdin(content, 256);

  ecallInsertAsset(global_eid1, &ret_val, assetName, strlen(assetName) + 1, content, strlen(content));
}

void handleAddAssetFromFile()
{
  sgx_status_t ret;
  int ret_val;
  char fileName[32];
  char assetName[32];
  char *fileContent;

  printf("File name: ");
  readStdin(fileName, 32);
  fileContent = readFile(fileName);

  if (fileContent == NULL)
  {
    printf("Error: Invalid file\n");
    return;
  }

  printf("Asset name: ");
  readStdin(assetName, 32);

  if (strlen(assetName) == 0)
  {
    printf("Error: Asset name cannot be empty\n");
    return;
  }

  if ((ret = ecallInsertAsset(global_eid1, &ret_val, assetName, strlen(assetName) + 1, fileContent, strlen(fileContent) + 1)) != SGX_SUCCESS)
  {
    print_error_message(ret, "ecallInsertAsset");
    handleKillEnclaveAndExit();
  }
}

void handleListAssets()
{
  sgx_status_t ret;
  int ret_val;

  if ((ret = ecallListAssets(global_eid1, &ret_val)) != SGX_SUCCESS)
  {
    print_error_message(ret, "ecallListAsset");
    handleKillEnclaveAndExit();
  }
}

void handlePrintAsset()
{
  sgx_status_t ret;
  int ret_val;
  char assetName[32];

  printf("Asset name: ");
  readStdin(assetName, 32);
  if ((ret = ecallPrintAsset(global_eid1, &ret_val, assetName)) != SGX_SUCCESS)
  {
    print_error_message(ret, "ecallGetAsset");
    handleKillEnclaveAndExit();
  }
  if (ret_val != 0)
  {
    printf("Error: invalid asset\n");
    return;
  }
}

void handleCompareHash()
{
  char assetName[32];
  char hashHex[72];
  char *hash;
  sgx_status_t ret;
  char ret_val;

  printf("Asset name: ");
  readStdin(assetName, 32);

  printf("Asset hash (sha256): ");
  readStdin(hashHex, 128);

  hexStringToCharArray(hashHex, &hash);

  if ((ret = ecallCheckDigest(global_eid1, &ret_val, assetName, hash)) != SGX_SUCCESS)
  {
    print_error_message(ret, "ecallGetAsset");
    handleKillEnclaveAndExit();
  }

  if (ret_val == -2)
    printf("Error: invalid asset\n");
  else if (ret_val == 0)
    printf("The hashes are equal\n");
  else
    printf("The hashes don't match\n");
}

/*
 * Application
 */

int SGX_CDECL main(int argc, char *argv[])
{
  char vaultName[32];
  char input[100];
  sgx_status_t ret;

  if (initialize_enclave1() < 0)
    return 1;


  int option;

  while (1)
  {
    printf("Do you want to open or create a vault?\n1 - Open\n2 - Create\n3 - Close\n>> ");
    fflush(stdin);
    if (fgets(input, sizeof(input), stdin) != NULL)
    {
      if (strcmp(input, "\n") == 0)
      {
        printf(">> ");
      }
      else
      {
        char* endptr;
        errno = 0;
        option = strtol(input, &endptr, 10);

          if (errno != 0 || input == endptr || option < 1 || option > 3) {
            printf("Error: invalid option\n");
            continue;
          }
        break;
      }
    }
  }

  if (option == 1)
  {
    int returnVal = 1;
    char password[128];

    printf("Vault name: ");
    readStdin(vaultName, 32);

    printf("Password: ");
    readStdin(password, 32);

    if ((ret = ecallOpenVault(global_eid1, &returnVal, vaultName, strlen(vaultName), password, strlen(password))) != SGX_SUCCESS)
    {
      print_error_message(ret, "Ups! Something went wrong...");
      return 1;
    }
    if (returnVal == 0)
      printf("Info: The vault was successfully opened!\n");

    return 0;
}

int handleCreateVaultOption(char* vaultName) {
    int returnVal = 1;
    char password[128];
    char ownerName[64];

    printf("Vault name: ");
    readStdin(vaultName, 32);

    printf("Owner name: ");
    readStdin(ownerName, 64);

    printf("Password: ");
    readStdin(password, 128);

    handleCreateVault(vaultName, password, ownerName);

    return 0;
}

int validIpv4Address(char* ip) {
  regex_t regex;
  int value;

  value = regcomp(&regex, 
         "([0-9]+)[.]([0-9]+)[.]([0-9]+)[.]([0-9]+)", REG_EXTENDED);

  if(value != 0)
    return -1;

  int patternMatch = regexec(&regex, ip, 0, NULL, 0);

  if(patternMatch == 0)
    return 0;
  
  regfree(&regex);

  return -2;
}

bool stringToInteger(char* str, int* value) {
        char* endptr;
        errno = 0;
        int _value = strtol(str, &endptr, 10);
          
        if (errno != 0 || str == endptr) {
            return false;
        }

        *value = _value;
        return true;
}

int serveClientCallback(SSL* ssl) {

  uint8_t* message;
  int mlen;
  BaseMessageLayer::receive_message(ssl, &message, mlen);

  if(strcmp((char*)message, "REQUEST_CLONE") != 0) {
    fprintf(stdout, "Unexpected operation from client\n");
    fprintf(stdout, "Message received: %s\n", (char*)message);
    SSL_shutdown(ssl);
    return 0;
  }
  
  printf("Received REQUEST_CLONE from client\n");

  // Obtain sealed data
  


  return 0;
}

int clientConnectionWithServerCallback(SSL* ssl) {
  const char* requestMessage = "REQUEST_CLONE";


  printf("Sending REQUEST_CLONE to server\n");
  BaseMessageLayer::send_message(ssl, (uint8_t*)requestMessage, strlen(requestMessage) + 1);



  return 0;
  
}

int handleServeVaultCloneOption() {

  char port[32];
  
  printf("Server Port: ");
  readStdin(port, 32);

  int _port = 0;

  if(stringToInteger(port, &_port) == false ||_port <= 0 || _port > 65535) {
    fprintf(stderr, "Invalid port received\n");
    return -1;
  }

  TlsServer::TlsServerConfig config;
  config.rootCA = "./certs/root.crt";
  config.myCertificate = "./certs/client_1.crt";
  config.myPrivateKey = "./certs/client_1.key";
  
  std::function<int(SSL*)> callback = std::function<int(SSL*)>(serveClientCallback);

  if( TlsServer::run_server(_port, config, callback) != 0) {
    fprintf(stderr, "An error ocurred while running TLS server\n");
    return -1;
  }
  
  return 0;

}

int handleLoadRemoteVaultOption() {

  char ip[64];
  char port[32];
  int status;

  printf("Server IP: ");
  readStdin(ip, sizeof(ip));

  status = validIpv4Address(ip);

  if(status != 0) {
    fprintf(stderr, "Invalid Ipv4 address\n");
    return -1;
  }

  printf("Server Port: ");
  readStdin(port, sizeof(port));

  int _port = 0;
  bool cvtStatus = stringToInteger(port, &_port);

  if(cvtStatus == false) {
    fprintf(stderr, "Invalid port\n");
    return -1;
  }


  TlsClient::TlsClientConfig config;
  config.rootCA = "./certs/root.crt";
  config.serverIP = ip;
  config.serverPort = _port;

  std::function<int(SSL*)> callback = std::function<int(SSL*)>(clientConnectionWithServerCallback);

  if (TlsClient::connect(config, callback) != 0) {
    fprintf(stderr, "Error while connecting with server\n");
    return -1;
  }

  return 0;
  
}

int handleStartOptions(int option, char* vaultName, char* input) {
  switch(option) {
    case 1: return handleOpenVaultOption(vaultName, input) != 0 ? -1 : 0;
    case 2: return handleCreateVaultOption(vaultName) != 0 ? -1 : 0;
    case 3: return 0;
    case 4: return handleLoadRemoteVaultOption() != 0 ? -1 : -1;
    default: return 0;
  }

  
}


int SGX_CDECL main(int argc, char *argv[])
{
  char vaultName[32];
  char input[100];
  sgx_status_t ret;

  if (initialize_enclave1() < 0)
    return 1;


  int option;

  while (1)
  {
    printf("Choose an option:\n1 - Open\n2 - Create\n3 - Close\n4 - Load remote vault\n>> ");
    fflush(stdin);
    if (fgets(input, sizeof(input), stdin) != NULL)
    {
      if (strcmp(input, "\n") == 0)
      {
        printf(">> ");
      }
      else
      {
        char* endptr;
        
        int option = 0;
        if(stringToInteger(input, &option) == false || option < 1 || option > 4) {
            fprintf(stderr, "Error: invalid option\n");
            continue;
        }
        
        if(option == 3) {
              handleKillEnclaveAndExit();
        } else {
          if(handleStartOptions(option, vaultName, input) == 0)
            break;
        }
          }
        
    }

  }


  while (1)
  {
    printf("Menu:\n -1 - Exit\n  1 - Add asset from keyboard\n  2 - Add asset from file\n  3 - List assets \
          \n  4 - Print asset\n  5 - Save asset to file\n  6 - Compare file digest\n  7 - Change password\n  8 - Allow remote vault clone\n");

    while (1)
    {
      printf("[%s] >> ", vaultName);
      fflush(stdin);
      if (fgets(input, sizeof(input), stdin) != NULL)
      {
        if (strcmp(input, "\n") == 0)
        {
          continue;
        }
        else
        {
          errno = 0;
          char* endptr;
          option = strtol(input, &endptr, 10);

          if (errno != 0 || input == endptr) {
            printf("Error: invalid option\n");
            continue;
          }
          break;
        }
      }
    }

    switch (option)
    {
    case -1:
      handleKillEnclaveAndExit();
      break;
    case 1:
      handleAddAssetFromKeyboard();
      break;
    case 2:
      handleAddAssetFromFile();
      break;
    case 3:
      handleListAssets();
      break;
    case 4:
      handlePrintAsset();
      break;
    case 5:
      handleSaveAsset();
      break;
    case 6:
      handleCompareHash();
      break;
    case 7:
      handleChangePassword();
      break;

    case 8:
      handleServeVaultCloneOption();
      break;
    default:
      printf("Error: invalid option\n");
    }
  }
}
