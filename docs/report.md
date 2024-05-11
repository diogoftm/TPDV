---
geometry: margin=25mm
title: Suspicious Deb package - Analysis
author: Tiago Silvestre - tiago.silvestre@ua.pt, Diogo Matos - dftm@ua.pt, David Araujo - davidaraujo@ua.pt
date: May 12, 2024
---

# Table of Contents
- [Table of Contents](#table-of-contents)
- [Introduction](#introduction)
- [Overall structure](#overall-structure)
- [Features and tests](#features-and-tests)
  - [Insert assets](#insert-assets)
  - [List assets](#list-assets)
  - [Print assets](#print-assets)
  - [Export assets](#export-assets)
  - [Compare assets hash](#compare-assets-hash)
  - [Seal and unseal](#seal-and-unseal)
  - [Clone vault](#clone-vault)
- [Conclusions](#conclusions)


# Introduction
The goal of this project is to implement a "tamper-proof digital vault" (TPDV) taking advantage of Intel's SGX enclaves. The TPDV stores digital assets and will be write once, without any possibility of deleting information. A malicious operator may destroy the entire TPDV, but it may not change anything already stored in it without that being detected.

In this report we provide a brief overview of our implementation of the TPDV and show the results of some tests performed when suited. We start out by presenting the [overall structure](#overall-structure) of the system, then we go [feature by feature](#features-and-tests) providing some insight into how they work. In the end, we sum everything in the [conclusions](#conclusions).

# Overall structure
```mermaid
sequenceDiagram
    App->>Enclave: Perform secure operation (ecall)
    opt extra unsecure request
        Enclave->>App: Request operation (ocall)
        App->>Enclave: Return operation result
    end
    Enclave->>App: Return secure operation result
```

Basically, there's two modules the application (`app.cpp`) and the enclave (`enclave1.cpp`). All the code inside application is executed without any extra isolation, on the other hand the code inside enclave is performed inside the SGX enclave. The first thing that the application does is to create the enclave and every time a critical operation needs to be executed, it performs an `ecall`, e.g. call an enclave method. The enclave runs in a limited environment so, sometimes, it might need to perform an action that has no security risk (e.g. a print, read a file) and can easily be perform outside the enclave. To do so, the enclave does a `ocall` in order to call a method outside the enclave.

For our specific use case, the part of the program that runs outside the enclave has the main goal to provide an interface to the user for him/her to interact with the vault. All the operation that clearly interact with the vault are performed inside the enclave.

# Features and tests

## Insert assets

## List assets

## Print assets

## Export assets

## Compare assets hash

## Seal and unseal

```mermaid
block-beta
    block
        Nonce
        Password
        Author
        N_files
    end
    block
      hash
      name
      size
      data
    end
    block
      ...
    end
```

## Clone vault
Clone a vault from a remote host was implemented using TLS communication. It consists of a TLS server which waits for clients and a client that requests the vault.

TLS requires trusted certificates to run properly, a script obtained from (here)[https://github.com/diogoftm/simulated-kms/blob/main/certs/makefile] which generates certificates signed by a self signed CA. These certificates are loaded by the server and the client is configured to trust the CA.

Implementation of client and server can be found in `src/App/AppSocket.cpp`. A simple message exchange protocol was built to support base communication (`BaseMessageLayer`).

The clone happens on top of that protocol, both server and client communication depends on a callback passed as argument to setup functions (see `TlsClient::connect(...)`  and `TlsServer::run_server(...)`). Both callbacks were defined in `src/App.cpp` (`serveClientCallback(SSL* ssl)` and `clientConnectionWithServerCallback(SSL* ssl)`).

Clone was divided in some phases, after communication is initialized the following steps (in case of success) happen.

1. Client sends a request clone message.
2. Server asks for vault name.
3. Client asks user for vault name, (if it's not present in server, server responses with a invalid vault message response and the communication terminates).
4. Server transmits vault data to the client.
5. Client sends an ok message after clone is completed. 
6. Server sends a close session message.

Server is not validating the client certificate, it could be implemented by adding some extra steps which could include asking for the client certificate, verifying if it was signed by the CA and then a challenge sign response would need to happen.

Even if a malicius client clones the vault, he would never be able to obtain vault decrypted data without knowing vault password and private key used by the enclave. 

//One major issue with sealing system is that the key used to encrypt the data is specific to the version of the enclave, so keeping the data from multiple software versions needs extra mechanisms. To solve...
# Conclusions