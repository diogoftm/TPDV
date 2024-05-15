# TPDV - Intel SGX Enclaves Temper-Proof Digital Vault 
The objective of this project is to implemnt a "tamper-proof digital vault" (TPDV) leveraging Intel's SGX enclaves. The TPDV is designed to securely store digital assets in a write-once manner, 
preventing any alteration or deletion of stored information. Although a malicious operator could potentially destroy the entire TPDV, they cannot modify any existing data without detection. 
Also mechanisms are deployed to enable the secure tranfer of the sealed vault content between different versions of the SGX enclave.

The full discription of the project can be found in `/docs/report.md` (or in `/docs/report.pdf` if you wish).

## Scope
This project was developed for the Secure Execution Invironments course of the Masters in Cybersecurity at University of Aveiro.   

## Contributors
- Diogo Matos - dftm@ua.pt
- Tiago Silvestre - tiago.silvestre@ua.pt
- David Araújo - davidaraujo@ua.pt
