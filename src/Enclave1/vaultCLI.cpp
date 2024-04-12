#include "VaultCLI.h"

void printOptions(){
    char buf[BUFSIZ] = { '\0' };
    va_list ap;

    va_start(ap,"Hello from enclave 1\n");
    (void)vsnprintf(buf,BUFSIZ,"Hello from enclave 1\n", ap);
    va_end(ap);
    ocall_e1_print_string(buf);
    return 0;
}