#include "Enclave1_u.h"
#include <errno.h>

typedef struct ms_ocall_e1_print_string_t {
	const char* ms_str;
} ms_ocall_e1_print_string_t;

static sgx_status_t SGX_CDECL Enclave1_ocall_e1_print_string(void* pms)
{
	ms_ocall_e1_print_string_t* ms = SGX_CAST(ms_ocall_e1_print_string_t*, pms);
	ocall_e1_print_string(ms->ms_str);

	return SGX_SUCCESS;
}

static const struct {
	size_t nr_ocall;
	void * table[1];
} ocall_table_Enclave1 = {
	1,
	{
		(void*)Enclave1_ocall_e1_print_string,
	}
};
sgx_status_t printOptions(sgx_enclave_id_t eid)
{
	sgx_status_t status;
	status = sgx_ecall(eid, 0, &ocall_table_Enclave1, NULL);
	return status;
}

