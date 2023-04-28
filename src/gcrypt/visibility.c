#include <stdio.h>
#include "gcrypt.h"

gcry_error_t ifm_gcry_md_open (gcry_md_hd_t *h, int algo, unsigned int flags)
{
	return gcry_md_open(h, algo, flags);
}

gcry_error_t ifm_gcry_md_algo_info (int algo, int what, void *buffer, size_t *nbytes)
{
	return gcry_md_algo_info(algo, what, buffer, nbytes);
	// 该代码用于测试验证是否调用适配层的接口。
	//return gpg_error (GPG_ERR_NOT_OPERATIONAL);
}