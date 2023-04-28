#ifndef _IFM_LIBGCRYPT_H
#define _IFM_LIBGCRYPT_H

#include <stddef.h>
#include <stdint.h>
#include <gcrypt.h>

#ifdef __cplusplus
extern "C" {
#endif

#define gcry_md_open ifm_gcry_md_open
#define gcry_md_algo_info ifm_gcry_md_algo_info

gcry_error_t ifm_gcry_md_open (gcry_md_hd_t *h, int algo, unsigned int flags);

gcry_error_t ifm_gcry_md_algo_info (int algo, int what, void *buffer,
                               size_t *nbytes);

#ifdef __cplusplus
}
#endif

#endif /* _IFM_LIBGCRYPT_H */