#ifndef IFM_NETTLE_MD5_H_INCLUDED
#define IFM_NETTLE_MD5_H_INCLUDED

#include <stddef.h>
#include <stdint.h>
#include "md5_meta.h"
#ifdef __aarch64__
#include "uadk/v1/wd.h"
#include "uadk/v1/wd_bmm.h"
#include "uadk/v1/wd_digest.h"
#endif


#ifdef __cplusplus
extern "C" {
#endif

#define md5_init ifm_md5_init
#define md5_update ifm_md5_update
#define md5_digest ifm_md5_digest

void
ifm_md5_init(struct ifm_md5_ctx *ctx);

void
ifm_md5_update(struct ifm_md5_ctx *ctx,
	   size_t length,
	   const uint8_t *data);

void
ifm_md5_digest(struct ifm_md5_ctx *ctx,
	   size_t length,
	   uint8_t *digest);

#ifdef __cplusplus
}
#endif

#endif /* IFM_NETTLE_MD5_H_INCLUDED */