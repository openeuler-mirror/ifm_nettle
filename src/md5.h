#ifndef IFM_NETTLE_MD5_H_INCLUDED
#define IFM_NETTLE_MD5_H_INCLUDED

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define md5_init ifm_md5_init
#define md5_update ifm_md5_update
#define md5_digest ifm_md5_digest
#define md5_ctx ifm_md5_ctx

#define MD5_DIGEST_SIZE 16
#define MD5_BLOCK_SIZE 64
/* For backwards compatibility */
#define MD5_DATA_SIZE MD5_BLOCK_SIZE

/* Digest is kept internally as 4 32-bit words. */
#define _MD5_DIGEST_LENGTH 4

struct ifm_md5_ctx
{
  uint32_t state[_MD5_DIGEST_LENGTH];
  uint64_t count;               /* Block count */
  unsigned index;               /* Into buffer */
  uint8_t block[MD5_BLOCK_SIZE]; /* Block buffer */
};

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