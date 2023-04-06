#ifndef IFM_NETTLE_SHA2_H_INCLUDED
#define IFM_NETTLE_SHA2_H_INCLUDED

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define sha256_init ifm_sha256_init
#define sha256_update ifm_sha256_update
#define sha256_digest ifm_sha256_digest
#define sha256_ctx ifm_sha256_ctx

/* SHA256 */
#define SHA256_DIGEST_SIZE 32
#define SHA256_BLOCK_SIZE 64

/* Digest is kept internally as 8 32-bit words. */
#define _SHA256_DIGEST_LENGTH 8

struct ifm_sha256_ctx
{
  uint32_t state[_SHA256_DIGEST_LENGTH];    /* State variables */
  uint64_t count;                           /* 64-bit block count */
  unsigned int index;                       /* index into buffer */
  uint8_t block[SHA256_BLOCK_SIZE];          /* SHA256 data buffer */
};

void
ifm_sha256_init(struct ifm_sha256_ctx *ctx);

void
ifm_sha256_update(struct ifm_sha256_ctx *ctx,
	      size_t length,
	      const uint8_t *data);

void
ifm_sha256_digest(struct ifm_sha256_ctx *ctx,
	      size_t length,
	      uint8_t *digest);

#ifdef __cplusplus
}
#endif

#endif /* IFM_NETTLE_SHA2_H_INCLUDED */