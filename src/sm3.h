#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define sm3_init ifm_sm3_init
#define sm3_update ifm_sm3_update
#define sm3_digest ifm_sm3_digest
#define sm3_ctx ifm_sm3_ctx

#define SM3_DIGEST_SIZE 32
#define SM3_BLOCK_SIZE 64

/* Digest is kept internally as 8 32-bit words. */
#define _SM3_DIGEST_LENGTH 8

struct ifm_sm3_ctx
{
  uint32_t state[_SM3_DIGEST_LENGTH];
  uint64_t count;               /* Block count */
  unsigned index;               /* Into buffer */
  uint8_t block[SM3_BLOCK_SIZE]; /* Block buffer */
};

void
ifm_sm3_init(struct ifm_sm3_ctx *ctx);

void
ifm_sm3_update(struct ifm_sm3_ctx *ctx,
	   size_t length,
	   const uint8_t *data);

void
ifm_sm3_digest(struct ifm_sm3_ctx *ctx,
	   size_t length,
	   uint8_t *digest);

#ifdef __cplusplus
}
#endif
