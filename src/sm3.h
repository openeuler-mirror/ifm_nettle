#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define SM3_DIGEST_SIZE 32
#define SM3_BLOCK_SIZE 64

/* Digest is kept internally as 8 32-bit words. */
#define _SM3_DIGEST_LENGTH 8

struct sm3_ctx
{
  uint32_t state[_SM3_DIGEST_LENGTH];
  uint64_t count;               /* Block count */
  unsigned index;               /* Into buffer */
  uint8_t block[SM3_BLOCK_SIZE]; /* Block buffer */
};

void
sm3_init(struct sm3_ctx *ctx);

void
sm3_update(struct sm3_ctx *ctx,
	   size_t length,
	   const uint8_t *data);

void
sm3_digest(struct sm3_ctx *ctx,
	   size_t length,
	   uint8_t *digest);

#ifdef __cplusplus
}
#endif
