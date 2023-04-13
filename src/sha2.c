#include <stdio.h>
#include "nettle/sha2.h"


/**
 * @ingroup uadk_sha256_init
 * @par 将uadk的sha256算法适配成sha256_init算法，该接口的使用场景以及参数同nettle中的sha256_init接口相同
 */
void
uadk_sha256_init(struct sha256_ctx *ctx)
{
    return;
}

/**
 * @ingroup uadk_sha256_update
 * @par 将uadk的sha256算法适配成sha256_update算法，该接口的使用场景以及参数同nettle中的sha256_update接口相同
 */
void
uadk_sha256_update(struct sha256_ctx *ctx,
	   size_t length,
	   const uint8_t *data)
{

}

/**
 * @ingroup uadk_sha256_update
 * @par 将uadk的sha256算法适配成sha256_digest算法，该接口的使用场景以及参数同nettle中的sha256_digest接口相同
 */
void
uadk_sha256_digest(struct sha256_ctx *ctx,
	   size_t length,
	   uint8_t *digest)
{

}

void
ifm_sha256_init(struct sha256_ctx *ctx)
{
    sha256_init(ctx);
}

void
ifm_sha256_update(struct sha256_ctx *ctx,
	   size_t length,
	   const uint8_t *data)
{
	sha256_update(ctx, length, data);
}

void
ifm_sha256_digest(struct sha256_ctx *ctx,
	   size_t length,
	   uint8_t *digest)
{
	sha256_digest(ctx, length, digest);
}