#include <stdio.h>
#include "nettle/sm3.h"


/**
 * @ingroup uadk_sm3_init
 * @par 将uadk的sm3算法适配成sm3_init算法，该接口的使用场景以及参数同nettle中的sm3_init接口相同
 */
void
uadk_sm3_init(struct sm3_ctx *ctx)
{
    return;
}

/**
 * @ingroup uadk_sm3_update
 * @par 将uadk的sm3算法适配成sm3_update算法，该接口的使用场景以及参数同nettle中的sm3_update接口相同
 */
void
uadk_sm3_update(struct sm3_ctx *ctx,
	   size_t length,
	   const uint8_t *data)
{

}

/**
 * @ingroup uadk_sm3_update
 * @par 将uadk的sm3算法适配成sm3_digest算法，该接口的使用场景以及参数同nettle中的sm3_digest接口相同
 */
void
uadk_sm3_digest(struct sm3_ctx *ctx,
	   size_t length,
	   uint8_t *digest)
{

}

void
ifm_sm3_init(struct sm3_ctx *ctx)
{
    sm3_init(ctx);
}

void
ifm_sm3_update(struct sm3_ctx *ctx,
	   size_t length,
	   const uint8_t *data)
{
	sm3_update(ctx, length, data);
}

void
ifm_sm3_digest(struct sm3_ctx *ctx,
	   size_t length,
	   uint8_t *digest)
{
	sm3_digest(ctx, length, digest);
}