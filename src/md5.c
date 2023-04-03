#include <stdio.h>
#include "nettle/md5.h"


/**
 * @ingroup uadk_md5_init
 * @par 将uadk的md5算法适配成md5_init算法，该接口的使用场景以及参数同nettle中的md5_init接口相同
 */
void
uadk_md5_init(struct md5_ctx *ctx)
{
    return;
}

/**
 * @ingroup uadk_md5_update
 * @par 将uadk的md5算法适配成md5_update算法，该接口的使用场景以及参数同nettle中的md5_update接口相同
 */
void
uadk_md5_update(struct md5_ctx *ctx,
	   size_t length,
	   const uint8_t *data)
{

}

/**
 * @ingroup uadk_md5_update
 * @par 将uadk的md5算法适配成md5_digest算法，该接口的使用场景以及参数同nettle中的md5_digest接口相同
 */
void
uadk_md5_digest(struct md5_ctx *ctx,
	   size_t length,
	   uint8_t *digest)
{

}

void
ifm_md5_init(struct md5_ctx *ctx)
{
    md5_init(ctx);
}

void
ifm_md5_update(struct md5_ctx *ctx,
	   size_t length,
	   const uint8_t *data)
{
	md5_update(ctx, length, data);
}

void
ifm_md5_digest(struct md5_ctx *ctx,
	   size_t length,
	   uint8_t *digest)
{
	md5_digest(ctx, length, digest);
}