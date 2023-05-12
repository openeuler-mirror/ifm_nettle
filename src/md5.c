#include <stdio.h>
#include <string.h>
#include "nettle/md5.h"
#ifdef __aarch64__
#include "uadk/v1/wd.h"
#include "uadk/v1/wd_digest.h"
#endif
#include "md5_meta.h"


#ifdef __aarch64__
/**
 * @ingroup uadk_md5_init
 * @par 将uadk的md5算法适配成md5_init算法，该接口的使用场景以及参数同nettle中的md5_init接口相同
 */
int uadk_md5_init(struct ifm_md5_ctx *ctx)
{
	static struct wd_queue q;
	static struct wd_blkpool_setup pool_setup;
	static void *pool=NULL;
	static bool q_init = false;
	int ret = 0;
	if (!q_init)
	{
		memset(&q, 0, sizeof(q));
		q.capa.alg = "digest";
		ret = wd_request_queue(&q);
		if (ret)
		{
			return ret;
		}
		
		memset(&pool_setup, 0, sizeof(pool_setup));
		pool_setup.block_size = MAX_BLOCK_SZ; //set pool  inv + key + in + out
		pool_setup.block_num = MAX_BLOCK_NM;
		pool_setup.align_size = SQE_SIZE;
		pool = wd_blkpool_create(&q, &pool_setup);
		
		q_init = true;
	}
	ctx->uadk_ctx.pool = pool;

	ctx->uadk_ctx.setup.alg = WCRYPTO_MD5;
	ctx->uadk_ctx.setup.mode = WCRYPTO_DIGEST_NORMAL;
	ctx->uadk_ctx.setup.br.alloc = (void *)wd_alloc_blk;
	ctx->uadk_ctx.setup.br.free = (void *)wd_free_blk;
	ctx->uadk_ctx.setup.br.iova_map = (void *)wd_blk_iova_map;
	ctx->uadk_ctx.setup.br.iova_unmap = (void *)wd_blk_iova_unmap;
	ctx->uadk_ctx.setup.br.get_bufsize = (void *)wd_blksize;
	ctx->uadk_ctx.setup.br.usr = pool;
	
	ctx->uadk_ctx.pq = &q;
	ctx->uadk_ctx.ctx = wcrypto_create_digest_ctx(&q, &(ctx->uadk_ctx.setup));
	memset(&(ctx->uadk_ctx.opdata), 0, sizeof(struct wcrypto_digest_op_data));

    return ret;
}

/**
 * @ingroup uadk_md5_update
 * @par 将源数据拆分成固定大小，然后分别调用wcrypto_do_digest接口提前进行hash计算。
 * 在原有的nettle对应的update接口中，会将数据提前进行压缩计算，因此只要64字节即可满足要求。
 * 但是UADK中没有对应的update接口，因此在update接口中不适合将所有的数据都存储起来。
 */
void
uadk_md5_update(struct ifm_md5_ctx *ctx,
	   size_t length,
	   const uint8_t *data)
{
	const uint8_t *data_pt=NULL;
	size_t total_len = 0;

	if (NULL == ctx->uadk_ctx.ctx)
	{
		ctx->uadk_ctx.ctx = wcrypto_create_digest_ctx(ctx->uadk_ctx.pq, &(ctx->uadk_ctx.setup));
	}

	// 接口的使用场景上，会存在多次update然后再digest的情况，因此需考虑无需重复申请的场景
	if (!ctx->uadk_ctx.opdata.in)
	{
		ctx->uadk_ctx.opdata.in = wd_alloc_blk(ctx->uadk_ctx.pool);
	}
	if (!ctx->uadk_ctx.opdata.out)
	{
		ctx->uadk_ctx.opdata.out = wd_alloc_blk(ctx->uadk_ctx.pool);
		ctx->uadk_ctx.opdata.out_bytes = MD5_DIGEST_SIZE; // MD5的长度是16
	}

	do
	{
		data_pt = data + total_len;
		// 分段输入，每段大小为MAX_BLOCK_SZ
		if (total_len + MAX_BLOCK_SZ <= length)
		{
			memcpy(ctx->uadk_ctx.opdata.in, data_pt, MAX_BLOCK_SZ);
			ctx->uadk_ctx.opdata.in_bytes = MAX_BLOCK_SZ;
			ctx->uadk_ctx.opdata.has_next = true;
			total_len += MAX_BLOCK_SZ;
		}
		else
		{
			memcpy(ctx->uadk_ctx.opdata.in, data_pt, length-total_len);
			ctx->uadk_ctx.opdata.in_bytes = length-total_len;
			ctx->uadk_ctx.opdata.has_next = false;
			total_len = length;
		}
		wcrypto_do_digest(ctx->uadk_ctx.ctx, &(ctx->uadk_ctx.opdata), NULL);
	} while (total_len < length);
}

/**
 * @ingroup uadk_md5_digest
 * @par 在update阶段已经提前将数据进行hash，因此在digest阶段只需要将数据复制到digest中，并且进行资源清理。
 */
void
uadk_md5_digest(struct ifm_md5_ctx *ctx,
	   size_t length,
	   uint8_t *digest)
{
	memcpy(digest, ctx->uadk_ctx.opdata.out, length);

	// 不可在该流程将内容释放，因为原有的接口支持调用update、do_digest、update、do_digest
	// if (ctx->uadk_ctx.opdata.in)
	// {
	// 	wd_free_blk(ctx->uadk_ctx.pool, ctx->uadk_ctx.opdata.in);
	// 	ctx->uadk_ctx.opdata.in = NULL;
	// }
	// if (ctx->uadk_ctx.opdata.out)
	// {
	// 	wd_free_blk(ctx->uadk_ctx.pool, ctx->uadk_ctx.opdata.out);
	// 	ctx->uadk_ctx.opdata.out = NULL;
	// }
	// if (ctx->uadk_ctx.ctx)
	// 	wcrypto_del_digest_ctx(ctx->uadk_ctx.ctx);
}
#endif

void
ifm_md5_init(struct ifm_md5_ctx *ctx)
{
	struct md5_ctx nettle_ctx;
    md5_init(&nettle_ctx);
	memcpy(ctx, &nettle_ctx, sizeof(nettle_ctx));

	// 对于使用鲲鹏加速的场景下，将原有ctx的内容进行初始化之外，需要额外调用uadk_md5_init初始化UADK所需的配置信息
	#ifdef __aarch64__
	if (0 != uadk_md5_init(ctx))
	{
		ctx->use_uadk = false;
	}
	else
	{
		ctx->use_uadk = true;
	}
	#endif
}

void
ifm_md5_update(struct ifm_md5_ctx *ctx,
	   size_t length,
	   const uint8_t *data)
{
	#ifdef __aarch64__
	// UADK不支持处理长度为0的字符串
	if (ctx->use_uadk && length >0)
	{
		uadk_md5_update(ctx, length, data);
	}
	else
	{
		md5_update((struct md5_ctx *)ctx, length, data);
		ctx->use_uadk = false;
	}
	#else
	md5_update((struct md5_ctx *)ctx, length, data);
	#endif
}

void
ifm_md5_digest(struct ifm_md5_ctx *ctx,
	   size_t length,
	   uint8_t *digest)
{
	#ifdef __aarch64__
	if (ctx->use_uadk)
	{
		uadk_md5_digest(ctx, length, digest);
	}
	else
	{
		md5_digest((struct md5_ctx *)ctx, length, digest);
	}
	#else
	md5_digest((struct md5_ctx *)ctx, length, digest);
	#endif
}