#ifndef IFM_NETTLE_MD5_META_INCLUDED
#define IFM_NETTLE_MD5_META_INCLUDED

#include <stddef.h>
#include <stdint.h>
#ifdef __aarch64__
#include "uadk/v1/wd.h"
#include "uadk/v1/wd_bmm.h"
#include "uadk/v1/wd_digest.h"
#endif


#ifdef __cplusplus
extern "C" {
#endif

#define MD5_DIGEST_SIZE 16
#define MD5_BLOCK_SIZE 64
/* For backwards compatibility */
#define MD5_DATA_SIZE MD5_BLOCK_SIZE

/* Digest is kept internally as 4 32-bit words. */
#define _MD5_DIGEST_LENGTH 4

#ifdef __aarch64__
#define SQE_SIZE 128
#define MAX_BLOCK_SZ	1024*1024*1		// 每次hash分段的最大长度
#define MAX_BLOCK_NM	128
struct uadk_digest_st
{
	struct wd_queue *pq;
    struct wcrypto_digest_ctx_setup setup;
	struct wcrypto_digest_op_data opdata;
	void *pool;
	void *ctx;
};
#endif

struct ifm_md5_ctx
{
    uint32_t state[_MD5_DIGEST_LENGTH];
    uint64_t count;               /* Block count */
    unsigned index;               /* Into buffer */
    uint8_t block[MD5_BLOCK_SIZE]; /* Block buffer */
#ifdef __aarch64__
    struct uadk_digest_st uadk_ctx; /* UADK相关的结构体数据 */
	bool use_uadk;
#endif
};

#ifdef __cplusplus
}
#endif

#endif /* IFM_NETTLE_MD5_META_INCLUDED */