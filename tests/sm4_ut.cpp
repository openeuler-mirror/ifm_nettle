#define _NETTLE_ATTRIBUTE_DEPRECATED

#include <gtest/gtest.h>
#include "stub/stub.h"

#include "cipher.h"
#include "ifm_utils.h"
#include "sm4.h"
#include "testutils.h"

const struct nettle_cipher nettle_ifm_sm4 = {"sm4",
                                             sizeof(struct ifm_sm4_ctx),
                                             SM4_BLOCK_SIZE,
                                             SM4_KEY_SIZE,
                                             (nettle_set_key_func *)ifm_sm4_set_encrypt_key,
                                             (nettle_set_key_func *)ifm_sm4_set_decrypt_key,
                                             (nettle_cipher_func *)ifm_sm4_crypt,
                                             (nettle_cipher_func *)ifm_sm4_crypt};

TEST(sm4_testcases, test_sm4_1)
{
    test_cipher(&nettle_ifm_sm4, SHEX("0123456789ABCDEFFEDCBA9876543210"), SHEX("0123456789ABCDEFFEDCBA9876543210"),
                SHEX("681EDF34D206965E86B3E94F536E4246"));
}

TEST(sm4_testcases, test_sm4_2)
{
    test_cipher(&nettle_ifm_sm4, SHEX("14151617191A1B1C1E1F202123242526"), SHEX("5C6D71CA30DE8B8B00549984D2EC7D4B"),
                SHEX("36E24D6FE45AD48608EEC5F6E80F4D03"));
}

TEST(sm4_testcases, test_sm4_3)
{
    test_cipher(&nettle_ifm_sm4, SHEX("28292A2B2D2E2F30323334353738393A"), SHEX("53F3F4C64F8616E4E7C56199F48F21F6"),
                SHEX("B029ABECA8BA39D87D962043535EEF11"));
}

TEST(sm4_testcases, test_sm4_4)
{
    test_cipher(&nettle_ifm_sm4, SHEX("A0A1A2A3A5A6A7A8AAABACADAFB0B1B2"), SHEX("F5F4F7F684878689A6A7A0A1D2CDCCCF"),
                SHEX("3C6ED10FAD7B88C2389838E05F417F46"));
}

TEST(sm4_testcases, test_sm4_5)
{
    test_cipher(&nettle_ifm_sm4, SHEX("FEDCBA98765432100123456789ABCDEF"), SHEX("000102030405060708090A0B0C0D0E0F"),
                SHEX("F766678F13F01ADEAC1B3EA955ADB594"));
}

//以下用于异常分支测试
#ifdef __aarch64__
extern "C" {
//extern int uadk_cipher_set_key(struct uadk_cipher_st *uadk_ctx, const uint8_t *uadk_key, uint16_t key_len);
}

int uadk_cipher_set_key_stub1(struct uadk_cipher_st *uadk_ctx, const uint8_t *uadk_key, uint16_t key_len)
{
    return 1;
}

int UadkEnabled_stub()
{
    return false;
}

IFMUadkShareCtx *get_uadk_ctx_stub(UadkQueueAlgType alg_type, int alg, int mode, bool is_shared)
{
    return NULL;
}

IFMUadkShareOpdata *get_uadk_opdata_stub(UadkQueueAlgType alg_type)
{
    return NULL;
}

TEST(sm4_testcases, test_sm4_exception1)
{
    Stub stub;
    stub.set(uadk_cipher_set_key, uadk_cipher_set_key_stub1);
    struct ifm_sm4_ctx ctx;
    memset(&ctx, 0, sizeof(ctx));
    ctx.use_uadk = true;
    ctx.uadk_ctx.ctx = NULL;
    ifm_sm4_crypt(&ctx, 1024, NULL, NULL);
    ASSERT (ctx.use_uadk == false);
    stub.reset(uadk_cipher_set_key);
}

TEST(sm4_testcases, test_sm4_exeception2)
{
    Stub s;
    s.set(UadkEnabled, UadkEnabled_stub);
    struct ifm_sm4_ctx *ctx = (ifm_sm4_ctx *)malloc(sizeof(ifm_sm4_ctx));
    memset(ctx, 0, sizeof(struct ifm_sm4_ctx));
    ctx->use_uadk = false;
    ifm_sm4_set_encrypt_key(ctx, SHEX("000102030405060708090A0B0C0D0E0F")->data);
    ifm_sm4_set_decrypt_key(ctx, SHEX("000102030405060708090A0B0C0D0E0F")->data);
    free(ctx);
    s.reset(UadkEnabled);
}

TEST(sm4_testcases, test_sm4_exeception3)
{
    Stub s;
    s.set(get_uadk_ctx, get_uadk_ctx_stub);
    struct uadk_cipher_st uadk_ctx;
    uadk_cipher_init(&uadk_ctx);
    uint8_t *dst = (uint8_t *)malloc(1);
    uadk_do_cipher(&uadk_ctx, NULL, dst, NULL, 0, 0);
    s.reset(get_uadk_ctx);
}

TEST(sm4_testcases, test_sm4_exeception4)
{
    Stub s;
    s.set(get_uadk_opdata, get_uadk_opdata_stub);
    void *ctx = xalloc(nettle_ifm_sm4.context_size);
    uint8_t *data = (uint8_t *)xalloc(SHEX("000102030405060708090A0B0C0D0E0F")->length);
    size_t length;
    length = SHEX("000102030405060708090A0B0C0D0E0F")->length;
    memset(ctx, 0, nettle_ifm_sm4.context_size);
    nettle_ifm_sm4.set_encrypt_key(ctx, SHEX("FEDCBA98765432100123456789ABCDEF")->data);
    nettle_ifm_sm4.encrypt(ctx, length, data, SHEX("000102030405060708090A0B0C0D0E0F")->data);
    s.reset(get_uadk_opdata);
    }

#endif