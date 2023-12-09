/******************************************************************************
 * ifm_nettle-rsa.c: add rsa support for ifm_nettle
 *
 * Copyright (c) Huawei Technologies Co., Ltd. 2020. All rights reserved.
 *
 * Authors:
 * jiaji2023 <jiaji@isrc.iscas.ac.cn>
 * chen-yufanspace <1109674186@qq.com>
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 ********************************************************************************/
/*
 * 当前由于UADK V1接口的限制，RSA的实现存在如下约束
 * 1. 密钥长度必须为1024的整数倍，否则输出结果会有误。
 * 2. 因为rsa初始化时不知道key_size，在key_prepare中再进行初始化，因此在使用时必须进行prepare步骤
 * 3. nettle中私钥全部采用RSA-CRT格式，因此默认使用rsa-crt模式
 * 4.
 * keygen时由于UADK在crt模式时不会生成私钥参数d，因此无法将参数d传给nettle私钥，该参数在nettle私钥中也只有keygen时会用到
 * 5.
 * 启用UADK时，由于需要调用openssl的随机大质数生成函数，目前测试时发现如果程序调用rsa_generate_keypair函数时有小概率会卡死
 */
#include <nettle/base16.h>
#include <nettle/bignum.h>
#include <nettle/pkcs1.h>
#include <nettle/rsa.h>
#include <nettle/sha1.h>
#include <openssl/bn.h>
#include <openssl/rand.h>
#include <openssl/rsa.h>
#include <string.h>

#undef md5_init
#undef md5_update
#undef md5_digest
#include "md5_meta.h"
#include "rsa_meta.h"
#include "rsa_pkcs1.h"

#undef sha224_init
#undef sha224_digest
#undef sha256_init
#undef sha256_update
#undef sha256_digest
#undef sha384_init
#undef sha384_digest
#undef sha512_init
#undef sha512_update
#undef sha512_digest
#undef sha512_224_init
#undef sha512_224_digest
#undef sha512_256_init
#undef sha512_256_digest

#include "rsa_utils.h"
#include "sha2_meta.h"

#ifdef __aarch64__
#include "uadk/v1/wd.h"
#include "uadk/v1/wd_rsa.h"
#endif

#define CRT_PARAMS_SZ(key_size) ((5 * (key_size)) >> 1)
#define CRT_GEN_PARAMS_SZ(key_size) ((7 * (key_size)) >> 1)
#define GEN_PARAMS_SZ(key_size) ((key_size) << 1)
#define GEN_PARAMS_SZ_UL(key_size) ((unsigned long)(key_size) << 1)
#define CRT_PARAM_SZ(key_size) ((key_size) >> 1)

#define BYTES_SIZE 256
#define KEYSIZEFORMAT 1024
#define BITS2BYTES 8

#ifdef __aarch64__
int uadk_rsactx_init(struct uadk_rsa_st *uadk_st, mpz_t n)
{
    IFMUadkShareCtx *p_share_ctx = NULL;
    memset(uadk_st, 0, sizeof(struct uadk_rsa_st));
    size_t bitLength = mpz_sizeinbase(n, 2);
    p_share_ctx = get_uadk_ctx(IFM_UADK_ALG_RSA, true, (int)bitLength, true);
    if (p_share_ctx == NULL) {
        IFM_ERR("uadk_ctx_init get_uadk_ctx failed\n");
        return -1;
    }
    uadk_st->ctx = p_share_ctx->ctx;
    return 0;
}

void uadk_rsactx_free(struct uadk_rsa_st *uadk_st)
{
    free_uadk_opdata(IFM_UADK_ALG_RSA, (IFMUadkShareOpdata *)uadk_st->opdata);
    free_uadk_ctx(IFM_UADK_ALG_RSA, (IFMUadkShareCtx *)uadk_st->ctx);
}

void uadk_rsa_set_pubkey(struct uadk_rsa_st *uadk_st, mpz_t n, mpz_t e)
{
    size_t size_n;
    size_t size_e;
    size_n = mpz_sizeinbase(n, BYTES_SIZE);
    size_e = mpz_sizeinbase(e, BYTES_SIZE);
    if (size_n == 0 || size_e == 0) {
        IFM_ERR("uadk_rsa_set_pubkey get_n_size failed\n");
        return;
    }
    char *buffern = (char *)malloc(size_n);
    char *buffere = (char *)malloc(size_n);
    if (buffern == NULL || buffere == NULL) {
        IFM_ERR("uadk_rsa_set_pubkey get_buffer failed\n");
        return;
    }
    mpz_export(buffern, &size_n, 1, 1, 0, 0, n);
    mpz_export(buffere, &size_e, 1, 1, 0, 0, e);
    struct wd_dtb wd_n;
    struct wd_dtb wd_e;

    wd_n.data = buffern;
    wd_n.dsize = size_n;

    wd_e.data = buffere;
    wd_e.dsize = size_e;
    wcrypto_set_rsa_pubkey_params(uadk_st->ctx, &wd_e, &wd_n);
}

void uadk_rsa_set_prikey(struct uadk_rsa_st *uadk_st, mpz_t p, mpz_t q, mpz_t a, mpz_t b, mpz_t c)
{
    size_t size_p;
    size_t size_q;
    size_t size_a;
    size_t size_b;
    size_t size_c;
    size_p = mpz_sizeinbase(p, BYTES_SIZE);
    size_q = mpz_sizeinbase(q, BYTES_SIZE);
    size_a = mpz_sizeinbase(a, BYTES_SIZE);
    size_b = mpz_sizeinbase(b, BYTES_SIZE);
    size_c = mpz_sizeinbase(c, BYTES_SIZE);
    if (size_p == 0 || size_q == 0 || size_a == 0 || size_b == 0 || size_c == 0) {
        IFM_ERR("uadk_rsa_set_prikey get_n_size failed\n");
        return;
    }
    char *bufferp = (char *)malloc(size_p);
    char *bufferq = (char *)malloc(size_q);
    char *buffera = (char *)malloc(size_a);
    char *bufferb = (char *)malloc(size_b);
    char *bufferc = (char *)malloc(size_c);
    if (bufferp == NULL || bufferq == NULL || buffera == NULL || bufferb == NULL || bufferc == NULL) {
        IFM_ERR("uadk_rsa_set_prikey get_buffer failed\n");
        return;
    }
    mpz_export(bufferp, &size_p, 1, 1, 0, 0, p);
    mpz_export(bufferq, &size_q, 1, 1, 0, 0, q);
    mpz_export(buffera, &size_a, 1, 1, 0, 0, a);
    mpz_export(bufferb, &size_b, 1, 1, 0, 0, b);
    mpz_export(bufferc, &size_c, 1, 1, 0, 0, c);
    struct wd_dtb wd_p;
    struct wd_dtb wd_q;
    struct wd_dtb wd_dp;
    struct wd_dtb wd_dq;
    struct wd_dtb wd_qinv;
    wd_dp.data = buffera;
    wd_dp.dsize = size_a;

    wd_dq.data = bufferb;
    wd_dq.dsize = size_b;

    wd_qinv.data = bufferc;
    wd_qinv.dsize = size_c;

    wd_q.data = bufferq;
    wd_q.dsize = size_q;

    wd_p.data = bufferp;
    wd_p.dsize = size_p;
    wcrypto_set_rsa_crt_prikey_params(uadk_st->ctx, &wd_dq, &wd_dp, &wd_qinv, &wd_q, &wd_p);
}

int uadk_rsa_sign(struct uadk_rsa_st *uadk_st, uint8_t *data, mpz_t signature, size_t size)
{
    IFMUadkShareOpdata *p_share_opdata = NULL;

    p_share_opdata = get_uadk_opdata(IFM_UADK_ALG_RSA);
    if (p_share_opdata == NULL) {
        IFM_ERR("uadk_rsa_sign get_uadk_opdata failed\n");
        return 0;
    }
    unsigned int key_size = wcrypto_rsa_key_bits(uadk_st->ctx) / BITS2BYTES;
    uadk_st->opdata = (struct wcrypto_rsa_op_data *)p_share_opdata->opdata;
    uadk_st->opdata->op_type = WCRYPTO_RSA_SIGN;
    uadk_st->opdata->in_bytes = key_size;
    uadk_st->opdata->out_bytes = key_size;

    int move;
    if (size < key_size) {
        move = key_size - size;
        memmove(data + move, data, size);
        memset(data, 0, move);
    }
    memcpy(uadk_st->opdata->in, data, key_size);
    int ret = wcrypto_do_rsa(uadk_st->ctx, uadk_st->opdata, NULL);
    if (0 != ret) {
        return 0;
    }
    uint8_t *tmp = uadk_st->opdata->out;
    move = 0;
    while (tmp[move] == 0) {
        move++;
    }
    uadk_st->opdata->out_bytes -= move;
    memmove(uadk_st->opdata->out, uadk_st->opdata->out + move, uadk_st->opdata->out_bytes);
    mpz_import(signature, uadk_st->opdata->out_bytes, 1, 1, 0, 0, uadk_st->opdata->out);
    free_uadk_opdata(IFM_UADK_ALG_RSA, p_share_opdata);
    return 1;
}

int uadk_rsa_verify(struct uadk_rsa_st *uadk_st, const mpz_t m, const mpz_t s)
{
    IFMUadkShareOpdata *p_share_opdata = NULL;
    p_share_opdata = get_uadk_opdata(IFM_UADK_ALG_RSA);
    if (p_share_opdata == NULL) {
        IFM_ERR("uadk_rsa_sign get_uadk_opdata failed\n");
        return 0;
    }

    size_t size_s;
    size_s = mpz_sizeinbase(s, BYTES_SIZE);
    uint8_t *data = (uint8_t *)malloc(size_s);
    if (data == NULL) {
        IFM_ERR("uadk_rsa_verify get_buffer failed\n");
        return 0;
    }
    mpz_export(data, &size_s, 1, sizeof(uint8_t), 0, 0, s);
    unsigned int key_size = wcrypto_rsa_key_bits(uadk_st->ctx) / BITS2BYTES;
    uadk_st->opdata = (struct wcrypto_rsa_op_data *)p_share_opdata->opdata;
    uadk_st->opdata->op_type = WCRYPTO_RSA_VERIFY;
    uadk_st->opdata->in_bytes = key_size;
    uadk_st->opdata->out_bytes = key_size;

    memcpy(uadk_st->opdata->in, data, key_size);
    if (0 != wcrypto_do_rsa(uadk_st->ctx, uadk_st->opdata, NULL)) {
        return 0;
    }

    mpz_t m1;
    mpz_init(m1);
    mpz_import(m1, uadk_st->opdata->out_bytes, 1, 1, 0, 0, uadk_st->opdata->out);
    int res = !mpz_cmp(m, m1);
    mpz_clear(m1);
    free_uadk_opdata(IFM_UADK_ALG_RSA, p_share_opdata);

    return res;
}

int fill_keygen_opdata(void *ctx, struct wcrypto_rsa_op_data *opdata)
{
    struct wd_dtb *wd_e = NULL;
    struct wd_dtb *wd_p = NULL;
    struct wd_dtb *wd_q = NULL;
    struct wcrypto_rsa_pubkey *pubkey = NULL;
    struct wcrypto_rsa_prikey *prikey = NULL;

    wcrypto_get_rsa_pubkey(ctx, &pubkey);
    wcrypto_get_rsa_pubkey_params(pubkey, &wd_e, NULL);
    wcrypto_get_rsa_prikey(ctx, &prikey);
    wcrypto_get_rsa_crt_prikey_params(prikey, NULL, NULL, NULL, &wd_q, &wd_p);
    opdata->in = wcrypto_new_kg_in(ctx, wd_e, wd_p, wd_q);
    opdata->out = wcrypto_new_kg_out(ctx);
    return 0;
}

int uadk_rsa_keygen(struct ifm_rsa_public_key *pub, struct ifm_rsa_private_key *key, unsigned n_size, unsigned e_size)
{
    struct uadk_rsa_st *uadk_st = &(pub->uadk_st);

    // ctx init
    IFMUadkShareCtx *p_share_ctx = NULL;
    memset(uadk_st, 0, sizeof(struct uadk_rsa_st));
    p_share_ctx = get_uadk_ctx(IFM_UADK_ALG_RSA, true, (int)n_size, true);
    if (p_share_ctx == NULL) {
        IFM_ERR("uadk_rsa_keygen get_uadk_ctx failed\n");
        return 0;
    }
    uadk_st->ctx = p_share_ctx->ctx;

    unsigned int key_size = wcrypto_rsa_key_bits(uadk_st->ctx) / BITS2BYTES;
    uadk_st->opdata = (struct wcrypto_rsa_op_data *)malloc(sizeof(struct wcrypto_rsa_op_data));
    uadk_st->opdata->op_type = WCRYPTO_RSA_GENKEY;
    uadk_st->opdata->in_bytes = key_size;

    struct wcrypto_rsa_pubkey *pubkey = NULL;
    struct wcrypto_rsa_prikey *prikey = NULL;
    struct wd_dtb *wd_e = NULL;
    struct wd_dtb *wd_p = NULL;
    struct wd_dtb *wd_q = NULL;

    struct wd_dtb wd_d;
    struct wd_dtb wd_n;
    struct wd_dtb wd_qinv;
    struct wd_dtb wd_dq;
    struct wd_dtb wd_dp;

    // 使用自定义种子初始化 OpenSSL 随机数生成器
    unsigned char seed_data[4096];
    // 填充 seed_data，可以是任意真实随机的数据
    RAND_seed(seed_data, sizeof(seed_data));
    BIGNUM *e_value = BN_new();
    BIGNUM *p = BN_new();
    BIGNUM *q = BN_new();
    BIGNUM *e_given = BN_new();
    if (e_size == 0) {
        char *e_str = mpz_get_str(NULL, 10, pub->e);
        BN_dec2bn(&e_given, e_str);
        free(e_str);
        BN_copy(e_value, e_given);
        BN_free(e_given);
    } else {
        BN_rand(e_value, e_size, -1, 0);
    }
    hpre_rsa_primegen(n_size, e_value, p, q, NULL);
    wcrypto_get_rsa_pubkey(uadk_st->ctx, &pubkey);
    wcrypto_get_rsa_pubkey_params(pubkey, &wd_e, NULL);
    wd_e->dsize = BN_bn2bin(e_value, (unsigned char *)wd_e->data);
    wcrypto_get_rsa_prikey(uadk_st->ctx, &prikey);
    wcrypto_get_rsa_crt_prikey_params(prikey, NULL, NULL, NULL, &wd_q, &wd_p);
    wd_q->dsize = BN_bn2bin(q, (unsigned char *)wd_q->data);
    wd_p->dsize = BN_bn2bin(p, (unsigned char *)wd_p->data);
    mpz_import(pub->e, wd_e->dsize, 1, 1, 0, 0, wd_e->data);
    mpz_import(key->p, wd_p->dsize, 1, 1, 0, 0, wd_p->data);
    mpz_import(key->q, wd_q->dsize, 1, 1, 0, 0, wd_q->data);

    BN_clear(e_value);
    BN_clear(p);
    BN_clear(q);

    fill_keygen_opdata(uadk_st->ctx, uadk_st->opdata);
    wcrypto_do_rsa(uadk_st->ctx, uadk_st->opdata, NULL);

    wcrypto_get_rsa_kg_out_params(uadk_st->opdata->out, &wd_d, &wd_n);
    wcrypto_get_rsa_kg_out_crt_params(uadk_st->opdata->out, &wd_qinv, &wd_dq, &wd_dp);

    mpz_import(key->a, wd_dp.dsize, 1, 1, 0, 0, wd_dp.data);
    mpz_import(key->b, wd_dq.dsize, 1, 1, 0, 0, wd_dq.data);
    mpz_import(key->c, wd_qinv.dsize, 1, 1, 0, 0, wd_qinv.data);
    mpz_mul(pub->n, key->p, key->q);
    free(uadk_st->opdata);
    return 1;
}
#endif

void ifm_rsa_public_key_init(struct ifm_rsa_public_key *key)
{
    rsa_public_key_init((struct rsa_public_key *)key);
#ifdef __aarch64__
    if (UadkEnabled() == false) {
        key->use_uadk = false;
    } else {
        key->use_uadk = true;
    }
#endif
}

void ifm_rsa_public_key_clear(struct ifm_rsa_public_key *key)
{
    rsa_public_key_clear((struct rsa_public_key *)key);
#ifdef __aarch64__
    if (key->use_uadk) {
        uadk_rsactx_free(&(key->uadk_st));
    }
#endif
}

int ifm_rsa_public_key_prepare(struct ifm_rsa_public_key *key)
{
#ifdef __aarch64__
    size_t bitLength = mpz_sizeinbase(key->n, 2);
    if (bitLength % KEYSIZEFORMAT != 0) {
        key->use_uadk = false;
    } else {
        key->use_uadk = true;
        if (0 == uadk_rsactx_init(&(key->uadk_st), key->n)) {
            uadk_rsa_set_pubkey(&(key->uadk_st), key->n, key->e);
        } else {
            key->use_uadk = false;
        }
    }
#endif
    return rsa_public_key_prepare((struct rsa_public_key *)key);
}

void ifm_rsa_private_key_init(struct ifm_rsa_private_key *key)
{
    rsa_private_key_init((struct rsa_private_key *)key);
#ifdef __aarch64__
    if (UadkEnabled() == false) {
        key->use_uadk = false;
    } else {
        key->use_uadk = true;
    }
#endif
}

void ifm_rsa_private_key_clear(struct ifm_rsa_private_key *key)
{
    rsa_private_key_clear((struct rsa_private_key *)key);
#ifdef __aarch64__
    if (key->use_uadk) {
        uadk_rsactx_free(&(key->uadk_st));
    }
#endif
}

int ifm_rsa_private_key_prepare(struct ifm_rsa_private_key *key)
{
#ifdef __aarch64__
    mpz_t result;
    mpz_init(result);
    mpz_mul(result, key->p, key->q);
    size_t bitLength = mpz_sizeinbase(result, 2);
    if (bitLength % KEYSIZEFORMAT != 0) {
        key->use_uadk = false;
    } else {
        key->use_uadk = true;
        if (0 == uadk_rsactx_init(&(key->uadk_st), result)) {
            uadk_rsa_set_prikey(&(key->uadk_st), key->p, key->q, key->a, key->b, key->c);
        } else {
            key->use_uadk = false;
        }
    }
    mpz_clear(result);
#endif
    return rsa_private_key_prepare((struct rsa_private_key *)key);
}

int ifm_rsa_md5_sign(const struct ifm_rsa_private_key *key, struct ifm_md5_ctx *hash, mpz_t signature)
{
#ifdef __aarch64__
    if (key->use_uadk) {
        struct ifm_rsa_private_key *ke;
        ke = (struct ifm_rsa_private_key *)key;
        mpz_t result;
        mpz_init(result);
        mpz_mul(result, key->p, key->q);
        size_t bitLength = mpz_sizeinbase(result, 2);

        int key_size = bitLength >> 3;
        if (uadk_pkcs1_rsa_md5_encode(signature, key_size, hash)) {
            size_t size_s;
            size_s = mpz_sizeinbase(signature, BYTES_SIZE);
            uint8_t *data = (uint8_t *)malloc(size_s);
            mpz_export(data, &size_s, 1, sizeof(uint8_t), 0, 0, signature);

            uadk_rsa_sign(&(ke->uadk_st), data, signature, size_s);
            free(data);
            return 1;
        } else {
            mpz_set_ui(signature, 0);
            return 0;
        }
    } else {
        return rsa_md5_sign((struct rsa_private_key *)key, (struct md5_ctx *)hash, signature);
    }
#else
    return rsa_md5_sign((struct rsa_private_key *)key, (struct md5_ctx *)hash, signature);
#endif
}

int ifm_rsa_md5_verify(const struct ifm_rsa_public_key *key, struct ifm_md5_ctx *hash, const mpz_t signature)
{
#ifdef __aarch64__
    if (key->use_uadk) {
        struct ifm_rsa_public_key *ke;
        ke = (struct ifm_rsa_public_key *)key;
        size_t bitLength = mpz_sizeinbase(key->n, 2);
        int key_size = bitLength >> 3;
        int res;
        mpz_t m;
        mpz_init(m);
        res = (uadk_pkcs1_rsa_md5_encode(m, key_size, hash) && uadk_rsa_verify(&(ke->uadk_st), m, signature));
        mpz_clear(m);
        return res;
    } else {
        return rsa_md5_verify((struct rsa_public_key *)key, (struct md5_ctx *)hash, signature);
    }
#else
    return rsa_md5_verify((struct rsa_public_key *)key, (struct md5_ctx *)hash, signature);
#endif
}

int ifm_rsa_sha1_sign(const struct ifm_rsa_private_key *key, struct sha1_ctx *hash, mpz_t signature)
{
    return rsa_sha1_sign((struct rsa_private_key *)key, hash, signature);
}

int ifm_rsa_sha1_verify(const struct ifm_rsa_public_key *key, struct sha1_ctx *hash, const mpz_t signature)
{
    return rsa_sha1_verify((struct rsa_public_key *)key, hash, signature);
}

int ifm_rsa_sha256_sign(const struct ifm_rsa_private_key *key, struct ifm_sha256_ctx *hash, mpz_t signature)
{
#ifdef __aarch64__
    if (key->use_uadk) {
        struct ifm_rsa_private_key *ke;
        ke = (struct ifm_rsa_private_key *)key;
        mpz_t result;
        mpz_init(result);
        mpz_mul(result, key->p, key->q);
        size_t bitLength = mpz_sizeinbase(result, 2);
        int key_size = bitLength >> 3;
        if (uadk_pkcs1_rsa_sha256_encode(signature, key_size, hash)) {
            size_t size_s;
            size_s = mpz_sizeinbase(signature, BYTES_SIZE);
            uint8_t *data = (uint8_t *)malloc(size_s);
            mpz_export(data, &size_s, 1, sizeof(uint8_t), 0, 0, signature);

            uadk_rsa_sign(&(ke->uadk_st), data, signature, size_s);
            free(data);
            return 1;
        } else {
            mpz_set_ui(signature, 0);
            return 0;
        }
    } else {
        return rsa_sha256_sign((struct rsa_private_key *)key, (struct sha256_ctx *)hash, signature);
    }
#else
    return rsa_sha256_sign((struct rsa_private_key *)key, (struct sha256_ctx *)hash, signature);
#endif
}

int ifm_rsa_sha256_verify(const struct ifm_rsa_public_key *key, struct ifm_sha256_ctx *hash, const mpz_t signature)
{
#ifdef __aarch64__
    if (key->use_uadk) {
        struct ifm_rsa_public_key *ke;
        ke = (struct ifm_rsa_public_key *)key;
        size_t bitLength = mpz_sizeinbase(key->n, 2);
        int key_size = bitLength >> 3;
        int res;
        mpz_t m;
        mpz_init(m);
        res = (uadk_pkcs1_rsa_sha256_encode(m, key_size, hash) && uadk_rsa_verify(&(ke->uadk_st), m, signature));
        mpz_clear(m);
        return res;
    } else {
        return rsa_sha256_verify((struct rsa_public_key *)key, (struct sha256_ctx *)hash, signature);
    }
#else
    return rsa_sha256_verify((struct rsa_public_key *)key, (struct sha256_ctx *)hash, signature);
#endif
}

int ifm_rsa_sha512_sign(const struct ifm_rsa_private_key *key, struct ifm_sha512_ctx *hash, mpz_t signature)
{
#ifdef __aarch64__
    if (key->use_uadk) {
        struct ifm_rsa_private_key *ke;
        ke = (struct ifm_rsa_private_key *)key;
        mpz_t result;
        mpz_init(result);
        mpz_mul(result, key->p, key->q);
        size_t bitLength = mpz_sizeinbase(result, 2);
        int key_size = bitLength >> 3;
        if (uadk_pkcs1_rsa_sha512_encode(signature, key_size, hash)) {
            size_t size_s;
            size_s = mpz_sizeinbase(signature, BYTES_SIZE);
            uint8_t *data = (uint8_t *)malloc(size_s);
            mpz_export(data, &size_s, 1, sizeof(uint8_t), 0, 0, signature);
            uadk_rsa_sign(&(ke->uadk_st), data, signature, size_s);
            free(data);
            return 1;
        } else {
            mpz_set_ui(signature, 0);
            return 0;
        }
    } else {
        return rsa_sha512_sign((struct rsa_private_key *)key, (struct sha512_ctx *)hash, signature);
    }
#else
    return rsa_sha512_sign((struct rsa_private_key *)key, (struct sha512_ctx *)hash, signature);
#endif
}

int ifm_rsa_sha512_verify(const struct ifm_rsa_public_key *key, struct ifm_sha512_ctx *hash, const mpz_t signature)
{
#ifdef __aarch64__
    if (key->use_uadk) {
        struct ifm_rsa_public_key *ke;
        ke = (struct ifm_rsa_public_key *)key;
        size_t bitLength = mpz_sizeinbase(key->n, 2);
        int key_size = bitLength >> 3;
        int res;
        mpz_t m;
        mpz_init(m);
        res = (uadk_pkcs1_rsa_sha512_encode(m, key_size, hash) && uadk_rsa_verify(&(ke->uadk_st), m, signature));
        mpz_clear(m);
        return res;
    } else {
        return rsa_sha512_verify((struct rsa_public_key *)key, (struct sha512_ctx *)hash, signature);
    }
#else
    return rsa_sha512_verify((struct rsa_public_key *)key, (struct sha512_ctx *)hash, signature);
#endif
}

int ifm_rsa_md5_sign_digest(const struct ifm_rsa_private_key *key, const uint8_t *digest, mpz_t s)
{
#ifdef __aarch64__
    if (key->use_uadk) {
        struct ifm_rsa_private_key *ke;
        ke = (struct ifm_rsa_private_key *)key;
        mpz_t result;
        mpz_init(result);
        mpz_mul(result, key->p, key->q);
        size_t bitLength = mpz_sizeinbase(result, 2) + 1;
        int key_size = bitLength >> 3;
        if (uadk_pkcs1_rsa_md5_encode_digest(s, key_size, digest)) {
            size_t size_s;
            size_s = mpz_sizeinbase(s, BYTES_SIZE);
            uint8_t *data = (uint8_t *)malloc(size_s);
            mpz_export(data, &size_s, 1, sizeof(uint8_t), 0, 0, s);
            uadk_rsa_sign(&(ke->uadk_st), data, s, size_s);
            free(data);
            return 1;
        } else {
            mpz_set_ui(s, 0);
            return 0;
        }
    } else {
        return rsa_md5_sign_digest((struct rsa_private_key *)key, digest, s);
    }
#else
    return rsa_md5_sign_digest((struct rsa_private_key *)key, digest, s);
#endif
}

int ifm_rsa_md5_verify_digest(const struct ifm_rsa_public_key *key, const uint8_t *digest, const mpz_t signature)
{
#ifdef __aarch64__
    if (key->use_uadk) {
        struct ifm_rsa_public_key *ke;
        ke = (struct ifm_rsa_public_key *)key;
        size_t bitLength = mpz_sizeinbase(key->n, 2) + 1;
        int key_size = bitLength >> 3;
        int res;
        mpz_t m;
        mpz_init(m);
        res = (uadk_pkcs1_rsa_md5_encode_digest(m, key_size, digest) && uadk_rsa_verify(&(ke->uadk_st), m, signature));
        mpz_clear(m);
        return res;
    } else {
        return rsa_md5_verify_digest((struct rsa_public_key *)key, digest, signature);
    }
#else
    return rsa_md5_verify_digest((struct rsa_public_key *)key, digest, signature);
#endif
}

int ifm_rsa_sha1_sign_digest(const struct ifm_rsa_private_key *key, const uint8_t *digest, mpz_t s)
{
    return rsa_sha1_sign_digest((struct rsa_private_key *)key, digest, s);
}

int ifm_rsa_sha1_verify_digest(const struct ifm_rsa_public_key *key, const uint8_t *digest, const mpz_t signature)
{
    return rsa_sha1_verify_digest((struct rsa_public_key *)key, digest, signature);
}

int ifm_rsa_sha256_sign_digest(const struct ifm_rsa_private_key *key, const uint8_t *digest, mpz_t s)
{
#ifdef __aarch64__
    if (key->use_uadk) {
        struct ifm_rsa_private_key *ke;
        ke = (struct ifm_rsa_private_key *)key;
        mpz_t result;
        mpz_init(result);
        mpz_mul(result, key->p, key->q);
        size_t bitLength = mpz_sizeinbase(result, 2) + 1;
        int key_size = bitLength >> 3;
        if (uadk_pkcs1_rsa_sha256_encode_digest(s, key_size, digest)) {
            size_t size_s;
            size_s = mpz_sizeinbase(s, BYTES_SIZE);
            uint8_t *data = (uint8_t *)malloc(size_s);
            mpz_export(data, &size_s, 1, sizeof(uint8_t), 0, 0, s);
            uadk_rsa_sign(&(ke->uadk_st), data, s, size_s);
            free(data);
            return 1;
        } else {
            mpz_set_ui(s, 0);
            return 0;
        }
    } else {
        return rsa_sha256_sign_digest((struct rsa_private_key *)key, digest, s);
    }
#else
    return rsa_sha256_sign_digest((struct rsa_private_key *)key, digest, s);
#endif
}

int ifm_rsa_sha256_verify_digest(const struct ifm_rsa_public_key *key, const uint8_t *digest, const mpz_t signature)
{
#ifdef __aarch64__
    if (key->use_uadk) {
        struct ifm_rsa_public_key *ke;
        ke = (struct ifm_rsa_public_key *)key;
        size_t bitLength = mpz_sizeinbase(key->n, 2) + 1;
        int key_size = bitLength >> 3;
        int res;
        mpz_t m;
        mpz_init(m);
        res = (uadk_pkcs1_rsa_sha256_encode_digest(m, key_size, digest) &&
               uadk_rsa_verify(&(ke->uadk_st), m, signature));
        mpz_clear(m);
        return res;
    } else {
        return rsa_sha256_verify_digest((struct rsa_public_key *)key, digest, signature);
    }
#else
    return rsa_sha256_verify_digest((struct rsa_public_key *)key, digest, signature);
#endif
}

int ifm_rsa_sha512_sign_digest(const struct ifm_rsa_private_key *key, const uint8_t *digest, mpz_t s)
{
#ifdef __aarch64__
    if (key->use_uadk) {
        struct ifm_rsa_private_key *ke;
        ke = (struct ifm_rsa_private_key *)key;
        mpz_t result;
        mpz_init(result);
        mpz_mul(result, key->p, key->q);
        size_t bitLength = mpz_sizeinbase(result, 2) + 1;
        int key_size = bitLength >> 3;
        if (uadk_pkcs1_rsa_sha512_encode_digest(s, key_size, digest)) {
            size_t size_s;
            size_s = mpz_sizeinbase(s, BYTES_SIZE);
            uint8_t *data = (uint8_t *)malloc(size_s);
            mpz_export(data, &size_s, 1, sizeof(uint8_t), 0, 0, s);
            uadk_rsa_sign(&(ke->uadk_st), data, s, size_s);
            free(data);
            return 1;
        } else {
            mpz_set_ui(s, 0);
            return 0;
        }
    } else {
        return rsa_sha512_sign_digest((struct rsa_private_key *)key, digest, s);
    }
#else
    return rsa_sha512_sign_digest((struct rsa_private_key *)key, digest, s);
#endif
}

int ifm_rsa_sha512_verify_digest(const struct ifm_rsa_public_key *key, const uint8_t *digest, const mpz_t signature)
{
#ifdef __aarch64__
    if (key->use_uadk) {
        struct ifm_rsa_public_key *ke;
        ke = (struct ifm_rsa_public_key *)key;
        size_t bitLength = mpz_sizeinbase(key->n, 2) + 1;
        int key_size = bitLength >> 3;
        int res;
        mpz_t m;
        mpz_init(m);
        res = (uadk_pkcs1_rsa_sha512_encode_digest(m, key_size, digest) &&
               uadk_rsa_verify(&(ke->uadk_st), m, signature));
        mpz_clear(m);
        return res;
    } else {
        return rsa_sha512_verify_digest((struct rsa_public_key *)key, digest, signature);
    }
#else
    return rsa_sha512_verify_digest((struct rsa_public_key *)key, digest, signature);
#endif
}

/* Key generation */

/* Note that the key structs must be initialized first. */
int ifm_rsa_generate_keypair(struct ifm_rsa_public_key *pub, struct ifm_rsa_private_key *key,

                             void *random_ctx, nettle_random_func *random, void *progress_ctx,
                             nettle_progress_func *progress,

                             /* Desired size of modulo, in bits */
                             unsigned n_size,

                             /* Desired size of public exponent, in bits. If
                              * zero, the passed in value pub->e is used. */
                             unsigned e_size)
{
#ifdef __aarch64__
    if (pub->use_uadk && key->use_uadk) {
        return uadk_rsa_keygen(pub, key, n_size, e_size);
    } else {
        return rsa_generate_keypair((struct rsa_public_key *)pub, (struct rsa_private_key *)key, random_ctx, random,
                                    progress_ctx, progress, n_size, e_size);
    }
#else
    return rsa_generate_keypair((struct rsa_public_key *)pub, (struct rsa_private_key *)key, random_ctx, random,
                                progress_ctx, progress, n_size, e_size);
#endif
}