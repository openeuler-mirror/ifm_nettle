/******************************************************************************
 * Copyright (c) Huawei Technologies Co., Ltd. 2020. All rights reserved.
 *
 * Authors:
 * YutingNie yvettemisaki@outlook.com 
 * YihuiTan 202121632838@smail.edu.cn.com
 * xinghailiao xinghailiao@smail.xtu.edu.cn
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
#include <stdio.h>
#include "gcrypt.h"
#include "gcry_uadk_sha2.h"
#include "gcry_uadk_aes.h"

gcry_error_t ifm_gcry_cipher_open(gcry_uadk_aes_hd_t *handle, int algo, int mode, unsigned int flags)
{
    return gcry_uadk_cipher_open(handle,  algo,  mode, flags);
}

gcry_error_t ifm_gcry_cipher_setkey(gcry_uadk_aes_hd_t hd, const void *key, size_t keylen)
{
    return gcry_uadk_cipher_setkey(hd, key, keylen);
}

gcry_error_t ifm_gcry_cipher_setiv(gcry_uadk_aes_hd_t hd, const void *iv, size_t ivlen)
{
    return gcry_uadk_cipher_setiv(hd, iv, ivlen);
}

gcry_error_t ifm_gcry_cipher_encrypt(gcry_uadk_aes_hd_t h, void *out, size_t outsize, const void *in, size_t inlen)
{
    return gcry_uadk_cipher_encrypt(h, out, outsize, in, inlen);
}

gcry_error_t ifm_gcry_cipher_decrypt(gcry_uadk_aes_hd_t h, void *out, size_t outsize, const void *in, size_t inlen)
{
    return gcry_uadk_cipher_decrypt(h, out, outsize, in, inlen);
}

size_t ifm_gcry_cipher_get_algo_keylen(int algo)
{
    return gcry_cipher_get_algo_keylen(algo);
}

size_t ifm_gcry_cipher_get_algo_blklen(int algo)
{
    return gcry_cipher_get_algo_blklen(algo);
}

void ifm_gcry_cipher_close(gcry_uadk_aes_hd_t h)
{
    return gcry_uadk_cipher_close(h);
}

gcry_error_t ifm_gcry_cipher_ctl(gcry_uadk_aes_hd_t hd, int cmd, void *buffer, size_t buflen)
{
    return gcry_uadk_cipher_ctl(hd, cmd, buffer, buflen);
}

gcry_error_t ifm_gcry_cipher_gettag(gcry_uadk_aes_hd_t hd, void *outtag, size_t taglen)
{
    return gcry_uadk_cipher_gettag(hd, outtag, taglen);
}

gcry_error_t ifm_gcry_cipher_checktag(gcry_uadk_aes_hd_t hd, const void *intag, size_t taglen)
{
    return gcry_uadk_cipher_checktag(hd, intag, taglen);
}

gpg_error_t ifm_gcry_cipher_setctr(gcry_uadk_aes_hd_t hd, const void *ctr, size_t ctrlen)
{
    return gcry_cipher_setctr(hd->gcry_hd_t, ctr, ctrlen);
}

gcry_error_t ifm_gcry_md_open(gcry_uadk_sha2_hd_t *h, int algo, unsigned int flags)
{
    return gcry_uadk_md_open(h, algo, flags);
}

gcry_error_t ifm_gcry_md_algo_info(int algo, int what, void *buffer, size_t *nbytes)
{
    return gcry_md_algo_info(algo, what, buffer, nbytes);
    // 该代码用于测试验证是否调用适配层的接口。
}

gcry_error_t ifm_gcry_md_setkey(gcry_uadk_sha2_hd_t hd, const void *key, size_t keylen) {
    return gcry_uadk_md_setkey(hd, key, keylen);
}

/* Asymmetric encryption functions. */
gcry_error_t ifm_gcry_pk_verify(gcry_sexp_t sigval, gcry_sexp_t data, gcry_sexp_t pkey)
{
    return gcry_pk_verify(sigval, data, pkey);
}

gcry_error_t ifm_gcry_pk_sign(gcry_sexp_t *result, gcry_sexp_t data, gcry_sexp_t skey)
{
    return gcry_pk_sign(result, data, skey);
}

gcry_error_t ifm_gcry_pk_encrypt(gcry_sexp_t *result, gcry_sexp_t data, gcry_sexp_t pkey)
{
    return gcry_pk_encrypt(result, data, pkey);
}

gcry_error_t ifm_gcry_pk_decrypt(gcry_sexp_t *result, gcry_sexp_t data, gcry_sexp_t skey)
{
    return gcry_pk_decrypt(result, data, skey);
}

gcry_error_t ifm_gcry_pk_testkey(gcry_sexp_t key)
{
    return gcry_pk_testkey(key);
}

gcry_error_t ifm_gcry_pk_genkey(gcry_sexp_t *r_key, gcry_sexp_t s_parms)
{
    return gcry_pk_genkey(r_key, s_parms);
}

gcry_error_t ifm_gcry_pk_ctl(int cmd, void *buffer, size_t buflen)
{
    return gcry_pk_ctl(cmd, buffer, buflen);
}

const char *ifm_gcry_pk_algo_name(int algorithm)
{
    return gcry_pk_algo_name(algorithm);
}

int ifm_gcry_pk_map_name(const char* name)
{
    return gcry_pk_map_name(name);
}

unsigned int ifm_gcry_pk_get_nbits(gcry_sexp_t key)
{
    return gcry_pk_get_nbits(key);
}

unsigned char *ifm_gcry_pk_get_keygrip(gcry_sexp_t key, unsigned char *array)
{
    return gcry_pk_get_keygrip(key, array);
}

const char *ifm_gcry_pk_get_curve(gcry_sexp_t key, int iterator, unsigned int *r_nbits)
{
    return gcry_pk_get_curve(key, iterator, r_nbits);
}

gcry_sexp_t ifm_gcry_pk_get_param(int algo, const char *name)
{
    return gcry_pk_get_param(algo, name);
}

gcry_error_t ifm_gcry_pubkey_get_sexp(gcry_sexp_t *r_sexp, int mode, gcry_ctx_t ctx)
{
    return gcry_pubkey_get_sexp(r_sexp, mode, ctx);
}

gcry_error_t ifm_gcry_md_enable(gcry_uadk_sha2_hd_t hd, int algo)
{
    return gcry_uadk_md_enable(hd, algo);
}

void ifm_gcry_md_write(gcry_uadk_sha2_hd_t hd, const void *buffer, size_t length)
{
    gcry_uadk_md_write(hd, buffer, length);
}

unsigned char *ifm_gcry_md_read(gcry_uadk_sha2_hd_t hd, int algo)
{
    return gcry_uadk_md_read(hd, algo);
}

void ifm_gcry_md_close(gcry_uadk_sha2_hd_t hd)
{
    gcry_uadk_md_close(hd);
}

void ifm_gcry_md_hash_buffer(int algo, void *digest,
                             const void *buffer, size_t length)
{
    gcry_md_hash_buffer(algo, digest, buffer, length);
}

gcry_err_code_t ifm_gcry_md_copy(gcry_uadk_sha2_hd_t *dst, gcry_uadk_sha2_hd_t src)
{
    return gcry_uadk_md_copy(dst, src);
}

void ifm_gcry_md_reset(gcry_uadk_sha2_hd_t hd) {
    gcry_uadk_md_reset(hd);
}
