/******************************************************************************
 * ifm_nettle-rsa_utils.c: util functions for rsa keygen
 *
 * Copyright (c) Huawei Technologies Co., Ltd. 2020. All rights reserved.
 *
 * Authors:
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
#ifdef __aarch64__
#include <openssl/err.h>
#include <openssl/rsa.h>

#define KAE_FAIL (-1)
#define KAE_SUCCESS 0
#define REDO (-2)
#define PRIMECOUNT 2
#endif

#ifdef __aarch64__
void set_primes(int i, BIGNUM *rsa_p, BIGNUM *rsa_q, BIGNUM **prime)
{
    if (i == 0) {
        *prime = rsa_p;
    } else {
        *prime = rsa_q;
    }
    BN_set_flags(*prime, BN_FLG_CONSTTIME);
}

int check_primeequal(int i, BIGNUM *rsa_p, BIGNUM *rsa_q, BIGNUM *prime)
{
    int j;
    for (j = 0; j < i; j++) {
        BIGNUM *prev_prime = NULL;
        if (j == 0) {
            prev_prime = rsa_p;
        }
        prev_prime = rsa_p;
        if (BN_cmp(prime, prev_prime) == 0) {
            return KAE_FAIL;
        }
    }
    return KAE_SUCCESS;
}

int check_prime_useful(int *n, BIGNUM *prime, BIGNUM *r1, BIGNUM *r2, BIGNUM *e_value, BN_CTX *ctx)
{
    if (BN_sub(r2, prime, BN_value_one()) == 0) {
        return -1;
    }
    ERR_set_mark();
    BN_set_flags(r2, BN_FLG_CONSTTIME);
    if (BN_mod_inverse(r1, r2, e_value, ctx) != NULL) {
        return 1;
    }
    unsigned long error = ERR_peek_last_error();
    if (ERR_GET_LIB(error) == ERR_LIB_BN && ERR_GET_REASON(error) == BN_R_NO_INVERSE) {
        ERR_pop_to_mark();
    } else {
        return -1;
    }
    return 0;
}

int hpre_get_prime_once(int i, const int *bitsr, int *n, BIGNUM *prime, BIGNUM *rsa_p, BIGNUM *rsa_q, BIGNUM *r1,
                        BIGNUM *r2, BIGNUM *e_value, BN_CTX *ctx)
{
    int ret = KAE_FAIL;
    int flag = 1;
    while (flag == 1) {
        if (BN_generate_prime_ex(prime, bitsr[i], 0, (const BIGNUM *)NULL, (const BIGNUM *)NULL, NULL) == 0) {
            return KAE_FAIL;
        }
        /*
         * prime should not be equal to p, q, r_3...
         * (those primes prior to this one)
         */
        if (check_primeequal(i, rsa_p, rsa_q, prime) == KAE_FAIL) {
            continue;
        }
        ret = check_prime_useful(n, prime, r1, r2, e_value, ctx);
        if (ret == KAE_FAIL) {
            return KAE_FAIL;
        } else if (ret == 1) {
            flag = 0;
            break;
        }
    }
    return ret;
}

int prime_mul_res(int i, BIGNUM *rsa_p, BIGNUM *rsa_q, BIGNUM *r1, BN_CTX *ctx)
{
    if (i == 1) {
        /* we get at least 2 primes */
        if (BN_mul(r1, rsa_p, rsa_q, ctx) == 0) {
            return -1;
        }
    } else {
        /* i == 0, do nothing */
        return 1;
    }
    return KAE_SUCCESS;
}

int check_prime_sufficient(int *i, int *bitsr, int *bitse, int *n, BIGNUM *rsa_p, BIGNUM *rsa_q, BIGNUM *r1,
                           BIGNUM *r2, BN_CTX *ctx)
{
    BN_ULONG bitst;
    static int retries = 0;

    /* calculate n immediately to see if it's sufficient */
    int ret = prime_mul_res(*i, rsa_p, rsa_q, r1, ctx);
    if (ret != KAE_SUCCESS) {
        return ret;
    }
    if (BN_rshift(r2, r1, *bitse - 4) == 0) { // right shift *bitse - 4
        return -1;
    }
    bitst = BN_get_word(r2);
    if (bitst < 0x9 || bitst > 0xF) {
        *bitse -= bitsr[*i];
        if (retries == 4) { // retries max is 4
            *i = -1;
            *bitse = 0;
            retries = 0;
            return 1;
        }
        retries++;
        return REDO;
    }
    retries = 0;
    return 0;
}

void switch_p_q(BIGNUM *rsa_p, BIGNUM *rsa_q, BIGNUM *p, BIGNUM *q)
{
    BIGNUM *tmp = (BIGNUM *)NULL;
    BIGNUM *temp_p = rsa_p;
    BIGNUM *temp_q = rsa_q;
    if (BN_cmp(rsa_p, rsa_q) < 0) {
        tmp = temp_p;
        temp_p = temp_q;
        temp_q = tmp;
    }
    BN_copy(q, temp_q);
    BN_copy(p, temp_p);
}

int hpre_rsa_primegen(int bits, BIGNUM *e_value, BIGNUM *p, BIGNUM *q, BN_GENCB *cb)
{
    int primes = 2;
    int n = 0;
    int bitse = 0;
    int i = 0;
    int bitsr[2]; // 2 bits
    BN_CTX *ctx;
    ctx = (BN_CTX *)NULL;
    BIGNUM *r1;
    r1 = (BIGNUM *)NULL;
    BIGNUM *r2;
    r2 = (BIGNUM *)NULL;
    BIGNUM *prime;
    prime = (BIGNUM *)NULL;
    BIGNUM *rsa_p;
    BIGNUM *rsa_q;
    BIGNUM *tmp;

    tmp = BN_new();
    ctx = BN_CTX_new();
    BN_CTX_start(ctx);
    r1 = BN_CTX_get(ctx);
    r2 = BN_CTX_get(ctx);
    rsa_p = BN_CTX_get(ctx);
    rsa_q = BN_CTX_get(ctx);
    BN_free(tmp);
    for (int t = 0; t < PRIMECOUNT; t++) {
        bitsr[t] = 0;
    }
    /* divide bits into 'primes' pieces evenly */
    int quo = bits / primes;
    bitsr[0] = quo;
    bitsr[1] = quo;
    /* generate p, q and other primes (if any) */
    for (i = 0; i < primes; i++) {
        int i_temp = i;
        set_primes(i, rsa_p, rsa_q, &prime);
    redo:
        if (hpre_get_prime_once(i, bitsr, &n, prime, rsa_p, rsa_q, r1, r2, e_value, ctx) == KAE_FAIL) {
            return 0;
        }
        bitse += bitsr[i];
        int ret = check_prime_sufficient(&i_temp, bitsr, &bitse, &n, rsa_p, rsa_q, r1, r2, ctx);
        i = i_temp;
        if (ret == -1) {
            return 0;
        } else if (ret == REDO) { // ret = -2 goto redo
            goto redo;
        } else if (ret == 1) {
            continue;
        }
    }
    switch_p_q(rsa_p, rsa_q, p, q);
    BN_CTX_end(ctx);
    return 1;
}
#endif