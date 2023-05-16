#include "nettle/aes.h"
#include "aes.h"

void ifm_aes128_set_encrypt_key(struct ifm_aes128_ctx* ctx, const uint8_t* key)
{
    aes128_set_encrypt_key((struct aes128_ctx*)ctx, key);
}

void ifm_aes128_set_decrypt_key(struct ifm_aes128_ctx* ctx, const uint8_t* key)
{
    aes128_set_decrypt_key((struct aes128_ctx*)ctx, key);
}

void ifm_aes128_invert_key(struct ifm_aes128_ctx* dst, const struct ifm_aes128_ctx* src)
{
    aes128_invert_key((struct aes128_ctx*)dst, (const struct aes128_ctx*)src);
}

void ifm_aes128_encrypt(const struct ifm_aes128_ctx* ctx, size_t length, uint8_t* dst, const uint8_t* src)
{
    aes128_encrypt((const struct aes128_ctx*)ctx, length, dst, src);
}

void ifm_aes128_decrypt(const struct ifm_aes128_ctx* ctx, size_t length, uint8_t* dst, const uint8_t* src)
{
    aes128_decrypt((const struct aes128_ctx*)ctx, length, dst, src);
}

void ifm_aes192_set_encrypt_key(struct ifm_aes192_ctx* ctx, const uint8_t* key)
{
    aes192_set_encrypt_key((struct aes192_ctx*)ctx, key);
}

void ifm_aes192_set_decrypt_key(struct ifm_aes192_ctx* ctx, const uint8_t* key)
{
    aes192_set_decrypt_key((struct aes192_ctx*)ctx, key);
}

void ifm_aes192_invert_key(struct ifm_aes192_ctx* dst, const struct ifm_aes192_ctx* src)
{
    aes192_invert_key((struct aes192_ctx*)dst, (const struct aes192_ctx*)src);
}

void ifm_aes192_encrypt(const struct ifm_aes192_ctx* ctx, size_t length, uint8_t* dst, const uint8_t* src)
{
    aes192_encrypt((const struct aes192_ctx*)ctx, length, dst, src);
}

void ifm_aes192_decrypt(const struct ifm_aes192_ctx* ctx, size_t length, uint8_t* dst, const uint8_t* src)
{
    aes192_decrypt((const struct aes192_ctx*)ctx, length, dst, src);
}

void ifm_aes256_set_encrypt_key(struct ifm_aes256_ctx* ctx, const uint8_t* key)
{
    aes256_set_encrypt_key((struct aes256_ctx*)ctx, key);
}

void ifm_aes256_set_decrypt_key(struct ifm_aes256_ctx* ctx, const uint8_t* key)
{
    aes256_set_decrypt_key((struct aes256_ctx*)ctx, key);
}

void ifm_aes256_invert_key(struct ifm_aes256_ctx* dst, const struct ifm_aes256_ctx* src)
{
    aes256_invert_key((struct aes256_ctx*)dst, (const struct aes256_ctx*)src);
}

void ifm_aes256_encrypt(const struct ifm_aes256_ctx* ctx, size_t length, uint8_t* dst, const uint8_t* src)
{
    aes256_encrypt((const struct aes256_ctx*)ctx, length, dst, src);
}

void ifm_aes256_decrypt(const struct ifm_aes256_ctx* ctx, size_t length, uint8_t* dst, const uint8_t* src)
{
    aes256_decrypt((const struct aes256_ctx*)ctx, length, dst, src);
}
