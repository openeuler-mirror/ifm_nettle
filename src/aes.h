#ifndef IFM_NETTLE_AES_H_INCLUDED
#define IFM_NETTLE_AES_H_INCLUDED

#ifdef __cplusplus
extern "C" {
#endif

#ifndef NETTLE_AES_H_INCLUDED
#define aes128_set_encrypt_key ifm_aes128_set_encrypt_key
#define aes192_set_encrypt_key ifm_aes192_set_encrypt_key
#define aes256_set_encrypt_key ifm_aes256_set_encrypt_key
#define aes128_encrypt ifm_aes128_encrypt
#define aes192_encrypt ifm_aes192_encrypt
#define aes256_encrypt ifm_aes256_encrypt
#define aes128_set_decrypt_key ifm_aes128_set_decrypt_key
#define aes192_set_decrypt_key ifm_aes192_set_decrypt_key
#define aes256_set_decrypt_key ifm_aes256_set_decrypt_key
#define aes128_decrypt ifm_aes128_decrypt
#define aes192_decrypt ifm_aes192_decrypt
#define aes256_decrypt ifm_aes256_decrypt
#define aes128_invert_key ifm_aes128_invert_key
#define aes192_invert_key ifm_aes192_invert_key
#define aes256_invert_key ifm_aes256_invert_key
#endif

#define _AES128_ROUNDS 10
#define _AES192_ROUNDS 12
#define _AES256_ROUNDS 14

    struct ifm_aes128_ctx
    {
        uint32_t keys[4 * (_AES128_ROUNDS + 1)];
    };
    struct ifm_aes192_ctx
    {
        uint32_t keys[4 * (_AES192_ROUNDS + 1)];
    };

    struct ifm_aes256_ctx
    {
        uint32_t keys[4 * (_AES256_ROUNDS + 1)];
    };

    void ifm_aes128_set_encrypt_key(struct ifm_aes128_ctx* ctx, const uint8_t* key);
    void ifm_aes192_set_encrypt_key(struct ifm_aes192_ctx* ctx, const uint8_t* key);
    void ifm_aes256_set_encrypt_key(struct ifm_aes256_ctx* ctx, const uint8_t* key);

    void ifm_aes128_encrypt(const struct ifm_aes128_ctx* ctx, size_t length, uint8_t* dst, const uint8_t* src);
    void ifm_aes192_encrypt(const struct ifm_aes192_ctx* ctx, size_t length, uint8_t* dst, const uint8_t* src);
    void ifm_aes256_encrypt(const struct ifm_aes256_ctx* ctx, size_t length, uint8_t* dst, const uint8_t* src);

    void ifm_aes128_set_decrypt_key(struct ifm_aes128_ctx* ctx, const uint8_t* key);
    void ifm_aes192_set_decrypt_key(struct ifm_aes192_ctx* ctx, const uint8_t* key);
    void ifm_aes256_set_decrypt_key(struct ifm_aes256_ctx* ctx, const uint8_t* key);

    void ifm_aes128_decrypt(const struct ifm_aes128_ctx* ctx, size_t length, uint8_t* dst, const uint8_t* src);
    void ifm_aes192_decrypt(const struct ifm_aes192_ctx* ctx, size_t length, uint8_t* dst, const uint8_t* src);
    void ifm_aes256_decrypt(const struct ifm_aes256_ctx* ctx, size_t length, uint8_t* dst, const uint8_t* src);

    void ifm_aes128_invert_key(struct ifm_aes128_ctx* dst, const struct ifm_aes128_ctx* src);
    void ifm_aes192_invert_key(struct ifm_aes192_ctx* dst, const struct ifm_aes192_ctx* src);
    void ifm_aes256_invert_key(struct ifm_aes256_ctx* dst, const struct ifm_aes256_ctx* src);

#ifdef __cplusplus
}
#endif

#endif /* IFM_NETTLE_AES_H_INCLUDED */
