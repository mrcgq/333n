/*
 * src/v3_crypto.c - v3 加密层实现
 *
 * 封装 libsodium, 提供 Magic 派生、AEAD 加密解密等功能。
 */
#define V3_BUILDING_CORE
#include "v3_internal.h"
#include <time.h>

// 初始化加密库
v3_error_t v3_crypto_init(void) {
    if (sodium_init() < 0) {
        return V3_ERR_INIT_FAILED;
    }
    return V3_OK;
}

// 派生 Magic (必须与服务端完全一致)
uint32_t v3_derive_magic(const uint8_t key[V3_KEY_SIZE], uint64_t window) {
    uint8_t input[40];
    uint8_t hash[32];
    uint32_t magic;

    memcpy(input, key, 32);
    // 小端序写入 window
    for (int i = 0; i < 8; i++) {
        input[32 + i] = (window >> (i * 8)) & 0xFF;
    }

    // 使用 BLAKE2b (libsodium 的默认通用 hash)
    crypto_generichash(hash, sizeof(hash), input, sizeof(input), NULL, 0);
    memcpy(&magic, hash, 4);
    return magic;
}

// 验证 Magic (允许容差)
bool v3_verify_magic(const uint8_t key[V3_KEY_SIZE], uint32_t received_magic) {
    uint64_t current_window = time(NULL) / V3_MAGIC_WINDOW_SEC;
    for (int i = -V3_MAGIC_TOLERANCE; i <= V3_MAGIC_TOLERANCE; i++) {
        if (received_magic == v3_derive_magic(key, current_window + i)) {
            return true;
        }
    }
    return false;
}

// AEAD 加密
v3_error_t v3_aead_encrypt(const uint8_t key[V3_KEY_SIZE], const uint8_t nonce[V3_NONCE_SIZE],
                           const uint8_t *aad, size_t aad_len,
                           const uint8_t *plaintext, size_t pt_len,
                           uint8_t *ciphertext, uint8_t tag[V3_TAG_SIZE]) {
    unsigned long long ct_len;
    uint8_t combined_ct[V3_MAX_PACKET];

    if (crypto_aead_chacha20poly1305_ietf_encrypt(
            combined_ct, &ct_len,
            plaintext, pt_len,
            aad, aad_len,
            NULL, nonce, key) != 0) {
        return V3_ERR_CRYPTO;
    }
    
    // libsodium 输出的密文是 [ciphertext | tag]，我们需要将其分开
    memcpy(ciphertext, combined_ct, pt_len);
    memcpy(tag, combined_ct + pt_len, V3_TAG_SIZE);
    
    return V3_OK;
}

// AEAD 解密
v3_error_t v3_aead_decrypt(const uint8_t key[V3_KEY_SIZE], const uint8_t nonce[V3_NONCE_SIZE],
                           const uint8_t *aad, size_t aad_len,
                           const uint8_t *ciphertext, size_t ct_len,
                           const uint8_t tag[V3_TAG_SIZE],
                           uint8_t *plaintext) {
    unsigned long long pt_len;
    uint8_t combined_ct[V3_MAX_PACKET];

    // 将 ciphertext 和 tag 组合起来，以符合 libsodium 的输入格式
    memcpy(combined_ct, ciphertext, ct_len);
    memcpy(combined_ct + ct_len, tag, V3_TAG_SIZE);

    if (crypto_aead_chacha20poly1305_ietf_decrypt(
            plaintext, &pt_len,
            NULL,
            combined_ct, ct_len + V3_TAG_SIZE,
            aad, aad_len,
            nonce, key) != 0) {
        return V3_ERR_DECRYPT_FAILED;
    }

    return V3_OK;
}
