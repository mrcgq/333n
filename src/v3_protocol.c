/*
 * src/v3_protocol.c - v3 协议封包/解包层实现
 *
 * 负责将用户数据打包成 v3 UDP 数据包，或反向解析。
 */
#define V3_BUILDING_CORE
#include "v3_internal.h"
#include <time.h>

// 封装一个 v3 数据包
int v3_protocol_pack(v3_context_t *ctx, uint16_t stream_id, const uint8_t *payload, size_t payload_len, uint8_t *out_buf, size_t out_buflen) {
    if (out_buflen < V3_HEADER_SIZE + payload_len) return V3_ERR_NO_MEMORY;

    v3_header_t *header = (v3_header_t*)out_buf;
    uint8_t *ciphertext_payload = out_buf + V3_HEADER_SIZE;

    // 1. 填充元数据
    v3_meta_t meta = {
        .session_token = ctx->session_token,
        .intent_id = 0, // 客户端通常为0
        .stream_id = stream_id,
        .flags = 0,
        .reserved = 0,
    };
    
    // 2. 生成 Header 的随机和时间相关部分
    uint64_t window = time(NULL) / V3_MAGIC_WINDOW_SEC;
    header->magic_derived = v3_derive_magic(ctx->master_key, window);
    randombytes_buf(header->nonce, V3_NONCE_SIZE);
    header->early_len = 0; // 简单起见，暂不使用 early data
    header->pad = 0;

    // 3. 构建 AAD (Additional Authenticated Data)
    uint8_t aad[8];
    memcpy(aad + 0, &header->early_len, 2);
    memcpy(aad + 2, &header->pad, 2);
    memcpy(aad + 4, &header->magic_derived, 4);

    // 4. 加密元数据块
    v3_error_t err = v3_aead_encrypt(ctx->master_key, header->nonce, aad, sizeof(aad),
                                     (const uint8_t*)&meta, sizeof(meta),
                                     header->enc_block, header->tag);
    if (err != V3_OK) return err;
    
    // 5. 将 payload 直接复制到头部之后 (v3 协议 payload 不加密)
    memcpy(ciphertext_payload, payload, payload_len);
    
    return V3_HEADER_SIZE + payload_len;
}

// 解封一个 v3 数据包
int v3_protocol_unpack(v3_context_t *ctx, const uint8_t *packet, size_t packet_len, uint16_t *stream_id, uint8_t *out_payload, size_t out_buflen) {
    if (packet_len < V3_HEADER_SIZE) return V3_ERR_INVALID_PARAM;

    const v3_header_t *header = (const v3_header_t*)packet;
    const uint8_t *payload = packet + V3_HEADER_SIZE;
    size_t payload_len = packet_len - V3_HEADER_SIZE;

    // 1. 验证 Magic
    if (!v3_verify_magic(ctx->master_key, header->magic_derived)) {
        ctx->stats.magic_failures++;
        return V3_ERR_MAGIC_INVALID;
    }

    // 2. 构建 AAD
    uint8_t aad[8];
    memcpy(aad + 0, &header->early_len, 2);
    memcpy(aad + 2, &header->pad, 2);
    memcpy(aad + 4, &header->magic_derived, 4);

    // 3. 解密元数据块
    v3_meta_t meta;
    v3_error_t err = v3_aead_decrypt(ctx->master_key, header->nonce, aad, sizeof(aad),
                                     header->enc_block, sizeof(header->enc_block),
                                     header->tag, (uint8_t*)&meta);

    if (err != V3_OK) {
        ctx->stats.decrypt_failures++;
        return err;
    }

    // 4. 验证会话令牌 (可选，增强安全性)
    if (meta.session_token != ctx->session_token) {
        // 可以选择忽略或标记为错误
    }

    // 5. 复制 payload
    if (payload_len > out_buflen) return V3_ERR_NO_MEMORY;
    
    memcpy(out_payload, payload, payload_len);
    *stream_id = meta.stream_id;

    return (int)payload_len;
}
