/*
 * src/v3_internal.h - v3 内核内部头文件
 *
 * 定义核心上下文结构，并声明各模块间共享的内部函数。
 */

#ifndef V3_INTERNAL_H
#define V3_INTERNAL_H

#include "include/v3_core.h"
#include "include/v3_platform.h"
#include "include/v3_config.h"
#include <sodium.h> // 确保已安装 libsodium-dev 或等效包

// --- Pacing 内部定义 ---
typedef struct {
    uint64_t    target_bps;
    double      tokens;
    double      tokens_per_ns;
    uint64_t    last_refill_ns;
    double      max_burst_tokens;
} v3_pacer_t;

// --- FEC 内部定义 ---
#define FEC_MAX_GROUP_SIZE 20
#define FEC_DECODE_CACHE_SIZE 64

// FEC 包头
#pragma pack(push, 1)
typedef struct {
    uint32_t group_id;
    uint8_t  shard_index;
    uint8_t  data_shards;
    uint8_t  parity_shards;
    uint8_t  reserved;
} v3_fec_header_t;
#pragma pack(pop)

// FEC 解码组
typedef struct {
    uint32_t group_id;
    uint64_t last_seen_ns;
    uint8_t  data_shards;
    uint8_t  parity_shards;
    uint16_t shard_len;
    uint8_t  shards[FEC_MAX_GROUP_SIZE][V3_PACKET_BUFFER_SIZE];
    bool     present[FEC_MAX_GROUP_SIZE];
    int      present_count;
    bool     recovered;
} v3_fec_decode_group_t;

// FEC 编码组
typedef struct {
    uint32_t group_id;
    int      count;
    uint8_t  data[FEC_MAX_GROUP_SIZE][V3_PACKET_BUFFER_SIZE];
    size_t   lens[FEC_MAX_GROUP_SIZE];
} v3_fec_encode_group_t;

typedef struct {
    v3_fec_encode_group_t   encode_group;
    v3_fec_decode_group_t   decode_cache[FEC_DECODE_CACHE_SIZE];
} v3_fec_context_t;


// --- 核心上下文 ---
// 这个结构体聚合了所有模块的状态
struct v3_context_s {
    v3_conn_state_t state;
    v3_mutex_t      mutex;

    // 配置
    v3_server_config_t server_config;
    v3_fec_config_t    fec_config;
    v3_pacing_config_t pacing_config;

    // 网络
    v3_socket_t     sock;
    v3_thread_t     recv_thread;
    volatile bool   running;

    // 会话
    uint64_t        session_token;
    uint8_t         master_key[V3_KEY_SIZE];

    // 统计
    v3_stats_t      stats;

    // 回调
    v3_recv_callback_t recv_callback;
    void*              recv_userdata;
    v3_state_callback_t state_callback;
    void*               state_userdata;

    // 子模块上下文
    v3_pacer_t       pacer;
    v3_fec_context_t fec_ctx;
};

// --- 内部函数声明 (模块间调用) ---
void v3_set_state(v3_context_t *ctx, v3_conn_state_t new_state);
int v3_connection_send_raw(v3_context_t *ctx, const uint8_t *data, size_t len);
void v3_connection_handle_unpacked(v3_context_t *ctx, uint16_t stream_id, const uint8_t* payload, int payload_len);

// 声明加密函数
uint32_t v3_derive_magic(const uint8_t key[V3_KEY_SIZE], uint64_t window);
bool v3_verify_magic(const uint8_t key[V3_KEY_SIZE], uint32_t received_magic);
v3_error_t v3_aead_encrypt(const uint8_t key[V3_KEY_SIZE], const uint8_t nonce[V3_NONCE_SIZE],
                           const uint8_t *aad, size_t aad_len,
                           const uint8_t *plaintext, size_t pt_len,
                           uint8_t *ciphertext, uint8_t tag[V3_TAG_SIZE]);
v3_error_t v3_aead_decrypt(const uint8_t key[V3_KEY_SIZE], const uint8_t nonce[V3_NONCE_SIZE],
                           const uint8_t *aad, size_t aad_len,
                           const uint8_t *ciphertext, size_t ct_len,
                           const uint8_t tag[V3_TAG_SIZE],
                           uint8_t *plaintext);
int v3_protocol_pack(v3_context_t *ctx, uint16_t stream_id, const uint8_t *payload, size_t payload_len, uint8_t *out_buf, size_t out_buflen);
int v3_protocol_unpack(v3_context_t *ctx, const uint8_t *packet, size_t packet_len, uint16_t *stream_id, uint8_t *out_payload, size_t out_buflen);

#endif // V3_INTERNAL_H
