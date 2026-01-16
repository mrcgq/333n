#ifndef V3_CORE_H
#define V3_CORE_H

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

#ifdef _WIN32
#include <windows.h>
#define V3_EXPORT __declspec(dllexport)
#define V3_IMPORT __declspec(dllimport)
#else
#define V3_EXPORT
#define V3_IMPORT
#endif

#ifdef V3_BUILDING_CORE
#define V3_API V3_EXPORT
#else
#define V3_API V3_IMPORT
#endif

// =========================================================
// 版本信息
// =========================================================
#include "version.h"

// =========================================================
// 常量定义（与服务端一致）
// =========================================================
#define V3_DEFAULT_PORT         51820
#define V3_HEADER_SIZE          52          // 与服务端 v3_header_t 一致
#define V3_MAX_PAYLOAD          1400
#define V3_MAX_PACKET           (V3_HEADER_SIZE + V3_MAX_PAYLOAD)
#define V3_MAGIC_WINDOW_SEC     60          // Magic 有效窗口（秒）
#define V3_MAGIC_TOLERANCE      1           // 允许前后各 1 个窗口

#define V3_KEY_SIZE             32          // ChaCha20-Poly1305 密钥长度
#define V3_NONCE_SIZE           12          // Nonce 长度
#define V3_TAG_SIZE             16          // Poly1305 Tag 长度

#define V3_MAX_INTENTS          16
#define V3_MAX_STREAMS          256
#define V3_SESSION_TIMEOUT_SEC  300         // 会话超时（秒）

// =========================================================
// 错误码定义
// =========================================================
typedef enum {
    V3_OK = 0,
    V3_ERR_INVALID_PARAM = -1,
    V3_ERR_NO_MEMORY = -2,
    V3_ERR_NETWORK = -3,
    V3_ERR_CRYPTO = -4,
    V3_ERR_MAGIC_INVALID = -5,
    V3_ERR_DECRYPT_FAILED = -6,
    V3_ERR_TIMEOUT = -7,
    V3_ERR_NOT_CONNECTED = -8,
    V3_ERR_ALREADY_RUNNING = -9,
    V3_ERR_NOT_RUNNING = -10,
    V3_ERR_CONFIG = -11,
    V3_ERR_IPC = -12,
    V3_ERR_PLATFORM = -13,
    V3_ERR_INIT_FAILED = -14,
} v3_error_t;

// =========================================================
// 协议头（与服务端完全一致）
// =========================================================
#pragma pack(push, 1)
typedef struct {
    uint32_t magic_derived;     // 4 bytes: 时间派生的 Magic
    uint8_t  nonce[12];         // 12 bytes: ChaCha20 Nonce
    uint8_t  enc_block[16];     // 16 bytes: 加密的元数据块
    uint8_t  tag[16];           // 16 bytes: Poly1305 Tag
    uint16_t early_len;         // 2 bytes: 早期数据长度（AAD）
    uint16_t pad;               // 2 bytes: 填充
} v3_header_t;
#pragma pack(pop)

// 验证结构体大小
_Static_assert(sizeof(v3_header_t) == V3_HEADER_SIZE, 
               "v3_header_t size mismatch");

// =========================================================
// 元数据结构（加密块内容）
// =========================================================
#pragma pack(push, 1)
typedef struct {
    uint64_t session_token;     // 8 bytes: 会话令牌
    uint16_t intent_id;         // 2 bytes: 意图 ID
    uint16_t stream_id;         // 2 bytes: 流 ID
    uint16_t flags;             // 2 bytes: 标志位
    uint16_t reserved;          // 2 bytes: 保留
} v3_meta_t;
#pragma pack(pop)

_Static_assert(sizeof(v3_meta_t) == 16, "v3_meta_t size mismatch");

// =========================================================
// 标志位定义
// =========================================================
#define V3_FLAG_FEC_ENABLED     (1 << 0)    // FEC 已启用
#define V3_FLAG_PACING_ENABLED  (1 << 1)    // Pacing 已启用
#define V3_FLAG_URGENT          (1 << 2)    // 紧急数据
#define V3_FLAG_FIN             (1 << 3)    // 流结束
#define V3_FLAG_RST             (1 << 4)    // 重置
#define V3_FLAG_ACK             (1 << 5)    // 确认

// =========================================================
// 连接状态
// =========================================================
typedef enum {
    V3_STATE_DISCONNECTED = 0,
    V3_STATE_CONNECTING,
    V3_STATE_CONNECTED,
    V3_STATE_RECONNECTING,
    V3_STATE_DISCONNECTING,
    V3_STATE_ERROR,
} v3_conn_state_t;

// =========================================================
// 核心上下文
// =========================================================
typedef struct v3_context_s v3_context_t;

// =========================================================
// 回调函数类型
// =========================================================

// 连接状态变化回调
typedef void (*v3_state_callback_t)(
    v3_context_t *ctx,
    v3_conn_state_t old_state,
    v3_conn_state_t new_state,
    void *userdata
);

// 数据接收回调
typedef void (*v3_recv_callback_t)(
    v3_context_t *ctx,
    uint16_t stream_id,
    const uint8_t *data,
    size_t len,
    void *userdata
);

// 错误回调
typedef void (*v3_error_callback_t)(
    v3_context_t *ctx,
    v3_error_t error,
    const char *message,
    void *userdata
);

// 日志回调
typedef void (*v3_log_callback_t)(
    int level,
    const char *message,
    void *userdata
);

// =========================================================
// 统计信息
// =========================================================
typedef struct {
    // 流量统计
    uint64_t packets_sent;
    uint64_t packets_recv;
    uint64_t bytes_sent;
    uint64_t bytes_recv;
    
    // 错误统计
    uint64_t packets_dropped;
    uint64_t decrypt_failures;
    uint64_t magic_failures;
    
    // FEC 统计
    uint64_t fec_groups_sent;
    uint64_t fec_groups_recv;
    uint64_t fec_recoveries;
    uint64_t fec_failures;
    
    // 性能统计
    uint64_t rtt_us;            // 往返时延（微秒）
    uint64_t rtt_min_us;
    uint64_t rtt_max_us;
    uint64_t jitter_us;         // 抖动
    
    // 连接统计
    uint64_t connect_time_sec;  // 连接持续时间
    uint32_t reconnect_count;   // 重连次数
    
    // 时间戳
    uint64_t last_send_time;
    uint64_t last_recv_time;
} v3_stats_t;

// =========================================================
// 核心 API
// =========================================================

/**
 * @brief 初始化 v3 核心库
 * @return V3_OK 成功，其他为错误码
 */
V3_API v3_error_t v3_init(void);

/**
 * @brief 清理 v3 核心库
 */
V3_API void v3_cleanup(void);

/**
 * @brief 创建 v3 上下文
 * @return 上下文指针，失败返回 NULL
 */
V3_API v3_context_t* v3_context_create(void);

/**
 * @brief 销毁 v3 上下文
 * @param ctx 上下文指针
 */
V3_API void v3_context_destroy(v3_context_t *ctx);

/**
 * @brief 设置连接参数
 * @param ctx 上下文
 * @param server_addr 服务器地址
 * @param server_port 服务器端口
 * @param key 32字节密钥
 * @return V3_OK 成功
 */
V3_API v3_error_t v3_set_server(
    v3_context_t *ctx,
    const char *server_addr,
    uint16_t server_port,
    const uint8_t key[V3_KEY_SIZE]
);

/**
 * @brief 设置本地绑定
 * @param ctx 上下文
 * @param local_addr 本地地址（NULL 为任意）
 * @param local_port 本地端口（0 为随机）
 */
V3_API v3_error_t v3_set_local(
    v3_context_t *ctx,
    const char *local_addr,
    uint16_t local_port
);

/**
 * @brief 连接到服务器
 * @param ctx 上下文
 * @return V3_OK 成功
 */
V3_API v3_error_t v3_connect(v3_context_t *ctx);

/**
 * @brief 断开连接
 * @param ctx 上下文
 */
V3_API void v3_disconnect(v3_context_t *ctx);

/**
 * @brief 发送数据
 * @param ctx 上下文
 * @param stream_id 流 ID
 * @param data 数据指针
 * @param len 数据长度
 * @return 发送的字节数，负数为错误
 */
V3_API int v3_send(
    v3_context_t *ctx,
    uint16_t stream_id,
    const uint8_t *data,
    size_t len
);

/**
 * @brief 接收数据（非阻塞）
 * @param ctx 上下文
 * @param stream_id 输出：流 ID
 * @param buf 缓冲区
 * @param buflen 缓冲区大小
 * @return 接收的字节数，0 为无数据，负数为错误
 */
V3_API int v3_recv(
    v3_context_t *ctx,
    uint16_t *stream_id,
    uint8_t *buf,
    size_t buflen
);

/**
 * @brief 获取当前状态
 */
V3_API v3_conn_state_t v3_get_state(v3_context_t *ctx);

/**
 * @brief 获取统计信息
 */
V3_API v3_error_t v3_get_stats(v3_context_t *ctx, v3_stats_t *stats);

/**
 * @brief 重置统计信息
 */
V3_API void v3_reset_stats(v3_context_t *ctx);

// =========================================================
// 回调设置
// =========================================================

V3_API void v3_set_state_callback(
    v3_context_t *ctx,
    v3_state_callback_t callback,
    void *userdata
);

V3_API void v3_set_recv_callback(
    v3_context_t *ctx,
    v3_recv_callback_t callback,
    void *userdata
);

V3_API void v3_set_error_callback(
    v3_context_t *ctx,
    v3_error_callback_t callback,
    void *userdata
);

V3_API void v3_set_log_callback(
    v3_log_callback_t callback,
    void *userdata
);

// =========================================================
// 工具函数
// =========================================================

/**
 * @brief 获取错误描述
 */
V3_API const char* v3_error_string(v3_error_t error);

/**
 * @brief 获取状态描述
 */
V3_API const char* v3_state_string(v3_conn_state_t state);

/**
 * @brief 获取版本字符串
 */
V3_API const char* v3_version_string(void);

/**
 * @brief Base64 编码密钥
 */
V3_API int v3_key_to_base64(const uint8_t key[V3_KEY_SIZE], char *out, size_t outlen);

/**
 * @brief Base64 解码密钥
 */
V3_API int v3_key_from_base64(const char *b64, uint8_t key[V3_KEY_SIZE]);

/**
 * @brief 生成随机密钥
 */
V3_API void v3_generate_key(uint8_t key[V3_KEY_SIZE]);

#endif // V3_CORE_H

