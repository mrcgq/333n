/*
 * src/v3_connection.c - v3 连接/会话管理实现
 *
 * 负责网络线程、状态机、超时、重连和统计。
 */
#define V3_BUILDING_CORE
#include "v3_internal.h"

// 声明外部函数
v3_error_t v3_crypto_init(void);
void v3_pacing_init(v3_context_t *ctx);
uint64_t v3_pacing_acquire(v3_context_t *ctx, size_t bytes);
void v3_fec_init(v3_context_t *ctx);
v3_error_t v3_fec_send(v3_context_t *ctx, uint16_t stream_id, const uint8_t *payload, size_t len);
void v3_fec_recv(v3_context_t *ctx, const uint8_t *fec_payload, size_t len);

// 接收线程函数
static void* recv_thread_func(void *arg) {
    v3_context_t *ctx = (v3_context_t*)arg;
    uint8_t buffer[V3_PACKET_BUFFER_SIZE];

    while (ctx->running) {
        int len = v3_socket_recvfrom(ctx->sock, buffer, sizeof(buffer), NULL, 0, NULL);
        if (len > 0) {
            v3_mutex_lock(&ctx->mutex);
            ctx->stats.packets_recv++;
            ctx->stats.bytes_recv += len;
            v3_mutex_unlock(&ctx->mutex);
            
            // 调用 FEC 模块处理接收的数据包
            v3_fec_recv(ctx, buffer, len);
        } else {
            // 超时或其他错误
        }
    }
    return NULL;
}

// 内部函数：设置状态并触发回调
void v3_set_state(v3_context_t *ctx, v3_conn_state_t new_state) {
    v3_mutex_lock(&ctx->mutex);
    v3_conn_state_t old_state = ctx->state;
    if (old_state != new_state) {
        ctx->state = new_state;
        if (ctx->state_callback) {
            ctx->state_callback(ctx, old_state, new_state, ctx->state_userdata);
        }
    }
    v3_mutex_unlock(&ctx->mutex);
}

// 全局初始化
v3_error_t v3_init(void) {
    v3_platform_init();
    return v3_crypto_init();
}

// 全局清理
void v3_cleanup(void) {
    v3_platform_cleanup();
}

// 创建上下文
v3_context_t* v3_context_create(void) {
    v3_context_t *ctx = (v3_context_t*)v3_calloc(1, sizeof(v3_context_t));
    if (!ctx) return NULL;
    v3_mutex_init(&ctx->mutex);
    v3_random_bytes(&ctx->session_token, sizeof(ctx->session_token));
    return ctx;
}

// 销毁上下文
void v3_context_destroy(v3_context_t *ctx) {
    if (!ctx) return;
    v3_disconnect(ctx);
    v3_mutex_destroy(&ctx->mutex);
    v3_free(ctx);
}

// 设置服务器信息
v3_error_t v3_set_server(v3_context_t *ctx, const char *addr, uint16_t port, const uint8_t key[V3_KEY_SIZE]) {
    v3_mutex_lock(&ctx->mutex);
    strncpy(ctx->server_config.address, addr, sizeof(ctx->server_config.address) - 1);
    ctx->server_config.port = port;
    memcpy(ctx->master_key, key, V3_KEY_SIZE);
    v3_mutex_unlock(&ctx->mutex);
    return V3_OK;
}

// 连接
v3_error_t v3_connect(v3_context_t *ctx) {
    v3_mutex_lock(&ctx->mutex);
    if (ctx->state != V3_STATE_DISCONNECTED) {
        v3_mutex_unlock(&ctx->mutex);
        return V3_ERR_ALREADY_RUNNING;
    }
    
    ctx->sock = v3_socket_udp_create(false);
    if (ctx->sock == V3_INVALID_SOCKET) {
        v3_mutex_unlock(&ctx->mutex);
        return V3_ERR_NETWORK;
    }
    v3_socket_set_recv_timeout(ctx->sock, 1000);
    
    // 初始化子模块
    v3_pacing_init(ctx);
    v3_fec_init(ctx);
    
    ctx->running = true;
    v3_thread_create(&ctx->recv_thread, recv_thread_func, ctx);
    v3_mutex_unlock(&ctx->mutex);

    v3_set_state(ctx, V3_STATE_CONNECTED); // 简化处理，直接设为已连接
    return V3_OK;
}

// 断开连接
void v3_disconnect(v3_context_t *ctx) {
    v3_mutex_lock(&ctx->mutex);
    if (ctx->state == V3_STATE_DISCONNECTED) {
        v3_mutex_unlock(&ctx->mutex);
        return;
    }
    
    ctx->running = false;
    v3_mutex_unlock(&ctx->mutex);

    v3_thread_join(ctx->recv_thread, NULL);

    v3_mutex_lock(&ctx->mutex);
    v3_socket_close(ctx->sock);
    ctx->sock = V3_INVALID_SOCKET;
    v3_mutex_unlock(&ctx->mutex);

    v3_set_state(ctx, V3_STATE_DISCONNECTED);
}

// 发送数据 (由 FEC 模块接管)
int v3_send(v3_context_t *ctx, uint16_t stream_id, const uint8_t *data, size_t len) {
    if (ctx->state != V3_STATE_CONNECTED) return V3_ERR_NOT_CONNECTED;
    
    // 调用 FEC 模块处理发送
    v3_error_t err = v3_fec_send(ctx, stream_id, data, len);
    
    return (err == V3_OK) ? (int)len : err;
}

// 内部函数：真正发送 UDP 数据包的地方，应用 Pacing
int v3_connection_send_raw(v3_context_t *ctx, const uint8_t *data, size_t len) {
    // 应用 Pacing
    uint64_t wait_ns = v3_pacing_acquire(ctx, len);
    if (wait_ns > 0) {
        v3_sleep_us((uint32_t)(wait_ns / 1000));
    }

    int sent = v3_socket_sendto(ctx->sock, data, len, ctx->server_config.address, ctx->server_config.port);
    if (sent > 0) {
        v3_mutex_lock(&ctx->mutex);
        ctx->stats.packets_sent++;
        ctx->stats.bytes_sent += sent;
        v3_mutex_unlock(&ctx->mutex);
    }
    return sent;
}

// 内部函数：处理解包/恢复后的数据
void v3_connection_handle_unpacked(v3_context_t *ctx, uint16_t stream_id, const uint8_t* payload, int payload_len) {
    if (payload_len >= 0 && ctx->recv_callback) {
        ctx->recv_callback(ctx, stream_id, payload, payload_len, ctx->recv_userdata);
    }
}

v3_conn_state_t v3_get_state(v3_context_t *ctx) {
    return ctx->state;
}

v3_error_t v3_get_stats(v3_context_t *ctx, v3_stats_t *stats) {
    if (!ctx || !stats) return V3_ERR_INVALID_PARAM;
    v3_mutex_lock(&ctx->mutex);
    memcpy(stats, &ctx->stats, sizeof(v3_stats_t));
    v3_mutex_unlock(&ctx->mutex);
    return V3_OK;
}
