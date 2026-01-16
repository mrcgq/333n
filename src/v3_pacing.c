/*
 * src/v3_pacing.c - v3 流量控制 (Pacing) 实现
 *
 * 实现了令牌桶算法，用于平滑发送流量，避免网络拥塞。
 */

#define V3_BUILDING_CORE
#include "v3_internal.h"

/**
 * @brief 初始化 Pacing 模块
 */
void v3_pacing_init(v3_context_t *ctx) {
    if (!ctx || !ctx->pacing_config.enabled) {
        return;
    }

    v3_pacer_t *p = &ctx->pacer;
    const v3_pacing_config_t *config = &ctx->pacing_config;

    p->target_bps = config->initial_bps > 0 ? config->initial_bps : 100 * 1000 * 1000;
    p->tokens_per_ns = (double)p->target_bps / 8.0 / 1e9;
    
    // 最大突发量设置为 100ms 的流量
    p->max_burst_tokens = (double)p->target_bps / 8.0 * 0.1;
    if (p->max_burst_tokens < V3_PACKET_BUFFER_SIZE * 10) {
        p->max_burst_tokens = V3_PACKET_BUFFER_SIZE * 10;
    }

    p->tokens = p->max_burst_tokens;
    p->last_refill_ns = v3_time_ns();
}

/**
 * @brief 销毁 Pacing 模块 (此处无动态内存，为空)
 */
void v3_pacing_destroy(v3_context_t *ctx) {
    (void)ctx;
}

/**
 * @brief 请求发送权限，并返回需要等待的时间
 * @param ctx 核心上下文
 * @param bytes 准备发送的字节数
 * @return 需要等待的纳秒数。0 表示可以立即发送。
 */
uint64_t v3_pacing_acquire(v3_context_t *ctx, size_t bytes) {
    if (!ctx || !ctx->pacing_config.enabled) {
        return 0; // Pacing 未启用，立即发送
    }

    v3_pacer_t *p = &ctx->pacer;
    v3_mutex_lock(&ctx->mutex);

    // 1. 补充令牌
    uint64_t now_ns = v3_time_ns();
    uint64_t elapsed_ns = now_ns - p->last_refill_ns;
    
    p->tokens += elapsed_ns * p->tokens_per_ns;
    p->last_refill_ns = now_ns;

    // 2. 限制最大令牌数（防止无限累积）
    if (p->tokens > p->max_burst_tokens) {
        p->tokens = p->max_burst_tokens;
    }

    // 3. 检查令牌是否足够
    if (p->tokens >= bytes) {
        // 令牌足够，消耗并立即发送
        p->tokens -= bytes;
        v3_mutex_unlock(&ctx->mutex);
        return 0;
    }

    // 4. 令牌不足，计算需要等待的时间
    double deficit = bytes - p->tokens;
    // 消耗掉所有剩余令牌
    p->tokens = 0;
    
    uint64_t wait_ns = (uint64_t)(deficit / p->tokens_per_ns);

    v3_mutex_unlock(&ctx->mutex);
    return wait_ns;
}

/**
 * @brief 动态调整 Pacing 速率 (用于BBR等高级算法)
 */
void v3_pacing_update_rate(v3_context_t *ctx, uint64_t new_bps) {
    if (!ctx || !ctx->pacing_config.enabled) {
        return;
    }

    v3_pacer_t *p = &ctx->pacer;
    v3_mutex_lock(&ctx->mutex);
    
    if (new_bps < ctx->pacing_config.min_bps) new_bps = ctx->pacing_config.min_bps;
    if (new_bps > ctx->pacing_config.max_bps) new_bps = ctx->pacing_config.max_bps;

    p->target_bps = new_bps;
    p->tokens_per_ns = (double)p->target_bps / 8.0 / 1e9;
    p->max_burst_tokens = (double)p->target_bps / 8.0 * 0.1;

    v3_mutex_unlock(&ctx->mutex);
}
