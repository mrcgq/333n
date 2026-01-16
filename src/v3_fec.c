/*
 * src/v3_fec.c - v3 前向纠错 (FEC) 实现
 *
 * 实现了与服务端兼容的 XOR FEC 机制，用于恢复少量丢包。
 */
#define V3_BUILDING_CORE
#include "v3_internal.h"

// 内部函数声明
static int v3_fec_send_group(v3_context_t *ctx);
static void v3_fec_recover(v3_context_t *ctx, v3_fec_decode_group_t *group);

/**
 * @brief 初始化 FEC 模块
 */
void v3_fec_init(v3_context_t *ctx) {
    if (!ctx || !ctx->fec_config.enabled) {
        return;
    }
    memset(&ctx->fec_ctx, 0, sizeof(v3_fec_context_t));
    ctx->fec_ctx.encode_group.group_id = (uint32_t)v3_random_u32();
}

/**
 * @brief 销毁 FEC 模块 (无动态内存，为空)
 */
void v3_fec_destroy(v3_context_t *ctx) {
    (void)ctx;
}

/**
 * @brief 处理待发送的数据包（FEC 编码）
 * @return V3_OK 成功
 */
v3_error_t v3_fec_send(v3_context_t *ctx, uint16_t stream_id, const uint8_t *payload, size_t len) {
    if (!ctx->fec_config.enabled) {
        // FEC 未启用，直接封装并发送普通数据包
        uint8_t packet_buf[V3_PACKET_BUFFER_SIZE];
        int packet_len = v3_protocol_pack(ctx, stream_id, payload, len, packet_buf, sizeof(packet_buf));
        if (packet_len < 0) return (v3_error_t)packet_len;
        return (v3_error_t)v3_connection_send_raw(ctx, packet_buf, packet_len);
    }
    
    v3_mutex_lock(&ctx->mutex);
    
    v3_fec_encode_group_t *group = &ctx->fec_ctx.encode_group;
    
    // 构造 FEC 负载: FEC Header + v3 Protocol Packet
    uint8_t fec_payload[V3_PACKET_BUFFER_SIZE];
    v3_fec_header_t *fec_header = (v3_fec_header_t*)fec_payload;
    
    fec_header->group_id = group->group_id;
    fec_header->shard_index = (uint8_t)group->count;
    fec_header->data_shards = ctx->fec_config.data_shards;
    fec_header->parity_shards = 1; // XOR 只有一个校验分片
    fec_header->reserved = 0;
    
    // 封装 v3 协议包
    int v3_len = v3_protocol_pack(ctx, stream_id, payload, len, fec_payload + sizeof(v3_fec_header_t), sizeof(fec_payload) - sizeof(v3_fec_header_t));
    if (v3_len < 0) {
        v3_mutex_unlock(&ctx->mutex);
        return (v3_error_t)v3_len;
    }
    
    size_t total_len = sizeof(v3_fec_header_t) + v3_len;
    
    // 加入编码组
    memcpy(group->data[group->count], fec_payload, total_len);
    group->lens[group->count] = total_len;
    group->count++;
    
    // 如果组已满，发送整个组
    if (group->count >= ctx->fec_config.data_shards) {
        v3_fec_send_group(ctx);
    }
    
    v3_mutex_unlock(&ctx->mutex);
    return V3_OK;
}

/**
 * @brief 发送一个完整的 FEC 组（数据分片 + 校验分片）
 */
static int v3_fec_send_group(v3_context_t *ctx) {
    v3_fec_encode_group_t *group = &ctx->fec_ctx.encode_group;
    if (group->count == 0) return 0;
    
    // 1. 发送所有数据分片
    for (int i = 0; i < group->count; i++) {
        v3_connection_send_raw(ctx, group->data[i], group->lens[i]);
    }
    
    // 2. 生成并发送校验分片
    uint8_t parity_payload[V3_PACKET_BUFFER_SIZE] = {0};
    size_t max_len = 0;
    
    for (int i = 0; i < group->count; i++) {
        if (group->lens[i] > max_len) {
            max_len = group->lens[i];
        }
    }
    
    for (int i = 0; i < group->count; i++) {
        for (size_t j = 0; j < group->lens[i]; j++) {
            parity_payload[j] ^= group->data[i][j];
        }
    }
    
    // 修复校验包的头部
    v3_fec_header_t *parity_header = (v3_fec_header_t*)parity_payload;
    parity_header->group_id = group->group_id;
    parity_header->shard_index = ctx->fec_config.data_shards; // 校验分片的索引
    
    v3_connection_send_raw(ctx, parity_payload, max_len);
    ctx->stats.fec_groups_sent++;
    
    // 3. 重置编码组
    group->count = 0;
    group->group_id++;
    
    return 0;
}

/**
 * @brief 处理收到的数据包（FEC 解码）
 */
void v3_fec_recv(v3_context_t *ctx, const uint8_t *packet, size_t len) {
    if (!ctx->fec_config.enabled) {
        // FEC 未启用，直接解包
        uint16_t stream_id;
        uint8_t payload[V3_MAX_PAYLOAD];
        int payload_len = v3_protocol_unpack(ctx, packet, len, &stream_id, payload, sizeof(payload));
        v3_connection_handle_unpacked(ctx, stream_id, payload, payload_len);
        return;
    }
    
    if (len < sizeof(v3_fec_header_t)) return;
    
    const v3_fec_header_t *header = (const v3_fec_header_t*)packet;
    
    v3_mutex_lock(&ctx->mutex);
    
    // 1. 查找或创建解码组
    v3_fec_decode_group_t *group = NULL;
    int oldest_idx = 0;
    uint64_t oldest_time = ctx->fec_ctx.decode_cache[0].last_seen_ns;
    
    for (int i = 0; i < FEC_DECODE_CACHE_SIZE; i++) {
        if (ctx->fec_ctx.decode_cache[i].group_id == header->group_id) {
            group = &ctx->fec_ctx.decode_cache[i];
            break;
        }
        if (ctx->fec_ctx.decode_cache[i].last_seen_ns < oldest_time) {
            oldest_time = ctx->fec_ctx.decode_cache[i].last_seen_ns;
            oldest_idx = i;
        }
    }
    
    if (!group) {
        // 没找到，重用最旧的缓存槽
        group = &ctx->fec_ctx.decode_cache[oldest_idx];
        memset(group, 0, sizeof(v3_fec_decode_group_t));
        group->group_id = header->group_id;
        group->data_shards = header->data_shards;
        group->parity_shards = header->parity_shards;
    }
    
    group->last_seen_ns = v3_time_ns();
    
    // 2. 存储分片
    if (header->shard_index < FEC_MAX_GROUP_SIZE && !group->present[header->shard_index]) {
        size_t shard_len = len - sizeof(v3_fec_header_t);
        memcpy(group->shards[header->shard_index], packet + sizeof(v3_fec_header_t), shard_len);
        group->present[header->shard_index] = true;
        group->present_count++;
        if (shard_len > group->shard_len) {
            group->shard_len = (uint16_t)shard_len;
        }
    }
    
    // 3. 检查是否可以恢复
    if (!group->recovered && group->present_count >= group->data_shards) {
        v3_fec_recover(ctx, group);
    }
    
    v3_mutex_unlock(&ctx->mutex);
}

/**
 * @brief 尝试恢复一个 FEC 组
 */
static void v3_fec_recover(v3_context_t *ctx, v3_fec_decode_group_t *group) {
    int missing_index = -1;
    int data_present_count = 0;
    
    for (int i = 0; i < group->data_shards; i++) {
        if (group->present[i]) {
            data_present_count++;
        } else {
            missing_index = i;
        }
    }
    
    // Case 1: 所有数据分片都已到达
    if (data_present_count == group->data_shards) {
        ctx->stats.fec_groups_recv++;
        for (int i = 0; i < group->data_shards; i++) {
            // 解包并向上层传递
            uint16_t stream_id;
            uint8_t payload[V3_MAX_PAYLOAD];
            int payload_len = v3_protocol_unpack(ctx, group->shards[i], group->shard_len, &stream_id, payload, sizeof(payload));
            v3_connection_handle_unpacked(ctx, stream_id, payload, payload_len);
        }
        group->recovered = true;
        return;
    }
    
    // Case 2: 丢失一个数据分片，但校验分片已到达
    if (data_present_count == group->data_shards - 1 && group->present[group->data_shards]) {
        // 使用 XOR 恢复
        uint8_t *missing_shard = group->shards[missing_index];
        memset(missing_shard, 0, group->shard_len);
        
        for (int i = 0; i <= group->data_shards; i++) {
            if (i != missing_index && group->present[i]) {
                for (int j = 0; j < group->shard_len; j++) {
                    missing_shard[j] ^= group->shards[i][j];
                }
            }
        }
        
        group->present[missing_index] = true;
        ctx->stats.fec_recoveries++;
        
        // 恢复成功，现在所有数据分片都齐了，再次调用本函数处理
        v3_fec_recover(ctx, group);
        return;
    }
    
    // Case 3: 丢失超过一个包，无法恢复
    if (group->present_count > group->data_shards) {
        ctx->stats.fec_failures++;
        group->recovered = true; // 标记为已处理，防止重复失败
    }
}
