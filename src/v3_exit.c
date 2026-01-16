
#define _CRT_SECURE_NO_WARNINGS
#define V3_BUILDING_CORE

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "v3_core.h"
#include "v3_lifecycle.h"
#include "v3_platform.h"
#include "v3_guard.h"

// =========================================================
// 退出处理器链表
// =========================================================
typedef struct exit_handler_node_s {
    void (*handler)(void *userdata);
    void *userdata;
    int priority;
    struct exit_handler_node_s *next;
} exit_handler_node_t;

static exit_handler_node_t *g_exit_handlers = NULL;
static v3_mutex_t g_exit_mutex;
static bool g_exit_mutex_initialized = false;
static bool g_exit_in_progress = false;

// =========================================================
// 内部函数
// =========================================================

static void ensure_mutex_initialized(void) {
    if (!g_exit_mutex_initialized) {
        v3_mutex_init(&g_exit_mutex);
        g_exit_mutex_initialized = true;
    }
}

// =========================================================
// 退出处理器注册
// =========================================================

/**
 * @brief 注册退出处理器
 * @param handler 处理函数
 * @param userdata 用户数据
 * @param priority 优先级（数值越大越先执行）
 */
void v3_exit_register(void (*handler)(void *), void *userdata, int priority) {
    if (!handler) return;
    
    ensure_mutex_initialized();
    
    exit_handler_node_t *node = (exit_handler_node_t *)malloc(sizeof(exit_handler_node_t));
    if (!node) return;
    
    node->handler = handler;
    node->userdata = userdata;
    node->priority = priority;
    
    v3_mutex_lock(&g_exit_mutex);
    
    // 按优先级插入（高优先级在前）
    exit_handler_node_t **pp = &g_exit_handlers;
    while (*pp && (*pp)->priority >= priority) {
        pp = &(*pp)->next;
    }
    node->next = *pp;
    *pp = node;
    
    v3_mutex_unlock(&g_exit_mutex);
}

/**
 * @brief 注销退出处理器
 */
void v3_exit_unregister(void (*handler)(void *), void *userdata) {
    if (!handler || !g_exit_mutex_initialized) return;
    
    v3_mutex_lock(&g_exit_mutex);
    
    exit_handler_node_t **pp = &g_exit_handlers;
    while (*pp) {
        if ((*pp)->handler == handler && (*pp)->userdata == userdata) {
            exit_handler_node_t *node = *pp;
            *pp = node->next;
            free(node);
            break;
        }
        pp = &(*pp)->next;
    }
    
    v3_mutex_unlock(&g_exit_mutex);
}

// =========================================================
// 退出执行
// =========================================================

/**
 * @brief 执行所有退出处理器
 */
void v3_exit_run_handlers(void) {
    if (!g_exit_mutex_initialized) return;
    
    v3_mutex_lock(&g_exit_mutex);
    
    if (g_exit_in_progress) {
        v3_mutex_unlock(&g_exit_mutex);
        return;
    }
    g_exit_in_progress = true;
    
    exit_handler_node_t *node = g_exit_handlers;
    g_exit_handlers = NULL;
    
    v3_mutex_unlock(&g_exit_mutex);
    
    // 执行所有处理器
    while (node) {
        exit_handler_node_t *next = node->next;
        
        if (node->handler) {
            node->handler(node->userdata);
        }
        
        free(node);
        node = next;
    }
}

/**
 * @brief 清理退出系统
 */
void v3_exit_cleanup(void) {
    v3_exit_run_handlers();
    
    if (g_exit_mutex_initialized) {
        v3_mutex_destroy(&g_exit_mutex);
        g_exit_mutex_initialized = false;
    }
    
    g_exit_in_progress = false;
}

// =========================================================
// 退出原因处理
// =========================================================

static v3_exit_reason_t g_exit_reason = V3_EXIT_NORMAL;
static int g_exit_code = 0;
static char g_exit_message[256] = {0};

void v3_exit_set_reason(v3_exit_reason_t reason, int code, const char *message) {
    g_exit_reason = reason;
    g_exit_code = code;
    
    if (message) {
        strncpy(g_exit_message, message, sizeof(g_exit_message) - 1);
        g_exit_message[sizeof(g_exit_message) - 1] = '\0';
    } else {
        g_exit_message[0] = '\0';
    }
}

v3_exit_reason_t v3_exit_get_reason(void) {
    return g_exit_reason;
}

int v3_exit_get_code(void) {
    return g_exit_code;
}

const char* v3_exit_get_message(void) {
    return g_exit_message[0] ? g_exit_message : NULL;
}

// =========================================================
// 状态保存
// =========================================================

typedef struct {
    uint64_t    timestamp;
    uint32_t    version;
    
    // 连接状态
    v3_conn_state_t conn_state;
    uint64_t    session_token;
    
    // 统计信息
    v3_stats_t  stats;
    
    // 配置信息
    int         active_server_index;
    
    // 退出信息
    v3_exit_reason_t exit_reason;
    int         exit_code;
    char        exit_message[256];
} v3_saved_state_t;

#define V3_STATE_MAGIC      0x33563353  // 'S3V3' in little-endian
#define V3_STATE_VERSION    1

static char g_state_file_path[260] = {0};

/**
 * @brief 设置状态文件路径
 */
void v3_exit_set_state_file(const char *path) {
    if (path) {
        strncpy(g_state_file_path, path, sizeof(g_state_file_path) - 1);
    } else {
        // 使用默认路径
        char app_dir[260];
        if (v3_get_app_data_dir(app_dir, sizeof(app_dir)) > 0) {
            snprintf(g_state_file_path, sizeof(g_state_file_path),
                     "%s\\v3_state.bin", app_dir);
        }
    }
}

/**
 * @brief 保存状态到文件
 */
v3_error_t v3_exit_save_state(v3_context_t *ctx) {
    if (!g_state_file_path[0]) {
        v3_exit_set_state_file(NULL);
    }
    
    if (!g_state_file_path[0]) {
        return V3_ERR_CONFIG;
    }
    
    v3_saved_state_t state = {0};
    
    // 填充状态
    state.timestamp = v3_time_unix();
    state.version = V3_STATE_VERSION;
    state.exit_reason = g_exit_reason;
    state.exit_code = g_exit_code;
    strncpy(state.exit_message, g_exit_message, sizeof(state.exit_message) - 1);
    
    if (ctx) {
        state.conn_state = v3_get_state(ctx);
        v3_get_stats(ctx, &state.stats);
    }
    
    // 写入文件
    FILE *fp = fopen(g_state_file_path, "wb");
    if (!fp) {
        return V3_ERR_PLATFORM;
    }
    
    uint32_t magic = V3_STATE_MAGIC;
    fwrite(&magic, sizeof(magic), 1, fp);
    fwrite(&state, sizeof(state), 1, fp);
    
    fclose(fp);
    
    return V3_OK;
}

/**
 * @brief 从文件恢复状态
 */
v3_error_t v3_exit_load_state(v3_saved_state_t *out_state) {
    if (!out_state) {
        return V3_ERR_INVALID_PARAM;
    }
    
    if (!g_state_file_path[0]) {
        v3_exit_set_state_file(NULL);
    }
    
    if (!g_state_file_path[0]) {
        return V3_ERR_CONFIG;
    }
    
    FILE *fp = fopen(g_state_file_path, "rb");
    if (!fp) {
        return V3_ERR_PLATFORM;
    }
    
    uint32_t magic;
    if (fread(&magic, sizeof(magic), 1, fp) != 1 || magic != V3_STATE_MAGIC) {
        fclose(fp);
        return V3_ERR_CONFIG;
    }
    
    if (fread(out_state, sizeof(*out_state), 1, fp) != 1) {
        fclose(fp);
        return V3_ERR_CONFIG;
    }
    
    fclose(fp);
    
    // 验证版本
    if (out_state->version != V3_STATE_VERSION) {
        return V3_ERR_CONFIG;
    }
    
    return V3_OK;
}

/**
 * @brief 删除状态文件
 */
void v3_exit_clear_state(void) {
    if (g_state_file_path[0]) {
        remove(g_state_file_path);
    }
}

// =========================================================
// 快速退出（紧急情况）
// =========================================================

/**
 * @brief 快速退出（不执行完整清理）
 */
void v3_exit_fast(int code) {
    g_exit_code = code;
    g_exit_reason = V3_EXIT_ERROR;
    
    // 仅执行最关键的清理
    v3_net_cleanup();
    
    _exit(code);
}

/**
 * @brief 崩溃退出（生成转储）
 */
void v3_exit_crash(const char *message) {
    g_exit_reason = V3_EXIT_CRASH;
    g_exit_code = -1;
    
    if (message) {
        strncpy(g_exit_message, message, sizeof(g_exit_message) - 1);
    }
    
    // 尝试保存状态
    v3_exit_save_state(NULL);
    
    // 触发崩溃转储
#ifdef V3_PLATFORM_WINDOWS
    // 在 Windows 上触发异常以生成 minidump
    __debugbreak();
#endif
    
    _exit(-1);
}




