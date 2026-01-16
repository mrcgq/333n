
#ifndef V3_GUARD_H
#define V3_GUARD_H

#include "v3_core.h"
#include "v3_config.h"

// =========================================================
// 守护模式
// =========================================================
typedef enum {
    V3_GUARD_MODE_DISABLED = 0,     // 禁用守护
    V3_GUARD_MODE_RESTART,          // 崩溃后自动重启
    V3_GUARD_MODE_WATCHDOG,         // 看门狗模式（需要周期性喂狗）
    V3_GUARD_MODE_SERVICE,          // Windows 服务模式
} v3_guard_mode_t;

// =========================================================
// 健康状态
// =========================================================
typedef enum {
    V3_HEALTH_UNKNOWN = 0,
    V3_HEALTH_HEALTHY,
    V3_HEALTH_DEGRADED,
    V3_HEALTH_UNHEALTHY,
    V3_HEALTH_CRITICAL,
} v3_health_status_t;

// =========================================================
// 健康检查结果
// =========================================================
typedef struct {
    v3_health_status_t  status;
    uint64_t            uptime_sec;
    uint64_t            last_check_time;
    
    // 网络健康
    bool                network_ok;
    uint64_t            last_packet_time;
    
    // 内存健康
    bool                memory_ok;
    uint64_t            memory_usage_mb;
    
    // 连接健康
    bool                connection_ok;
    v3_conn_state_t     conn_state;
    uint32_t            reconnect_count;
    
    // 错误统计
    uint64_t            error_count;
    uint64_t            crash_count;
    
    // 详细信息
    char                message[256];
} v3_health_result_t;

// =========================================================
// 守护配置
// =========================================================
typedef struct {
    v3_guard_mode_t mode;
    
    // 重启配置
    int             restart_delay_sec;      // 重启延迟
    int             max_restarts;           // 最大重启次数（0 = 无限）
    int             restart_window_sec;     // 统计窗口（秒）
    
    // 看门狗配置
    int             watchdog_timeout_sec;   // 看门狗超时
    int             watchdog_interval_sec;  // 喂狗间隔
    
    // 健康检查配置
    int             health_check_interval_sec;
    bool            auto_reconnect_on_unhealthy;
    
    // 日志配置
    bool            log_restarts;
    bool            log_health_checks;
} v3_guard_config_t;

// =========================================================
// 守护上下文
// =========================================================
typedef struct v3_guard_s v3_guard_t;

// =========================================================
// 回调函数
// =========================================================

// 进程崩溃回调
typedef void (*v3_guard_crash_callback_t)(
    v3_guard_t *guard,
    int exit_code,
    const char *crash_info,
    void *userdata
);

// 重启回调
typedef void (*v3_guard_restart_callback_t)(
    v3_guard_t *guard,
    int restart_count,
    void *userdata
);

// 健康检查回调
typedef void (*v3_guard_health_callback_t)(
    v3_guard_t *guard,
    const v3_health_result_t *health,
    void *userdata
);

// =========================================================
// 守护 API
// =========================================================

/**
 * @brief 创建守护管理器
 */
V3_API v3_guard_t* v3_guard_create(void);

/**
 * @brief 销毁守护管理器
 */
V3_API void v3_guard_destroy(v3_guard_t *guard);

/**
 * @brief 初始化守护
 * @param guard 守护管理器
 * @param ctx 核心上下文
 * @param config 守护配置
 */
V3_API v3_error_t v3_guard_init(
    v3_guard_t *guard,
    v3_context_t *ctx,
    const v3_guard_config_t *config
);

/**
 * @brief 启动守护
 */
V3_API v3_error_t v3_guard_start(v3_guard_t *guard);

/**
 * @brief 停止守护
 */
V3_API void v3_guard_stop(v3_guard_t *guard);

/**
 * @brief 喂狗（看门狗模式）
 */
V3_API void v3_guard_watchdog_kick(v3_guard_t *guard);

/**
 * @brief 手动触发健康检查
 */
V3_API v3_error_t v3_guard_health_check(
    v3_guard_t *guard,
    v3_health_result_t *result
);

/**
 * @brief 获取最近的健康状态
 */
V3_API v3_health_status_t v3_guard_get_health_status(v3_guard_t *guard);

/**
 * @brief 获取重启次数
 */
V3_API int v3_guard_get_restart_count(v3_guard_t *guard);

/**
 * @brief 重置重启计数器
 */
V3_API void v3_guard_reset_restart_count(v3_guard_t *guard);

// =========================================================
// 回调设置
// =========================================================

V3_API void v3_guard_set_crash_callback(
    v3_guard_t *guard,
    v3_guard_crash_callback_t callback,
    void *userdata
);

V3_API void v3_guard_set_restart_callback(
    v3_guard_t *guard,
    v3_guard_restart_callback_t callback,
    void *userdata
);

V3_API void v3_guard_set_health_callback(
    v3_guard_t *guard,
    v3_guard_health_callback_t callback,
    void *userdata
);

// =========================================================
// Windows 服务集成
// =========================================================

#ifdef V3_PLATFORM_WINDOWS

/**
 * @brief 安装为 Windows 服务
 * @param service_name 服务名称
 * @param display_name 显示名称
 * @param description 描述
 * @param exe_path 可执行文件路径（NULL 使用当前）
 */
V3_API v3_error_t v3_service_install(
    const char *service_name,
    const char *display_name,
    const char *description,
    const char *exe_path
);

/**
 * @brief 卸载 Windows 服务
 */
V3_API v3_error_t v3_service_uninstall(const char *service_name);

/**
 * @brief 启动 Windows 服务
 */
V3_API v3_error_t v3_service_start(const char *service_name);

/**
 * @brief 停止 Windows 服务
 */
V3_API v3_error_t v3_service_stop(const char *service_name);

/**
 * @brief 检查服务是否安装
 */
V3_API bool v3_service_is_installed(const char *service_name);

/**
 * @brief 检查服务是否运行
 */
V3_API bool v3_service_is_running(const char *service_name);

/**
 * @brief 运行为服务（入口点）
 * 
 * 当作为服务启动时，应调用此函数而非 v3_lifecycle_run
 */
V3_API int v3_service_run(
    const char *service_name,
    v3_lifecycle_t *lifecycle
);

#endif // V3_PLATFORM_WINDOWS

// =========================================================
// 崩溃转储
// =========================================================

/**
 * @brief 启用崩溃转储
 * @param dump_dir 转储目录（NULL 使用默认）
 */
V3_API v3_error_t v3_crash_dump_enable(const char *dump_dir);

/**
 * @brief 禁用崩溃转储
 */
V3_API void v3_crash_dump_disable(void);

/**
 * @brief 获取最近的崩溃转储文件
 * @param buf 输出缓冲区
 * @param buflen 缓冲区大小
 * @return 路径长度，0 表示没有转储
 */
V3_API int v3_crash_dump_get_latest(char *buf, size_t buflen);

// =========================================================
// 字符串转换
// =========================================================

V3_API const char* v3_guard_mode_string(v3_guard_mode_t mode);
V3_API const char* v3_health_status_string(v3_health_status_t status);

#endif // V3_GUARD_H
