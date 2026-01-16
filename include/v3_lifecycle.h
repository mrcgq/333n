
#ifndef V3_LIFECYCLE_H
#define V3_LIFECYCLE_H

#include "v3_core.h"
#include "v3_config.h"

// =========================================================
// 生命周期状态
// =========================================================
typedef enum {
    V3_LIFECYCLE_STOPPED = 0,       // 已停止
    V3_LIFECYCLE_STARTING,          // 正在启动
    V3_LIFECYCLE_RUNNING,           // 运行中
    V3_LIFECYCLE_STOPPING,          // 正在停止
    V3_LIFECYCLE_RESTARTING,        // 正在重启
    V3_LIFECYCLE_ERROR,             // 错误状态
} v3_lifecycle_state_t;

// =========================================================
// 退出原因
// =========================================================
typedef enum {
    V3_EXIT_NORMAL = 0,             // 正常退出
    V3_EXIT_ERROR,                  // 错误退出
    V3_EXIT_SIGNAL,                 // 信号退出
    V3_EXIT_RESTART,                // 重启退出
    V3_EXIT_UPGRADE,                // 升级退出
    V3_EXIT_CRASH,                  // 崩溃
} v3_exit_reason_t;

// =========================================================
// 启动选项
// =========================================================
typedef struct {
    bool        daemon_mode;        // 守护进程模式
    bool        single_instance;    // 单实例模式
    bool        enable_ipc;         // 启用 IPC
    bool        enable_guard;       // 启用守护
    const char *config_path;        // 配置文件路径
    const char *log_path;           // 日志文件路径
    const char *pid_file;           // PID 文件路径
    int         verbosity;          // 详细程度
} v3_startup_options_t;

// =========================================================
// 生命周期上下文
// =========================================================
typedef struct v3_lifecycle_s v3_lifecycle_t;

// =========================================================
// 回调函数
// =========================================================

// 状态变化回调
typedef void (*v3_lifecycle_state_callback_t)(
    v3_lifecycle_t *lc,
    v3_lifecycle_state_t old_state,
    v3_lifecycle_state_t new_state,
    void *userdata
);

// 退出回调（用于清理）
typedef void (*v3_lifecycle_exit_callback_t)(
    v3_lifecycle_t *lc,
    v3_exit_reason_t reason,
    int exit_code,
    void *userdata
);

// =========================================================
// 生命周期 API
// =========================================================

/**
 * @brief 创建生命周期管理器
 */
V3_API v3_lifecycle_t* v3_lifecycle_create(void);

/**
 * @brief 销毁生命周期管理器
 */
V3_API void v3_lifecycle_destroy(v3_lifecycle_t *lc);

/**
 * @brief 初始化（解析命令行参数等）
 * @param lc 生命周期管理器
 * @param argc 参数数量
 * @param argv 参数数组
 * @param options 启动选项
 * @return V3_OK 成功
 */
V3_API v3_error_t v3_lifecycle_init(
    v3_lifecycle_t *lc,
    int argc,
    char **argv,
    const v3_startup_options_t *options
);

/**
 * @brief 启动
 * @param lc 生命周期管理器
 * @return V3_OK 成功
 */
V3_API v3_error_t v3_lifecycle_start(v3_lifecycle_t *lc);

/**
 * @brief 停止
 * @param lc 生命周期管理器
 * @param reason 退出原因
 */
V3_API void v3_lifecycle_stop(v3_lifecycle_t *lc, v3_exit_reason_t reason);

/**
 * @brief 请求重启
 */
V3_API void v3_lifecycle_restart(v3_lifecycle_t *lc);

/**
 * @brief 运行主循环（阻塞）
 * @return 退出码
 */
V3_API int v3_lifecycle_run(v3_lifecycle_t *lc);

/**
 * @brief 获取当前状态
 */
V3_API v3_lifecycle_state_t v3_lifecycle_get_state(v3_lifecycle_t *lc);

/**
 * @brief 获取核心上下文
 */
V3_API v3_context_t* v3_lifecycle_get_context(v3_lifecycle_t *lc);

/**
 * @brief 获取配置
 */
V3_API v3_config_t* v3_lifecycle_get_config(v3_lifecycle_t *lc);

/**
 * @brief 设置状态回调
 */
V3_API void v3_lifecycle_set_state_callback(
    v3_lifecycle_t *lc,
    v3_lifecycle_state_callback_t callback,
    void *userdata
);

/**
 * @brief 设置退出回调
 */
V3_API void v3_lifecycle_set_exit_callback(
    v3_lifecycle_t *lc,
    v3_lifecycle_exit_callback_t callback,
    void *userdata
);

// =========================================================
// 单实例管理
// =========================================================

/**
 * @brief 检查是否已有实例运行
 * @return true 如果已有实例运行
 */
V3_API bool v3_is_instance_running(void);

/**
 * @brief 获取运行中实例的 PID
 * @return PID，如果没有运行实例返回 0
 */
V3_API uint32_t v3_get_running_instance_pid(void);

/**
 * @brief 向运行中的实例发送信号
 * @param signal_type 信号类型（平台相关）
 * @return V3_OK 成功
 */
V3_API v3_error_t v3_signal_instance(int signal_type);

// =========================================================
// PID 文件管理
// =========================================================

/**
 * @brief 创建 PID 文件
 */
V3_API v3_error_t v3_pid_file_create(const char *path);

/**
 * @brief 删除 PID 文件
 */
V3_API void v3_pid_file_remove(const char *path);

/**
 * @brief 读取 PID 文件
 * @return PID，失败返回 0
 */
V3_API uint32_t v3_pid_file_read(const char *path);

// =========================================================
// 状态字符串
// =========================================================

V3_API const char* v3_lifecycle_state_string(v3_lifecycle_state_t state);
V3_API const char* v3_exit_reason_string(v3_exit_reason_t reason);

#endif // V3_LIFECYCLE_H


