
#ifndef V3_CONFIG_H
#define V3_CONFIG_H

#include "v3_core.h"

// =========================================================
// 配置常量
// =========================================================
#define V3_CONFIG_FILENAME      "v3_config.json"
#define V3_CONFIG_MAX_SERVERS   32
#define V3_CONFIG_MAX_PATH      260

// =========================================================
// FEC 类型（与服务端一致）
// =========================================================
typedef enum {
    V3_FEC_NONE = 0,
    V3_FEC_XOR,
    V3_FEC_RS_SIMPLE,
    V3_FEC_RS_SIMD,
    V3_FEC_AUTO,
} v3_fec_type_t;

// =========================================================
// 流量伪装配置（与服务端 ad_profile_t 一致）
// =========================================================
typedef enum {
    V3_PROFILE_NONE = 0,
    V3_PROFILE_HTTPS,
    V3_PROFILE_VIDEO,
    V3_PROFILE_VOIP,
    V3_PROFILE_GAMING,
} v3_profile_t;

// =========================================================
// 服务器配置
// =========================================================
typedef struct {
    char        name[64];               // 配置名称
    char        address[256];           // 服务器地址
    uint16_t    port;                   // 服务器端口
    uint8_t     key[V3_KEY_SIZE];       // 密钥
    bool        enabled;                // 是否启用
    
    // 可选配置
    char        local_address[64];      // 本地绑定地址
    uint16_t    local_port;             // 本地端口
    
    // 高级配置
    uint16_t    mtu;                    // MTU（0 = 自动）
    int         timeout_sec;            // 连接超时
} v3_server_config_t;

// =========================================================
// FEC 配置
// =========================================================
typedef struct {
    bool            enabled;            // 是否启用
    v3_fec_type_t   type;              // FEC 类型
    uint8_t         data_shards;        // 数据分片数
    uint8_t         parity_shards;      // 校验分片数
    bool            adaptive;           // 自适应调整
} v3_fec_config_t;

// =========================================================
// Pacing 配置
// =========================================================
typedef struct {
    bool        enabled;                // 是否启用
    uint64_t    initial_bps;            // 初始速率 (bps)
    uint64_t    min_bps;                // 最小速率
    uint64_t    max_bps;                // 最大速率
    bool        brutal_mode;            // Brutal 模式（恒定速率）
} v3_pacing_config_t;

// =========================================================
// 流量伪装配置
// =========================================================
typedef struct {
    bool            enabled;            // 是否启用
    v3_profile_t    profile;            // 伪装配置
} v3_antidetect_config_t;

// =========================================================
// 日志配置
// =========================================================
typedef enum {
    V3_LOG_LEVEL_TRACE = 0,
    V3_LOG_LEVEL_DEBUG,
    V3_LOG_LEVEL_INFO,
    V3_LOG_LEVEL_WARN,
    V3_LOG_LEVEL_ERROR,
    V3_LOG_LEVEL_FATAL,
    V3_LOG_LEVEL_OFF,
} v3_log_level_t;

typedef struct {
    v3_log_level_t  level;              // 日志级别
    bool            to_file;            // 写入文件
    bool            to_console;         // 输出到控制台
    char            file_path[V3_CONFIG_MAX_PATH];  // 日志文件路径
    uint32_t        max_file_size_mb;   // 最大文件大小 (MB)
    uint32_t        max_files;          // 最大文件数量（轮转）
} v3_log_config_t;

// =========================================================
// 系统配置
// =========================================================
typedef struct {
    bool        auto_start;             // 开机自启
    bool        minimize_to_tray;       // 最小化到托盘
    bool        close_to_tray;          // 关闭时最小化到托盘
    bool        auto_reconnect;         // 自动重连
    int         reconnect_delay_sec;    // 重连延迟
    int         reconnect_max_attempts; // 最大重连次数（0 = 无限）
    char        language[16];           // 语言
} v3_system_config_t;

// =========================================================
// 完整配置
// =========================================================
typedef struct {
    // 版本
    uint32_t                version;
    
    // 服务器列表
    v3_server_config_t      servers[V3_CONFIG_MAX_SERVERS];
    int                     server_count;
    int                     active_server;      // 当前激活的服务器索引
    
    // 功能配置
    v3_fec_config_t         fec;
    v3_pacing_config_t      pacing;
    v3_antidetect_config_t  antidetect;
    
    // 系统配置
    v3_log_config_t         log;
    v3_system_config_t      system;
} v3_config_t;

// =========================================================
// 配置 API
// =========================================================

/**
 * @brief 初始化默认配置
 */
V3_API void v3_config_init_default(v3_config_t *config);

/**
 * @brief 从文件加载配置
 * @param config 配置结构体
 * @param path 文件路径（NULL 使用默认路径）
 * @return V3_OK 成功
 */
V3_API v3_error_t v3_config_load(v3_config_t *config, const char *path);

/**
 * @brief 保存配置到文件
 * @param config 配置结构体
 * @param path 文件路径（NULL 使用默认路径）
 * @return V3_OK 成功
 */
V3_API v3_error_t v3_config_save(const v3_config_t *config, const char *path);

/**
 * @brief 验证配置有效性
 * @param config 配置结构体
 * @param error_msg 错误信息缓冲区（可选）
 * @param error_msg_len 缓冲区大小
 * @return V3_OK 验证通过
 */
V3_API v3_error_t v3_config_validate(
    const v3_config_t *config,
    char *error_msg,
    size_t error_msg_len
);

/**
 * @brief 获取默认配置文件路径
 * @param buf 输出缓冲区
 * @param buflen 缓冲区大小
 * @return 路径长度
 */
V3_API int v3_config_get_default_path(char *buf, size_t buflen);

// =========================================================
// 服务器配置操作
// =========================================================

/**
 * @brief 添加服务器配置
 * @return 新服务器的索引，失败返回 -1
 */
V3_API int v3_config_add_server(
    v3_config_t *config,
    const v3_server_config_t *server
);

/**
 * @brief 删除服务器配置
 */
V3_API v3_error_t v3_config_remove_server(
    v3_config_t *config,
    int index
);

/**
 * @brief 更新服务器配置
 */
V3_API v3_error_t v3_config_update_server(
    v3_config_t *config,
    int index,
    const v3_server_config_t *server
);

/**
 * @brief 设置活动服务器
 */
V3_API v3_error_t v3_config_set_active_server(
    v3_config_t *config,
    int index
);

/**
 * @brief 获取活动服务器配置
 */
V3_API const v3_server_config_t* v3_config_get_active_server(
    const v3_config_t *config
);

// =========================================================
// 配置序列化（用于 IPC）
// =========================================================

/**
 * @brief 将配置序列化为 JSON
 * @param config 配置结构体
 * @param buf 输出缓冲区
 * @param buflen 缓冲区大小
 * @return JSON 长度，负数为错误
 */
V3_API int v3_config_to_json(
    const v3_config_t *config,
    char *buf,
    size_t buflen
);

/**
 * @brief 从 JSON 解析配置
 * @param json JSON 字符串
 * @param config 输出配置结构体
 * @return V3_OK 成功
 */
V3_API v3_error_t v3_config_from_json(
    const char *json,
    v3_config_t *config
);

// =========================================================
// 配置监听（文件变更通知）
// =========================================================

typedef void (*v3_config_change_callback_t)(
    const v3_config_t *new_config,
    void *userdata
);

/**
 * @brief 开始监听配置文件变更
 */
V3_API v3_error_t v3_config_watch(
    const char *path,
    v3_config_change_callback_t callback,
    void *userdata
);

/**
 * @brief 停止监听
 */
V3_API void v3_config_unwatch(void);

#endif // V3_CONFIG_H
