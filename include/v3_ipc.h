
#ifndef V3_IPC_H
#define V3_IPC_H

#include "v3_core.h"

// =========================================================
// IPC 常量
// =========================================================
#define V3_IPC_PIPE_NAME        "\\\\.\\pipe\\v3_core_ipc"
#define V3_IPC_PIPE_NAME_FMT    "\\\\.\\pipe\\v3_core_ipc_%u"
#define V3_IPC_BUFFER_SIZE      65536
#define V3_IPC_TIMEOUT_MS       5000
#define V3_IPC_MAX_CLIENTS      16

// =========================================================
// IPC 消息类型
// =========================================================
typedef enum {
    // 控制命令 (0x01xx)
    V3_IPC_CMD_PING             = 0x0100,
    V3_IPC_CMD_PONG             = 0x0101,
    V3_IPC_CMD_CONNECT          = 0x0110,
    V3_IPC_CMD_DISCONNECT       = 0x0111,
    V3_IPC_CMD_RECONNECT        = 0x0112,
    V3_IPC_CMD_SHUTDOWN         = 0x01FF,
    
    // 配置命令 (0x02xx)
    V3_IPC_CMD_GET_CONFIG       = 0x0200,
    V3_IPC_CMD_SET_CONFIG       = 0x0201,
    V3_IPC_CMD_LOAD_CONFIG      = 0x0202,
    V3_IPC_CMD_SAVE_CONFIG      = 0x0203,
    
    // 状态查询 (0x03xx)
    V3_IPC_CMD_GET_STATE        = 0x0300,
    V3_IPC_CMD_GET_STATS        = 0x0301,
    V3_IPC_CMD_GET_VERSION      = 0x0302,
    V3_IPC_CMD_GET_LOG          = 0x0303,
    
    // 响应 (0x80xx)
    V3_IPC_RSP_OK               = 0x8000,
    V3_IPC_RSP_ERROR            = 0x8001,
    V3_IPC_RSP_CONFIG           = 0x8002,
    V3_IPC_RSP_STATE            = 0x8003,
    V3_IPC_RSP_STATS            = 0x8004,
    V3_IPC_RSP_VERSION          = 0x8005,
    V3_IPC_RSP_LOG              = 0x8006,
    
    // 事件通知 (0xE0xx)
    V3_IPC_EVT_STATE_CHANGED    = 0xE000,
    V3_IPC_EVT_STATS_UPDATE     = 0xE001,
    V3_IPC_EVT_ERROR            = 0xE002,
    V3_IPC_EVT_LOG              = 0xE003,
} v3_ipc_msg_type_t;

// =========================================================
// IPC 消息头
// =========================================================
#pragma pack(push, 1)
typedef struct {
    uint32_t magic;             // 'V3IP' = 0x50493356
    uint16_t version;           // 协议版本
    uint16_t type;              // v3_ipc_msg_type_t
    uint32_t seq;               // 序列号
    uint32_t payload_len;       // 负载长度
} v3_ipc_header_t;
#pragma pack(pop)

#define V3_IPC_MAGIC            0x50493356  // 'V3IP' in little-endian
#define V3_IPC_VERSION          0x0001
#define V3_IPC_HEADER_SIZE      sizeof(v3_ipc_header_t)

// =========================================================
// IPC 上下文
// =========================================================
typedef struct v3_ipc_server_s v3_ipc_server_t;
typedef struct v3_ipc_client_s v3_ipc_client_t;

// =========================================================
// IPC 回调
// =========================================================

// 服务端：收到客户端消息
typedef void (*v3_ipc_request_callback_t)(
    v3_ipc_server_t *server,
    uint32_t client_id,
    v3_ipc_msg_type_t type,
    const uint8_t *payload,
    uint32_t payload_len,
    void *userdata
);

// 服务端：客户端连接/断开
typedef void (*v3_ipc_client_callback_t)(
    v3_ipc_server_t *server,
    uint32_t client_id,
    bool connected,
    void *userdata
);

// 客户端：收到服务端响应/事件
typedef void (*v3_ipc_response_callback_t)(
    v3_ipc_client_t *client,
    v3_ipc_msg_type_t type,
    uint32_t seq,
    const uint8_t *payload,
    uint32_t payload_len,
    void *userdata
);

// =========================================================
// IPC 服务端 API（核心进程使用）
// =========================================================

/**
 * @brief 创建 IPC 服务端
 * @return 服务端句柄
 */
V3_API v3_ipc_server_t* v3_ipc_server_create(void);

/**
 * @brief 销毁 IPC 服务端
 */
V3_API void v3_ipc_server_destroy(v3_ipc_server_t *server);

/**
 * @brief 启动 IPC 服务端
 * @param server 服务端句柄
 * @param pipe_name 命名管道名称（NULL 使用默认）
 * @return V3_OK 成功
 */
V3_API v3_error_t v3_ipc_server_start(
    v3_ipc_server_t *server,
    const char *pipe_name
);

/**
 * @brief 停止 IPC 服务端
 */
V3_API void v3_ipc_server_stop(v3_ipc_server_t *server);

/**
 * @brief 设置请求回调
 */
V3_API void v3_ipc_server_set_request_callback(
    v3_ipc_server_t *server,
    v3_ipc_request_callback_t callback,
    void *userdata
);

/**
 * @brief 设置客户端连接回调
 */
V3_API void v3_ipc_server_set_client_callback(
    v3_ipc_server_t *server,
    v3_ipc_client_callback_t callback,
    void *userdata
);

/**
 * @brief 向客户端发送响应
 */
V3_API v3_error_t v3_ipc_server_respond(
    v3_ipc_server_t *server,
    uint32_t client_id,
    v3_ipc_msg_type_t type,
    uint32_t seq,
    const uint8_t *payload,
    uint32_t payload_len
);

/**
 * @brief 向所有客户端广播事件
 */
V3_API v3_error_t v3_ipc_server_broadcast(
    v3_ipc_server_t *server,
    v3_ipc_msg_type_t type,
    const uint8_t *payload,
    uint32_t payload_len
);

/**
 * @brief 获取已连接客户端数量
 */
V3_API int v3_ipc_server_client_count(v3_ipc_server_t *server);

// =========================================================
// IPC 客户端 API（GUI/CLI 使用）
// =========================================================

/**
 * @brief 创建 IPC 客户端
 */
V3_API v3_ipc_client_t* v3_ipc_client_create(void);

/**
 * @brief 销毁 IPC 客户端
 */
V3_API void v3_ipc_client_destroy(v3_ipc_client_t *client);

/**
 * @brief 连接到核心进程
 * @param client 客户端句柄
 * @param pipe_name 命名管道名称（NULL 使用默认）
 * @param timeout_ms 超时时间
 * @return V3_OK 成功
 */
V3_API v3_error_t v3_ipc_client_connect(
    v3_ipc_client_t *client,
    const char *pipe_name,
    uint32_t timeout_ms
);

/**
 * @brief 断开连接
 */
V3_API void v3_ipc_client_disconnect(v3_ipc_client_t *client);

/**
 * @brief 检查是否已连接
 */
V3_API bool v3_ipc_client_is_connected(v3_ipc_client_t *client);

/**
 * @brief 设置响应回调
 */
V3_API void v3_ipc_client_set_callback(
    v3_ipc_client_t *client,
    v3_ipc_response_callback_t callback,
    void *userdata
);

/**
 * @brief 发送请求（异步）
 * @return 序列号，可用于匹配响应
 */
V3_API uint32_t v3_ipc_client_send(
    v3_ipc_client_t *client,
    v3_ipc_msg_type_t type,
    const uint8_t *payload,
    uint32_t payload_len
);

/**
 * @brief 发送请求并等待响应（同步）
 * @param client 客户端句柄
 * @param type 请求类型
 * @param payload 请求负载
 * @param payload_len 负载长度
 * @param rsp_type 输出：响应类型
 * @param rsp_buf 输出缓冲区
 * @param rsp_buflen 缓冲区大小
 * @param timeout_ms 超时时间
 * @return 响应负载长度，负数为错误
 */
V3_API int v3_ipc_client_request(
    v3_ipc_client_t *client,
    v3_ipc_msg_type_t type,
    const uint8_t *payload,
    uint32_t payload_len,
    v3_ipc_msg_type_t *rsp_type,
    uint8_t *rsp_buf,
    uint32_t rsp_buflen,
    uint32_t timeout_ms
);

/**
 * @brief 处理待处理的消息（非阻塞）
 * @return 处理的消息数量
 */
V3_API int v3_ipc_client_poll(v3_ipc_client_t *client);

// =========================================================
// 便捷函数
// =========================================================

/**
 * @brief 发送 PING 并等待 PONG
 */
V3_API v3_error_t v3_ipc_ping(v3_ipc_client_t *client, uint32_t timeout_ms);

/**
 * @brief 获取核心状态
 */
V3_API v3_error_t v3_ipc_get_state(
    v3_ipc_client_t *client,
    v3_conn_state_t *out_state,
    uint32_t timeout_ms
);

/**
 * @brief 获取统计信息
 */
V3_API v3_error_t v3_ipc_get_stats(
    v3_ipc_client_t *client,
    v3_stats_t *out_stats,
    uint32_t timeout_ms
);

/**
 * @brief 请求连接
 */
V3_API v3_error_t v3_ipc_request_connect(
    v3_ipc_client_t *client,
    uint32_t timeout_ms
);

/**
 * @brief 请求断开
 */
V3_API v3_error_t v3_ipc_request_disconnect(
    v3_ipc_client_t *client,
    uint32_t timeout_ms
);

/**
 * @brief 请求关闭核心进程
 */
V3_API v3_error_t v3_ipc_request_shutdown(
    v3_ipc_client_t *client,
    uint32_t timeout_ms
);

#endif // V3_IPC_H

