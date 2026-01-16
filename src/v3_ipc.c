
#define _CRT_SECURE_NO_WARNINGS
#define V3_BUILDING_CORE

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "v3_ipc.h"
#include "v3_platform.h"

#ifdef V3_PLATFORM_WINDOWS
#include <windows.h>
#endif

// =========================================================
// IPC 服务端结构
// =========================================================
struct v3_ipc_server_s {
    char                pipe_name[256];
    bool                running;
    
    v3_thread_t         accept_thread;
    v3_event_t          stop_event;
    v3_mutex_t          mutex;
    
    // 客户端列表
    struct {
        HANDLE          pipe;
        uint32_t        id;
        bool            active;
        v3_thread_t     thread;
    } clients[V3_IPC_MAX_CLIENTS];
    int                 client_count;
    uint32_t            next_client_id;
    
    // 回调
    v3_ipc_request_callback_t   request_callback;
    void                        *request_userdata;
    v3_ipc_client_callback_t    client_callback;
    void                        *client_userdata;
};

// =========================================================
// IPC 客户端结构
// =========================================================
struct v3_ipc_client_s {
    HANDLE              pipe;
    bool                connected;
    v3_mutex_t          mutex;
    
    uint32_t            next_seq;
    
    // 回调
    v3_ipc_response_callback_t  response_callback;
    void                        *response_userdata;
    
    // 接收线程
    v3_thread_t         recv_thread;
    bool                recv_running;
};

// =========================================================
// 辅助函数
// =========================================================

static bool send_message(HANDLE pipe, v3_ipc_msg_type_t type, uint32_t seq,
                         const uint8_t *payload, uint32_t payload_len) {
    v3_ipc_header_t header = {
        .magic = V3_IPC_MAGIC,
        .version = V3_IPC_VERSION,
        .type = type,
        .seq = seq,
        .payload_len = payload_len,
    };
    
    DWORD written;
    
    if (!WriteFile(pipe, &header, sizeof(header), &written, NULL) ||
        written != sizeof(header)) {
        return false;
    }
    
    if (payload_len > 0 && payload) {
        if (!WriteFile(pipe, payload, payload_len, &written, NULL) ||
            written != payload_len) {
            return false;
        }
    }
    
    return true;
}

static bool recv_message(HANDLE pipe, v3_ipc_header_t *header,
                         uint8_t *payload, uint32_t payload_buflen,
                         uint32_t timeout_ms) {
    DWORD read;
    
    // 设置超时
    COMMTIMEOUTS timeouts = {
        .ReadIntervalTimeout = 0,
        .ReadTotalTimeoutMultiplier = 0,
        .ReadTotalTimeoutConstant = timeout_ms,
    };
    SetCommTimeouts(pipe, &timeouts);
    
    // 读取头部
    if (!ReadFile(pipe, header, sizeof(*header), &read, NULL) ||
        read != sizeof(*header)) {
        return false;
    }
    
    // 验证头部
    if (header->magic != V3_IPC_MAGIC || header->version != V3_IPC_VERSION) {
        return false;
    }
    
    // 读取负载
    if (header->payload_len > 0) {
        if (header->payload_len > payload_buflen) {
            // 缓冲区太小，丢弃数据
            uint8_t discard[256];
            uint32_t remaining = header->payload_len;
            while (remaining > 0) {
                DWORD to_read = remaining > sizeof(discard) ? sizeof(discard) : remaining;
                if (!ReadFile(pipe, discard, to_read, &read, NULL)) {
                    return false;
                }
                remaining -= read;
            }
            return false;
        }
        
        if (!ReadFile(pipe, payload, header->payload_len, &read, NULL) ||
            read != header->payload_len) {
            return false;
        }
    }
    
    return true;
}

// =========================================================
// 服务端线程
// =========================================================

static void* client_handler_thread(void *arg);

static void* accept_thread_func(void *arg) {
    v3_ipc_server_t *server = (v3_ipc_server_t *)arg;
    
    while (server->running) {
        // 创建命名管道实例
        HANDLE pipe = CreateNamedPipeA(
            server->pipe_name,
            PIPE_ACCESS_DUPLEX,
            PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT,
            PIPE_UNLIMITED_INSTANCES,
            V3_IPC_BUFFER_SIZE,
            V3_IPC_BUFFER_SIZE,
            V3_IPC_TIMEOUT_MS,
            NULL
        );
        
        if (pipe == INVALID_HANDLE_VALUE) {
            v3_sleep_ms(100);
            continue;
        }
        
        // 等待客户端连接
        BOOL connected = ConnectNamedPipe(pipe, NULL);
        if (!connected && GetLastError() != ERROR_PIPE_CONNECTED) {
            CloseHandle(pipe);
            continue;
        }
        
        if (!server->running) {
            CloseHandle(pipe);
            break;
        }
        
        // 查找空闲槽位
        v3_mutex_lock(&server->mutex);
        
        int slot = -1;
        for (int i = 0; i < V3_IPC_MAX_CLIENTS; i++) {
            if (!server->clients[i].active) {
                slot = i;
                break;
            }
        }
        
        if (slot < 0) {
            v3_mutex_unlock(&server->mutex);
            CloseHandle(pipe);
            continue;
        }
        
        server->clients[slot].pipe = pipe;
        server->clients[slot].id = ++server->next_client_id;
        server->clients[slot].active = true;
        server->client_count++;
        
        // 启动客户端处理线程
        struct {
            v3_ipc_server_t *server;
            int slot;
        } *ctx = malloc(sizeof(*ctx));
        ctx->server = server;
        ctx->slot = slot;
        
        v3_thread_create(&server->clients[slot].thread, client_handler_thread, ctx);
        
        v3_mutex_unlock(&server->mutex);
        
        // 通知客户端连接
        if (server->client_callback) {
            server->client_callback(server, server->clients[slot].id, true,
                                    server->client_userdata);
        }
    }
    
    return NULL;
}

static void* client_handler_thread(void *arg) {
    struct {
        v3_ipc_server_t *server;
        int slot;
    } *ctx = arg;
    
    v3_ipc_server_t *server = ctx->server;
    int slot = ctx->slot;
    free(ctx);
    
    HANDLE pipe = server->clients[slot].pipe;
    uint32_t client_id = server->clients[slot].id;
    
    v3_ipc_header_t header;
    uint8_t payload[V3_IPC_BUFFER_SIZE];
    
    while (server->running && server->clients[slot].active) {
        if (recv_message(pipe, &header, payload, sizeof(payload), 1000)) {
            if (server->request_callback) {
                server->request_callback(server, client_id, header.type,
                                         payload, header.payload_len,
                                         server->request_userdata);
            }
        }
    }
    
    // 清理
    v3_mutex_lock(&server->mutex);
    
    CloseHandle(server->clients[slot].pipe);
    server->clients[slot].active = false;
    server->client_count--;
    
    v3_mutex_unlock(&server->mutex);
    
    // 通知客户端断开
    if (server->client_callback) {
        server->client_callback(server, client_id, false, server->client_userdata);
    }
    
    return NULL;
}

// =========================================================
// 服务端 API
// =========================================================

v3_ipc_server_t* v3_ipc_server_create(void) {
    v3_ipc_server_t *server = (v3_ipc_server_t *)calloc(1, sizeof(v3_ipc_server_t));
    if (!server) return NULL;
    
    v3_mutex_init(&server->mutex);
    v3_event_init(&server->stop_event, true);
    
    return server;
}

void v3_ipc_server_destroy(v3_ipc_server_t *server) {
    if (!server) return;
    
    v3_ipc_server_stop(server);
    
    v3_event_destroy(&server->stop_event);
    v3_mutex_destroy(&server->mutex);
    
    free(server);
}

v3_error_t v3_ipc_server_start(v3_ipc_server_t *server, const char *pipe_name) {
    if (!server) return V3_ERR_INVALID_PARAM;
    
    if (server->running) return V3_ERR_ALREADY_RUNNING;
    
    if (pipe_name) {
        strncpy(server->pipe_name, pipe_name, sizeof(server->pipe_name) - 1);
    } else {
        snprintf(server->pipe_name, sizeof(server->pipe_name),
                 V3_IPC_PIPE_NAME_FMT, v3_getpid());
    }
    
    server->running = true;
    v3_event_reset(&server->stop_event);
    
    v3_error_t err = v3_thread_create(&server->accept_thread, accept_thread_func, server);
    if (err != V3_OK) {
        server->running = false;
        return err;
    }
    
    return V3_OK;
}

void v3_ipc_server_stop(v3_ipc_server_t *server) {
    if (!server || !server->running) return;
    
    server->running = false;
    v3_event_set(&server->stop_event);
    
    // 关闭所有客户端
    v3_mutex_lock(&server->mutex);
    
    for (int i = 0; i < V3_IPC_MAX_CLIENTS; i++) {
        if (server->clients[i].active) {
            server->clients[i].active = false;
            DisconnectNamedPipe(server->clients[i].pipe);
            CloseHandle(server->clients[i].pipe);
        }
    }
    
    v3_mutex_unlock(&server->mutex);
    
    // 创建一个虚拟连接来唤醒 accept 线程
    HANDLE dummy = CreateFileA(
        server->pipe_name,
        GENERIC_READ | GENERIC_WRITE,
        0, NULL, OPEN_EXISTING, 0, NULL
    );
    if (dummy != INVALID_HANDLE_VALUE) {
        CloseHandle(dummy);
    }
    
    v3_thread_join(server->accept_thread, NULL);
}

void v3_ipc_server_set_request_callback(v3_ipc_server_t *server,
                                         v3_ipc_request_callback_t callback,
                                         void *userdata) {
    if (!server) return;
    server->request_callback = callback;
    server->request_userdata = userdata;
}

void v3_ipc_server_set_client_callback(v3_ipc_server_t *server,
                                        v3_ipc_client_callback_t callback,
                                        void *userdata) {
    if (!server) return;
    server->client_callback = callback;
    server->client_userdata = userdata;
}

v3_error_t v3_ipc_server_respond(v3_ipc_server_t *server, uint32_t client_id,
                                  v3_ipc_msg_type_t type, uint32_t seq,
                                  const uint8_t *payload, uint32_t payload_len) {
    if (!server) return V3_ERR_INVALID_PARAM;
    
    v3_mutex_lock(&server->mutex);
    
    HANDLE pipe = INVALID_HANDLE_VALUE;
    for (int i = 0; i < V3_IPC_MAX_CLIENTS; i++) {
        if (server->clients[i].active && server->clients[i].id == client_id) {
            pipe = server->clients[i].pipe;
            break;
        }
    }
    
    v3_mutex_unlock(&server->mutex);
    
    if (pipe == INVALID_HANDLE_VALUE) {
        return V3_ERR_NOT_CONNECTED;
    }
    
    if (!send_message(pipe, type, seq, payload, payload_len)) {
        return V3_ERR_IPC;
    }
    
    return V3_OK;
}

v3_error_t v3_ipc_server_broadcast(v3_ipc_server_t *server, v3_ipc_msg_type_t type,
                                    const uint8_t *payload, uint32_t payload_len) {
    if (!server) return V3_ERR_INVALID_PARAM;
    
    v3_mutex_lock(&server->mutex);
    
    for (int i = 0; i < V3_IPC_MAX_CLIENTS; i++) {
        if (server->clients[i].active) {
            send_message(server->clients[i].pipe, type, 0, payload, payload_len);
        }
    }
    
    v3_mutex_unlock(&server->mutex);
    
    return V3_OK;
}

int v3_ipc_server_client_count(v3_ipc_server_t *server) {
    if (!server) return 0;
    return server->client_count;
}

// =========================================================
// 客户端 API
// =========================================================

v3_ipc_client_t* v3_ipc_client_create(void) {
    v3_ipc_client_t *client = (v3_ipc_client_t *)calloc(1, sizeof(v3_ipc_client_t));
    if (!client) return NULL;
    
    client->pipe = INVALID_HANDLE_VALUE;
    v3_mutex_init(&client->mutex);
    
    return client;
}

void v3_ipc_client_destroy(v3_ipc_client_t *client) {
    if (!client) return;
    
    v3_ipc_client_disconnect(client);
    v3_mutex_destroy(&client->mutex);
    
    free(client);
}

v3_error_t v3_ipc_client_connect(v3_ipc_client_t *client, const char *pipe_name,
                                  uint32_t timeout_ms) {
    if (!client) return V3_ERR_INVALID_PARAM;
    
    if (client->connected) return V3_ERR_ALREADY_RUNNING;
    
    char name[256];
    if (pipe_name) {
        strncpy(name, pipe_name, sizeof(name) - 1);
    } else {
        // 尝试查找运行中的实例
        uint32_t pid = v3_get_running_instance_pid();
        if (pid) {
            snprintf(name, sizeof(name), V3_IPC_PIPE_NAME_FMT, pid);
        } else {
            return V3_ERR_NOT_CONNECTED;
        }
    }
    
    // 等待管道可用
    if (!WaitNamedPipeA(name, timeout_ms)) {
        return V3_ERR_TIMEOUT;
    }
    
    // 连接到管道
    client->pipe = CreateFileA(
        name,
        GENERIC_READ | GENERIC_WRITE,
        0,
        NULL,
        OPEN_EXISTING,
        0,
        NULL
    );
    
    if (client->pipe == INVALID_HANDLE_VALUE) {
        return V3_ERR_IPC;
    }
    
    // 设置为消息模式
    DWORD mode = PIPE_READMODE_MESSAGE;
    SetNamedPipeHandleState(client->pipe, &mode, NULL, NULL);
    
    client->connected = true;
    
    return V3_OK;
}

void v3_ipc_client_disconnect(v3_ipc_client_t *client) {
    if (!client) return;
    
    client->connected = false;
    
    if (client->pipe != INVALID_HANDLE_VALUE) {
        CloseHandle(client->pipe);
        client->pipe = INVALID_HANDLE_VALUE;
    }
}

bool v3_ipc_client_is_connected(v3_ipc_client_t *client) {
    return client && client->connected;
}

void v3_ipc_client_set_callback(v3_ipc_client_t *client,
                                 v3_ipc_response_callback_t callback,
                                 void *userdata) {
    if (!client) return;
    client->response_callback = callback;
    client->response_userdata = userdata;
}

uint32_t v3_ipc_client_send(v3_ipc_client_t *client, v3_ipc_msg_type_t type,
                             const uint8_t *payload, uint32_t payload_len) {
    if (!client || !client->connected) return 0;
    
    v3_mutex_lock(&client->mutex);
    
    uint32_t seq = ++client->next_seq;
    
    if (!send_message(client->pipe, type, seq, payload, payload_len)) {
        v3_mutex_unlock(&client->mutex);
        return 0;
    }
    
    v3_mutex_unlock(&client->mutex);
    
    return seq;
}

int v3_ipc_client_request(v3_ipc_client_t *client, v3_ipc_msg_type_t type,
                           const uint8_t *payload, uint32_t payload_len,
                           v3_ipc_msg_type_t *rsp_type, uint8_t *rsp_buf,
                           uint32_t rsp_buflen, uint32_t timeout_ms) {
    if (!client || !client->connected) return V3_ERR_NOT_CONNECTED;
    
    v3_mutex_lock(&client->mutex);
    
    uint32_t seq = ++client->next_seq;
    
    if (!send_message(client->pipe, type, seq, payload, payload_len)) {
        v3_mutex_unlock(&client->mutex);
        return V3_ERR_IPC;
    }
    
    v3_ipc_header_t header;
    if (!recv_message(client->pipe, &header, rsp_buf, rsp_buflen, timeout_ms)) {
        v3_mutex_unlock(&client->mutex);
        return V3_ERR_TIMEOUT;
    }
    
    v3_mutex_unlock(&client->mutex);
    
    if (rsp_type) *rsp_type = header.type;
    
    return (int)header.payload_len;
}

int v3_ipc_client_poll(v3_ipc_client_t *client) {
    // Windows 命名管道是同步的，这个函数在这个实现中不需要
    (void)client;
    return 0;
}

// =========================================================
// 便捷函数
// =========================================================

v3_error_t v3_ipc_ping(v3_ipc_client_t *client, uint32_t timeout_ms) {
    v3_ipc_msg_type_t rsp_type;
    int result = v3_ipc_client_request(client, V3_IPC_CMD_PING, NULL, 0,
                                        &rsp_type, NULL, 0, timeout_ms);
    
    if (result < 0) return (v3_error_t)result;
    if (rsp_type != V3_IPC_CMD_PONG) return V3_ERR_IPC;
    
    return V3_OK;
}

v3_error_t v3_ipc_get_state(v3_ipc_client_t *client, v3_conn_state_t *out_state,
                             uint32_t timeout_ms) {
    v3_ipc_msg_type_t rsp_type;
    v3_conn_state_t state;
    
    int result = v3_ipc_client_request(client, V3_IPC_CMD_GET_STATE, NULL, 0,
                                        &rsp_type, (uint8_t *)&state,
                                        sizeof(state), timeout_ms);
    
    if (result < 0) return (v3_error_t)result;
    if (rsp_type != V3_IPC_RSP_STATE) return V3_ERR_IPC;
    
    if (out_state) *out_state = state;
    return V3_OK;
}

v3_error_t v3_ipc_get_stats(v3_ipc_client_t *client, v3_stats_t *out_stats,
                             uint32_t timeout_ms) {
    v3_ipc_msg_type_t rsp_type;
    v3_stats_t stats;
    
    int result = v3_ipc_client_request(client, V3_IPC_CMD_GET_STATS, NULL, 0,
                                        &rsp_type, (uint8_t *)&stats,
                                        sizeof(stats), timeout_ms);
    
    if (result < 0) return (v3_error_t)result;
    if (rsp_type != V3_IPC_RSP_STATS) return V3_ERR_IPC;
    
    if (out_stats) memcpy(out_stats, &stats, sizeof(stats));
    return V3_OK;
}

v3_error_t v3_ipc_request_connect(v3_ipc_client_t *client, uint32_t timeout_ms) {
    v3_ipc_msg_type_t rsp_type;
    int result = v3_ipc_client_request(client, V3_IPC_CMD_CONNECT, NULL, 0,
                                        &rsp_type, NULL, 0, timeout_ms);
    
    if (result < 0) return (v3_error_t)result;
    if (rsp_type != V3_IPC_RSP_OK) return V3_ERR_IPC;
    
    return V3_OK;
}

v3_error_t v3_ipc_request_disconnect(v3_ipc_client_t *client, uint32_t timeout_ms) {
    v3_ipc_msg_type_t rsp_type;
    int result = v3_ipc_client_request(client, V3_IPC_CMD_DISCONNECT, NULL, 0,
                                        &rsp_type, NULL, 0, timeout_ms);
    
    if (result < 0) return (v3_error_t)result;
    if (rsp_type != V3_IPC_RSP_OK) return V3_ERR_IPC;
    
    return V3_OK;
}

v3_error_t v3_ipc_request_shutdown(v3_ipc_client_t *client, uint32_t timeout_ms) {
    v3_ipc_msg_type_t rsp_type;
    int result = v3_ipc_client_request(client, V3_IPC_CMD_SHUTDOWN, NULL, 0,
                                        &rsp_type, NULL, 0, timeout_ms);
    
    if (result < 0) return (v3_error_t)result;
    
    return V3_OK;
}









