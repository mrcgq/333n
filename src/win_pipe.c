
#define _WIN32_WINNT 0x0601
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "v3_ipc.h"
#include "v3_platform.h"
#include "version.h"

// =========================================================
// 管道配置
// =========================================================
#define PIPE_BUFFER_SIZE        65536
#define PIPE_TIMEOUT_MS         5000
#define PIPE_MAX_INSTANCES      10

// =========================================================
// 内部数据结构
// =========================================================
typedef struct {
    HANDLE          pipe;
    OVERLAPPED      overlap;
    HANDLE          event;
    BOOL            connected;
    BOOL            pending_io;
    
    uint8_t         recv_buf[PIPE_BUFFER_SIZE];
    uint32_t        recv_len;
    
    uint8_t         send_buf[PIPE_BUFFER_SIZE];
    uint32_t        send_len;
    
} pipe_instance_t;

typedef struct {
    WCHAR               name[256];
    pipe_instance_t     instances[PIPE_MAX_INSTANCES];
    int                 instance_count;
    
    HANDLE              thread;
    HANDLE              stop_event;
    volatile BOOL       running;
    
    v3_ipc_handler_t    handler;
    void               *handler_ctx;
    
    CRITICAL_SECTION    lock;
    
} pipe_server_t;

typedef struct {
    HANDLE      pipe;
    OVERLAPPED  overlap;
    HANDLE      event;
    BOOL        connected;
    
    uint8_t     recv_buf[PIPE_BUFFER_SIZE];
    uint8_t     send_buf[PIPE_BUFFER_SIZE];
    
} pipe_client_t;

// =========================================================
// 消息协议
// =========================================================
// 消息格式：[Length:4][Type:4][Data:N]

typedef struct __attribute__((packed)) {
    uint32_t    length;     // 消息总长度（包括头部）
    uint32_t    type;       // 消息类型
} pipe_msg_header_t;

#define MSG_HEADER_SIZE sizeof(pipe_msg_header_t)

// =========================================================
// 服务器实现
// =========================================================

static BOOL create_pipe_instance(pipe_server_t *server, int index) {
    pipe_instance_t *inst = &server->instances[index];
    
    memset(inst, 0, sizeof(pipe_instance_t));
    
    // 创建事件
    inst->event = CreateEvent(NULL, TRUE, FALSE, NULL);
    if (inst->event == NULL) return FALSE;
    
    inst->overlap.hEvent = inst->event;
    
    // 创建命名管道
    inst->pipe = CreateNamedPipeW(
        server->name,
        PIPE_ACCESS_DUPLEX | FILE_FLAG_OVERLAPPED,
        PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT,
        PIPE_MAX_INSTANCES,
        PIPE_BUFFER_SIZE,
        PIPE_BUFFER_SIZE,
        PIPE_TIMEOUT_MS,
        NULL  // 默认安全描述符
    );
    
    if (inst->pipe == INVALID_HANDLE_VALUE) {
        CloseHandle(inst->event);
        return FALSE;
    }
    
    // 开始等待连接
    if (ConnectNamedPipe(inst->pipe, &inst->overlap)) {
        // 立即连接（不应该发生在异步模式）
        inst->connected = TRUE;
    } else {
        DWORD err = GetLastError();
        if (err == ERROR_IO_PENDING) {
            inst->pending_io = TRUE;
        } else if (err == ERROR_PIPE_CONNECTED) {
            inst->connected = TRUE;
            SetEvent(inst->event);
        } else {
            CloseHandle(inst->pipe);
            CloseHandle(inst->event);
            return FALSE;
        }
    }
    
    return TRUE;
}

static void close_pipe_instance(pipe_instance_t *inst) {
    if (inst->pipe != INVALID_HANDLE_VALUE) {
        DisconnectNamedPipe(inst->pipe);
        CloseHandle(inst->pipe);
        inst->pipe = INVALID_HANDLE_VALUE;
    }
    if (inst->event != NULL) {
        CloseHandle(inst->event);
        inst->event = NULL;
    }
    inst->connected = FALSE;
    inst->pending_io = FALSE;
}

static BOOL handle_client_message(pipe_server_t *server, 
                                  pipe_instance_t *inst) {
    if (inst->recv_len < MSG_HEADER_SIZE) return TRUE;
    
    pipe_msg_header_t *hdr = (pipe_msg_header_t*)inst->recv_buf;
    
    if (hdr->length > PIPE_BUFFER_SIZE || hdr->length < MSG_HEADER_SIZE) {
        // 无效消息
        return FALSE;
    }
    
    if (inst->recv_len < hdr->length) {
        // 等待更多数据
        return TRUE;
    }
    
    // 完整消息，调用处理器
    if (server->handler) {
        v3_ipc_message_t msg = {
            .type = hdr->type,
            .data = inst->recv_buf + MSG_HEADER_SIZE,
            .length = hdr->length - MSG_HEADER_SIZE,
        };
        
        v3_ipc_message_t response = {0};
        
        int result = server->handler(&msg, &response, server->handler_ctx);
        
        if (result == 0 && response.length > 0) {
            // 发送响应
            pipe_msg_header_t resp_hdr = {
                .length = MSG_HEADER_SIZE + response.length,
                .type = response.type,
            };
            
            memcpy(inst->send_buf, &resp_hdr, MSG_HEADER_SIZE);
            memcpy(inst->send_buf + MSG_HEADER_SIZE, 
                   response.data, response.length);
            inst->send_len = resp_hdr.length;
            
            DWORD written;
            WriteFile(inst->pipe, inst->send_buf, inst->send_len,
                     &written, NULL);
        }
    }
    
    // 移动剩余数据
    if (inst->recv_len > hdr->length) {
        memmove(inst->recv_buf, 
                inst->recv_buf + hdr->length,
                inst->recv_len - hdr->length);
        inst->recv_len -= hdr->length;
    } else {
        inst->recv_len = 0;
    }
    
    return TRUE;
}

static DWORD WINAPI pipe_server_thread(LPVOID param) {
    pipe_server_t *server = (pipe_server_t*)param;
    
    // 创建等待事件数组
    HANDLE events[PIPE_MAX_INSTANCES + 1];
    events[0] = server->stop_event;
    
    for (int i = 0; i < server->instance_count; i++) {
        events[i + 1] = server->instances[i].event;
    }
    
    while (server->running) {
        DWORD result = WaitForMultipleObjects(
            server->instance_count + 1,
            events,
            FALSE,
            1000  // 1 秒超时
        );
        
        if (result == WAIT_OBJECT_0) {
            // 停止信号
            break;
        }
        
        if (result == WAIT_TIMEOUT) {
            continue;
        }
        
        if (result >= WAIT_OBJECT_0 + 1 && 
            result < WAIT_OBJECT_0 + 1 + server->instance_count) {
            
            int index = result - WAIT_OBJECT_0 - 1;
            pipe_instance_t *inst = &server->instances[index];
            
            ResetEvent(inst->event);
            
            if (inst->pending_io) {
                DWORD bytes;
                BOOL success = GetOverlappedResult(inst->pipe, 
                                                   &inst->overlap,
                                                   &bytes, FALSE);
                
                if (!success) {
                    // 连接失败，重新创建实例
                    close_pipe_instance(inst);
                    create_pipe_instance(server, index);
                    continue;
                }
                
                inst->pending_io = FALSE;
                inst->connected = TRUE;
            }
            
            if (inst->connected) {
                // 读取数据
                DWORD available = PIPE_BUFFER_SIZE - inst->recv_len;
                DWORD bytes_read = 0;
                
                BOOL success = ReadFile(
                    inst->pipe,
                    inst->recv_buf + inst->recv_len,
                    available,
                    &bytes_read,
                    &inst->overlap
                );
                
                if (success && bytes_read > 0) {
                    inst->recv_len += bytes_read;
                    
                    if (!handle_client_message(server, inst)) {
                        // 处理失败，断开连接
                        close_pipe_instance(inst);
                        create_pipe_instance(server, index);
                    }
                } else {
                    DWORD err = GetLastError();
                    if (err == ERROR_IO_PENDING) {
                        inst->pending_io = TRUE;
                    } else if (err == ERROR_BROKEN_PIPE || 
                               err == ERROR_PIPE_NOT_CONNECTED) {
                        // 客户端断开
                        close_pipe_instance(inst);
                        create_pipe_instance(server, index);
                    }
                }
            }
        }
    }
    
    return 0;
}

// =========================================================
// 公开 API - 服务器
// =========================================================

v3_ipc_server_t* v3_ipc_server_create(const char *name) {
    pipe_server_t *server = (pipe_server_t*)calloc(1, sizeof(pipe_server_t));
    if (server == NULL) return NULL;
    
    // 构建管道名称
    swprintf(server->name, 256, L"\\\\.\\pipe\\%S", name);
    
    InitializeCriticalSection(&server->lock);
    
    server->stop_event = CreateEvent(NULL, TRUE, FALSE, NULL);
    if (server->stop_event == NULL) {
        free(server);
        return NULL;
    }
    
    return (v3_ipc_server_t*)server;
}

int v3_ipc_server_start(v3_ipc_server_t *handle, 
                        v3_ipc_handler_t handler,
                        void *ctx) {
    pipe_server_t *server = (pipe_server_t*)handle;
    if (server == NULL) return -1;
    
    server->handler = handler;
    server->handler_ctx = ctx;
    
    // 创建管道实例
    server->instance_count = 2;  // 2 个并发连接
    
    for (int i = 0; i < server->instance_count; i++) {
        if (!create_pipe_instance(server, i)) {
            // 清理已创建的实例
            for (int j = 0; j < i; j++) {
                close_pipe_instance(&server->instances[j]);
            }
            return -1;
        }
    }
    
    server->running = TRUE;
    ResetEvent(server->stop_event);
    
    // 启动服务线程
    server->thread = CreateThread(NULL, 0, pipe_server_thread, 
                                  server, 0, NULL);
    if (server->thread == NULL) {
        for (int i = 0; i < server->instance_count; i++) {
            close_pipe_instance(&server->instances[i]);
        }
        return -1;
    }
    
    return 0;
}

int v3_ipc_server_stop(v3_ipc_server_t *handle) {
    pipe_server_t *server = (pipe_server_t*)handle;
    if (server == NULL) return -1;
    
    server->running = FALSE;
    SetEvent(server->stop_event);
    
    if (server->thread != NULL) {
        WaitForSingleObject(server->thread, 5000);
        CloseHandle(server->thread);
        server->thread = NULL;
    }
    
    for (int i = 0; i < server->instance_count; i++) {
        close_pipe_instance(&server->instances[i]);
    }
    
    return 0;
}

void v3_ipc_server_destroy(v3_ipc_server_t *handle) {
    pipe_server_t *server = (pipe_server_t*)handle;
    if (server == NULL) return;
    
    v3_ipc_server_stop(handle);
    
    if (server->stop_event != NULL) {
        CloseHandle(server->stop_event);
    }
    
    DeleteCriticalSection(&server->lock);
    
    free(server);
}

// =========================================================
// 公开 API - 客户端
// =========================================================

v3_ipc_client_t* v3_ipc_client_create(const char *name) {
    pipe_client_t *client = (pipe_client_t*)calloc(1, sizeof(pipe_client_t));
    if (client == NULL) return NULL;
    
    client->event = CreateEvent(NULL, TRUE, FALSE, NULL);
    if (client->event == NULL) {
        free(client);
        return NULL;
    }
    
    client->overlap.hEvent = client->event;
    
    // 构建管道名称
    WCHAR pipe_name[256];
    swprintf(pipe_name, 256, L"\\\\.\\pipe\\%S", name);
    
    // 等待管道可用
    if (!WaitNamedPipeW(pipe_name, PIPE_TIMEOUT_MS)) {
        CloseHandle(client->event);
        free(client);
        return NULL;
    }
    
    // 打开管道
    client->pipe = CreateFileW(
        pipe_name,
        GENERIC_READ | GENERIC_WRITE,
        0,
        NULL,
        OPEN_EXISTING,
        FILE_FLAG_OVERLAPPED,
        NULL
    );
    
    if (client->pipe == INVALID_HANDLE_VALUE) {
        CloseHandle(client->event);
        free(client);
        return NULL;
    }
    
    // 设置为消息模式
    DWORD mode = PIPE_READMODE_MESSAGE;
    SetNamedPipeHandleState(client->pipe, &mode, NULL, NULL);
    
    client->connected = TRUE;
    
    return (v3_ipc_client_t*)client;
}

int v3_ipc_client_send(v3_ipc_client_t *handle,
                       const v3_ipc_message_t *msg,
                       v3_ipc_message_t *response,
                       int timeout_ms) {
    pipe_client_t *client = (pipe_client_t*)handle;
    if (client == NULL || !client->connected) return -1;
    
    // 构建消息
    pipe_msg_header_t hdr = {
        .length = MSG_HEADER_SIZE + msg->length,
        .type = msg->type,
    };
    
    memcpy(client->send_buf, &hdr, MSG_HEADER_SIZE);
    if (msg->length > 0 && msg->data != NULL) {
        memcpy(client->send_buf + MSG_HEADER_SIZE, msg->data, msg->length);
    }
    
    // 发送
    DWORD written;
    if (!WriteFile(client->pipe, client->send_buf, hdr.length, 
                   &written, NULL)) {
        return -1;
    }
    
    // 等待响应
    if (response == NULL) return 0;
    
    DWORD bytes_read;
    if (!ReadFile(client->pipe, client->recv_buf, PIPE_BUFFER_SIZE,
                  &bytes_read, &client->overlap)) {
        if (GetLastError() != ERROR_IO_PENDING) {
            return -1;
        }
        
        DWORD result = WaitForSingleObject(client->event, 
                                           timeout_ms > 0 ? timeout_ms : INFINITE);
        if (result != WAIT_OBJECT_0) {
            CancelIo(client->pipe);
            return -1;
        }
        
        GetOverlappedResult(client->pipe, &client->overlap, 
                           &bytes_read, FALSE);
    }
    
    ResetEvent(client->event);
    
    if (bytes_read < MSG_HEADER_SIZE) {
        return -1;
    }
    
    pipe_msg_header_t *resp_hdr = (pipe_msg_header_t*)client->recv_buf;
    
    response->type = resp_hdr->type;
    response->length = resp_hdr->length - MSG_HEADER_SIZE;
    
    if (response->length > 0) {
        response->data = malloc(response->length);
        if (response->data) {
            memcpy(response->data, 
                   client->recv_buf + MSG_HEADER_SIZE,
                   response->length);
        }
    }
    
    return 0;
}

void v3_ipc_client_destroy(v3_ipc_client_t *handle) {
    pipe_client_t *client = (pipe_client_t*)handle;
    if (client == NULL) return;
    
    if (client->pipe != INVALID_HANDLE_VALUE) {
        CloseHandle(client->pipe);
    }
    if (client->event != NULL) {
        CloseHandle(client->event);
    }
    
    free(client);
}

void v3_ipc_message_free(v3_ipc_message_t *msg) {
    if (msg && msg->data) {
        free(msg->data);
        msg->data = NULL;
        msg->length = 0;
    }
}


