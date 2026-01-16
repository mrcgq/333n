
#define _CRT_SECURE_NO_WARNINGS
#define V3_BUILDING_CORE

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "v3_lifecycle.h"
#include "v3_ipc.h"
#include "v3_guard.h"
#include "v3_platform.h"

// =========================================================
// 生命周期上下文结构
// =========================================================
struct v3_lifecycle_s {
    // 状态
    v3_lifecycle_state_t    state;
    v3_mutex_t              state_mutex;
    
    // 核心组件
    v3_context_t            *context;
    v3_config_t             config;
    v3_ipc_server_t         *ipc_server;
    v3_guard_t              *guard;
    
    // 启动选项
    v3_startup_options_t    options;
    
    // 线程
    v3_thread_t             main_thread;
    v3_thread_t             ipc_thread;
    v3_event_t              stop_event;
    
    // 回调
    v3_lifecycle_state_callback_t   state_callback;
    void                            *state_callback_userdata;
    v3_lifecycle_exit_callback_t    exit_callback;
    void                            *exit_callback_userdata;
    
    // 退出信息
    v3_exit_reason_t        exit_reason;
    int                     exit_code;
    
    // PID 文件
    char                    pid_file_path[260];
    
    // 日志文件
    FILE                    *log_file;
};

// =========================================================
// 内部函数声明
// =========================================================
static void set_state(v3_lifecycle_t *lc, v3_lifecycle_state_t new_state);
static void* main_thread_func(void *arg);
static void handle_ipc_request(v3_ipc_server_t *server, uint32_t client_id,
                               v3_ipc_msg_type_t type, const uint8_t *payload,
                               uint32_t payload_len, void *userdata);

// =========================================================
// 生命周期 API 实现
// =========================================================

v3_lifecycle_t* v3_lifecycle_create(void) {
    v3_lifecycle_t *lc = (v3_lifecycle_t *)calloc(1, sizeof(v3_lifecycle_t));
    if (!lc) return NULL;
    
    lc->state = V3_LIFECYCLE_STOPPED;
    v3_mutex_init(&lc->state_mutex);
    v3_event_init(&lc->stop_event, true);  // Manual reset
    
    return lc;
}

void v3_lifecycle_destroy(v3_lifecycle_t *lc) {
    if (!lc) return;
    
    // 确保已停止
    if (lc->state != V3_LIFECYCLE_STOPPED) {
        v3_lifecycle_stop(lc, V3_EXIT_NORMAL);
    }
    
    // 清理组件
    if (lc->guard) {
        v3_guard_destroy(lc->guard);
    }
    
    if (lc->ipc_server) {
        v3_ipc_server_destroy(lc->ipc_server);
    }
    
    if (lc->context) {
        v3_context_destroy(lc->context);
    }
    
    // 删除 PID 文件
    if (lc->pid_file_path[0]) {
        v3_pid_file_remove(lc->pid_file_path);
    }
    
    // 关闭日志
    if (lc->log_file) {
        fclose(lc->log_file);
    }
    
    v3_event_destroy(&lc->stop_event);
    v3_mutex_destroy(&lc->state_mutex);
    
    free(lc);
}

v3_error_t v3_lifecycle_init(v3_lifecycle_t *lc, int argc, char **argv,
                              const v3_startup_options_t *options) {
    if (!lc || !options) {
        return V3_ERR_INVALID_PARAM;
    }
    
    // 保存选项
    memcpy(&lc->options, options, sizeof(v3_startup_options_t));
    
    // 加载配置
    v3_config_init_default(&lc->config);
    
    if (options->config_path) {
        v3_error_t err = v3_config_load(&lc->config, options->config_path);
        if (err != V3_OK) {
            fprintf(stderr, "Warning: Failed to load config from %s: %s\n",
                    options->config_path, v3_error_string(err));
        }
    } else {
        // 尝试加载默认配置
        v3_config_load(&lc->config, NULL);
    }
    
    // 设置日志
    if (lc->config.log.to_file && lc->config.log.file_path[0]) {
        lc->log_file = fopen(lc->config.log.file_path, "a");
    }
    
    // 设置 PID 文件路径
    if (options->pid_file) {
        strncpy(lc->pid_file_path, options->pid_file, sizeof(lc->pid_file_path) - 1);
    } else if (options->single_instance) {
        char app_dir[260];
        if (v3_get_app_data_dir(app_dir, sizeof(app_dir)) > 0) {
            snprintf(lc->pid_file_path, sizeof(lc->pid_file_path),
                     "%s\\v3_core.pid", app_dir);
        }
    }
    
    // 创建核心上下文
    lc->context = v3_context_create();
    if (!lc->context) {
        return V3_ERR_NO_MEMORY;
    }
    
    // 应用服务器配置
    const v3_server_config_t *server = v3_config_get_active_server(&lc->config);
    if (server && server->address[0]) {
        v3_set_server(lc->context, server->address, server->port, server->key);
        
        if (server->local_address[0] || server->local_port) {
            v3_set_local(lc->context, 
                         server->local_address[0] ? server->local_address : NULL,
                         server->local_port);
        }
    }
    
    // 创建 IPC 服务器
    if (options->enable_ipc) {
        lc->ipc_server = v3_ipc_server_create();
        if (lc->ipc_server) {
            v3_ipc_server_set_request_callback(lc->ipc_server, 
                                                handle_ipc_request, lc);
        }
    }
    
    // 创建守护管理器
    if (options->enable_guard) {
        lc->guard = v3_guard_create();
        if (lc->guard) {
            v3_guard_config_t guard_config = {
                .mode = V3_GUARD_MODE_RESTART,
                .restart_delay_sec = lc->config.system.reconnect_delay_sec,
                .max_restarts = lc->config.system.reconnect_max_attempts,
                .restart_window_sec = 300,
                .health_check_interval_sec = 30,
                .auto_reconnect_on_unhealthy = lc->config.system.auto_reconnect,
            };
            v3_guard_init(lc->guard, lc->context, &guard_config);
        }
    }
    
    return V3_OK;
}

v3_error_t v3_lifecycle_start(v3_lifecycle_t *lc) {
    if (!lc) return V3_ERR_INVALID_PARAM;
    
    v3_mutex_lock(&lc->state_mutex);
    
    if (lc->state != V3_LIFECYCLE_STOPPED) {
        v3_mutex_unlock(&lc->state_mutex);
        return V3_ERR_ALREADY_RUNNING;
    }
    
    set_state(lc, V3_LIFECYCLE_STARTING);
    
    v3_mutex_unlock(&lc->state_mutex);
    
    // 创建 PID 文件
    if (lc->pid_file_path[0]) {
        v3_error_t err = v3_pid_file_create(lc->pid_file_path);
        if (err != V3_OK) {
            fprintf(stderr, "Warning: Failed to create PID file: %s\n",
                    v3_error_string(err));
        }
    }
    
    // 启动 IPC 服务器
    if (lc->ipc_server) {
        v3_error_t err = v3_ipc_server_start(lc->ipc_server, NULL);
        if (err != V3_OK) {
            fprintf(stderr, "Warning: Failed to start IPC server: %s\n",
                    v3_error_string(err));
        }
    }
    
    // 启动守护
    if (lc->guard) {
        v3_guard_start(lc->guard);
    }
    
    // 重置停止事件
    v3_event_reset(&lc->stop_event);
    
    // 连接到服务器
    if (lc->config.server_count > 0 && lc->config.active_server >= 0) {
        v3_error_t err = v3_connect(lc->context);
        if (err != V3_OK) {
            fprintf(stderr, "Warning: Initial connection failed: %s\n",
                    v3_error_string(err));
            // 不作为致命错误，守护模块会处理重连
        }
    }
    
    set_state(lc, V3_LIFECYCLE_RUNNING);
    
    return V3_OK;
}

void v3_lifecycle_stop(v3_lifecycle_t *lc, v3_exit_reason_t reason) {
    if (!lc) return;
    
    v3_mutex_lock(&lc->state_mutex);
    
    if (lc->state == V3_LIFECYCLE_STOPPED || 
        lc->state == V3_LIFECYCLE_STOPPING) {
        v3_mutex_unlock(&lc->state_mutex);
        return;
    }
    
    set_state(lc, V3_LIFECYCLE_STOPPING);
    lc->exit_reason = reason;
    
    v3_mutex_unlock(&lc->state_mutex);
    
    // 停止守护
    if (lc->guard) {
        v3_guard_stop(lc->guard);
    }
    
    // 断开连接
    v3_disconnect(lc->context);
    
    // 停止 IPC 服务器
    if (lc->ipc_server) {
        v3_ipc_server_stop(lc->ipc_server);
    }
    
    // 设置停止事件
    v3_event_set(&lc->stop_event);
    
    // 调用退出回调
    if (lc->exit_callback) {
        lc->exit_callback(lc, reason, lc->exit_code, lc->exit_callback_userdata);
    }
    
    set_state(lc, V3_LIFECYCLE_STOPPED);
}

void v3_lifecycle_restart(v3_lifecycle_t *lc) {
    if (!lc) return;
    
    set_state(lc, V3_LIFECYCLE_RESTARTING);
    
    // 断开当前连接
    v3_disconnect(lc->context);
    
    // 短暂等待
    v3_sleep_ms(1000);
    
    // 重新连接
    v3_connect(lc->context);
    
    set_state(lc, V3_LIFECYCLE_RUNNING);
}

int v3_lifecycle_run(v3_lifecycle_t *lc) {
    if (!lc) return -1;
    
    // 等待停止事件
    while (lc->state == V3_LIFECYCLE_RUNNING || 
           lc->state == V3_LIFECYCLE_RESTARTING) {
        v3_error_t err = v3_event_wait(&lc->stop_event, 1000);
        
        if (err == V3_OK) {
            // 停止事件被触发
            break;
        }
        
        // 周期性任务
        if (lc->guard) {
            v3_guard_watchdog_kick(lc->guard);
        }
    }
    
    return lc->exit_code;
}

v3_lifecycle_state_t v3_lifecycle_get_state(v3_lifecycle_t *lc) {
    if (!lc) return V3_LIFECYCLE_STOPPED;
    return lc->state;
}

v3_context_t* v3_lifecycle_get_context(v3_lifecycle_t *lc) {
    if (!lc) return NULL;
    return lc->context;
}

v3_config_t* v3_lifecycle_get_config(v3_lifecycle_t *lc) {
    if (!lc) return NULL;
    return &lc->config;
}

void v3_lifecycle_set_state_callback(v3_lifecycle_t *lc,
                                      v3_lifecycle_state_callback_t callback,
                                      void *userdata) {
    if (!lc) return;
    lc->state_callback = callback;
    lc->state_callback_userdata = userdata;
}

void v3_lifecycle_set_exit_callback(v3_lifecycle_t *lc,
                                     v3_lifecycle_exit_callback_t callback,
                                     void *userdata) {
    if (!lc) return;
    lc->exit_callback = callback;
    lc->exit_callback_userdata = userdata;
}

// =========================================================
// 内部函数实现
// =========================================================

static void set_state(v3_lifecycle_t *lc, v3_lifecycle_state_t new_state) {
    v3_lifecycle_state_t old_state = lc->state;
    lc->state = new_state;
    
    if (lc->state_callback && old_state != new_state) {
        lc->state_callback(lc, old_state, new_state, lc->state_callback_userdata);
    }
}

static void handle_ipc_request(v3_ipc_server_t *server, uint32_t client_id,
                               v3_ipc_msg_type_t type, const uint8_t *payload,
                               uint32_t payload_len, void *userdata) {
    v3_lifecycle_t *lc = (v3_lifecycle_t *)userdata;
    
    switch (type) {
        case V3_IPC_CMD_PING:
            v3_ipc_server_respond(server, client_id, V3_IPC_CMD_PONG, 0, NULL, 0);
            break;
            
        case V3_IPC_CMD_GET_STATE: {
            v3_conn_state_t state = v3_get_state(lc->context);
            v3_ipc_server_respond(server, client_id, V3_IPC_RSP_STATE, 0,
                                  (uint8_t *)&state, sizeof(state));
            break;
        }
            
        case V3_IPC_CMD_GET_STATS: {
            v3_stats_t stats;
            v3_get_stats(lc->context, &stats);
            v3_ipc_server_respond(server, client_id, V3_IPC_RSP_STATS, 0,
                                  (uint8_t *)&stats, sizeof(stats));
            break;
        }
            
        case V3_IPC_CMD_CONNECT:
            v3_connect(lc->context);
            v3_ipc_server_respond(server, client_id, V3_IPC_RSP_OK, 0, NULL, 0);
            break;
            
        case V3_IPC_CMD_DISCONNECT:
            v3_disconnect(lc->context);
            v3_ipc_server_respond(server, client_id, V3_IPC_RSP_OK, 0, NULL, 0);
            break;
            
        case V3_IPC_CMD_SHUTDOWN:
            v3_ipc_server_respond(server, client_id, V3_IPC_RSP_OK, 0, NULL, 0);
            v3_lifecycle_stop(lc, V3_EXIT_NORMAL);
            break;
            
        case V3_IPC_CMD_GET_VERSION: {
            const char *version = v3_version_string();
            v3_ipc_server_respond(server, client_id, V3_IPC_RSP_VERSION, 0,
                                  (uint8_t *)version, (uint32_t)strlen(version) + 1);
            break;
        }
            
        default:
            v3_ipc_server_respond(server, client_id, V3_IPC_RSP_ERROR, 0, NULL, 0);
            break;
    }
}

// =========================================================
// 单实例管理
// =========================================================

bool v3_is_instance_running(void) {
    char pid_path[260];
    char app_dir[260];
    
    if (v3_get_app_data_dir(app_dir, sizeof(app_dir)) <= 0) {
        return false;
    }
    
    snprintf(pid_path, sizeof(pid_path), "%s\\v3_core.pid", app_dir);
    
    uint32_t pid = v3_pid_file_read(pid_path);
    if (pid == 0) {
        return false;
    }
    
    return v3_process_exists(pid);
}

uint32_t v3_get_running_instance_pid(void) {
    char pid_path[260];
    char app_dir[260];
    
    if (v3_get_app_data_dir(app_dir, sizeof(app_dir)) <= 0) {
        return 0;
    }
    
    snprintf(pid_path, sizeof(pid_path), "%s\\v3_core.pid", app_dir);
    
    return v3_pid_file_read(pid_path);
}

v3_error_t v3_signal_instance(int signal_type) {
    (void)signal_type;
    
    // 在 Windows 上，我们使用 IPC 而不是信号
    v3_ipc_client_t *client = v3_ipc_client_create();
    if (!client) {
        return V3_ERR_NO_MEMORY;
    }
    
    v3_error_t err = v3_ipc_client_connect(client, NULL, 5000);
    if (err != V3_OK) {
        v3_ipc_client_destroy(client);
        return err;
    }
    
    err = v3_ipc_request_shutdown(client, 5000);
    
    v3_ipc_client_disconnect(client);
    v3_ipc_client_destroy(client);
    
    return err;
}

// =========================================================
// PID 文件管理
// =========================================================

v3_error_t v3_pid_file_create(const char *path) {
    if (!path) return V3_ERR_INVALID_PARAM;
    
    // 确保目录存在
    char dir[260];
    strncpy(dir, path, sizeof(dir) - 1);
    char *last_sep = strrchr(dir, '\\');
    if (last_sep) {
        *last_sep = '\0';
        v3_mkdir_recursive(dir);
    }
    
    FILE *fp = fopen(path, "w");
    if (!fp) {
        return V3_ERR_PLATFORM;
    }
    
    fprintf(fp, "%u", v3_getpid());
    fclose(fp);
    
    return V3_OK;
}

void v3_pid_file_remove(const char *path) {
    if (path) {
        remove(path);
    }
}

uint32_t v3_pid_file_read(const char *path) {
    if (!path) return 0;
    
    FILE *fp = fopen(path, "r");
    if (!fp) return 0;
    
    uint32_t pid = 0;
    fscanf(fp, "%u", &pid);
    fclose(fp);
    
    return pid;
}

// =========================================================
// 字符串转换
// =========================================================

const char* v3_lifecycle_state_string(v3_lifecycle_state_t state) {
    switch (state) {
        case V3_LIFECYCLE_STOPPED:      return "Stopped";
        case V3_LIFECYCLE_STARTING:     return "Starting";
        case V3_LIFECYCLE_RUNNING:      return "Running";
        case V3_LIFECYCLE_STOPPING:     return "Stopping";
        case V3_LIFECYCLE_RESTARTING:   return "Restarting";
        case V3_LIFECYCLE_ERROR:        return "Error";
        default:                        return "Unknown";
    }
}

const char* v3_exit_reason_string(v3_exit_reason_t reason) {
    switch (reason) {
        case V3_EXIT_NORMAL:    return "Normal";
        case V3_EXIT_ERROR:     return "Error";
        case V3_EXIT_SIGNAL:    return "Signal";
        case V3_EXIT_RESTART:   return "Restart";
        case V3_EXIT_UPGRADE:   return "Upgrade";
        case V3_EXIT_CRASH:     return "Crash";
        default:                return "Unknown";
    }
}





