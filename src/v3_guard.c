
#define _WIN32_WINNT 0x0601
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "v3_guard.h"
#include "v3_platform.h"
#include "v3_lifecycle.h"
#include "version.h"

// =========================================================
// 守护进程配置
// =========================================================
#define GUARD_CHECK_INTERVAL_MS     1000    // 检查间隔
#define GUARD_RESTART_DELAY_MS      2000    // 重启延迟
#define GUARD_MAX_RESTARTS          10      // 最大重启次数
#define GUARD_RESTART_WINDOW_SEC    300     // 重启计数窗口（秒）
#define GUARD_HEALTH_TIMEOUT_MS     5000    // 健康检查超时

// =========================================================
// 守护进程状态
// =========================================================
typedef struct {
    HANDLE              process_handle;     // 被监控进程句柄
    DWORD               process_id;         // 被监控进程 ID
    HANDLE              monitor_thread;     // 监控线程
    HANDLE              stop_event;         // 停止信号
    
    volatile BOOL       running;            // 运行状态
    volatile BOOL       should_restart;     // 是否应重启
    
    // 重启统计
    int                 restart_count;      // 重启次数
    time_t              first_restart_time; // 首次重启时间
    time_t              last_restart_time;  // 最后重启时间
    
    // 配置
    v3_guard_config_t   config;
    
    // 回调
    v3_guard_callback_t on_crash;
    v3_guard_callback_t on_restart;
    v3_guard_callback_t on_max_restarts;
    void               *callback_ctx;
    
    // 日志
    HANDLE              log_file;
    CRITICAL_SECTION    log_lock;
    
} v3_guard_state_t;

static v3_guard_state_t g_guard = {0};

// =========================================================
// 日志函数
// =========================================================
static void guard_log(const char *level, const char *fmt, ...) {
    if (!g_guard.config.enable_logging) return;
    
    EnterCriticalSection(&g_guard.log_lock);
    
    // 获取时间戳
    SYSTEMTIME st;
    GetLocalTime(&st);
    
    char timestamp[64];
    snprintf(timestamp, sizeof(timestamp), 
             "%04d-%02d-%02d %02d:%02d:%02d.%03d",
             st.wYear, st.wMonth, st.wDay,
             st.wHour, st.wMinute, st.wSecond, st.wMilliseconds);
    
    // 格式化消息
    char message[1024];
    va_list args;
    va_start(args, fmt);
    vsnprintf(message, sizeof(message), fmt, args);
    va_end(args);
    
    // 输出到控制台
    printf("[%s] [%s] [Guard] %s\n", timestamp, level, message);
    
    // 输出到日志文件
    if (g_guard.log_file != INVALID_HANDLE_VALUE) {
        char log_line[1200];
        int len = snprintf(log_line, sizeof(log_line),
                          "[%s] [%s] [Guard] %s\r\n",
                          timestamp, level, message);
        
        DWORD written;
        WriteFile(g_guard.log_file, log_line, len, &written, NULL);
        FlushFileBuffers(g_guard.log_file);
    }
    
    LeaveCriticalSection(&g_guard.log_lock);
}

#define LOG_INFO(...)   guard_log("INFO", __VA_ARGS__)
#define LOG_WARN(...)   guard_log("WARN", __VA_ARGS__)
#define LOG_ERROR(...)  guard_log("ERROR", __VA_ARGS__)

// =========================================================
// 重启计数管理
// =========================================================
static void guard_reset_restart_count(void) {
    g_guard.restart_count = 0;
    g_guard.first_restart_time = 0;
}

static BOOL guard_should_restart(void) {
    time_t now = time(NULL);
    
    // 检查是否超过重启窗口，重置计数
    if (g_guard.first_restart_time > 0 &&
        (now - g_guard.first_restart_time) > GUARD_RESTART_WINDOW_SEC) {
        guard_reset_restart_count();
    }
    
    // 检查是否达到最大重启次数
    if (g_guard.restart_count >= g_guard.config.max_restarts) {
        LOG_ERROR("Max restart count (%d) reached in %d seconds",
                  g_guard.config.max_restarts, GUARD_RESTART_WINDOW_SEC);
        
        if (g_guard.on_max_restarts) {
            g_guard.on_max_restarts(g_guard.callback_ctx);
        }
        return FALSE;
    }
    
    return TRUE;
}

static void guard_record_restart(void) {
    time_t now = time(NULL);
    
    if (g_guard.restart_count == 0) {
        g_guard.first_restart_time = now;
    }
    
    g_guard.restart_count++;
    g_guard.last_restart_time = now;
    
    LOG_INFO("Restart count: %d/%d", 
             g_guard.restart_count, g_guard.config.max_restarts);
}

// =========================================================
// 进程启动
// =========================================================
static BOOL guard_start_process(void) {
    STARTUPINFOW si = {0};
    PROCESS_INFORMATION pi = {0};
    
    si.cb = sizeof(si);
    
    // 隐藏窗口（如果配置要求）
    if (g_guard.config.hide_window) {
        si.dwFlags = STARTF_USESHOWWINDOW;
        si.wShowWindow = SW_HIDE;
    }
    
    // 转换命令行为宽字符
    WCHAR cmd_line[MAX_PATH * 2];
    MultiByteToWideChar(CP_UTF8, 0, 
                        g_guard.config.command_line, -1,
                        cmd_line, MAX_PATH * 2);
    
    // 工作目录
    WCHAR *work_dir = NULL;
    WCHAR work_dir_buf[MAX_PATH];
    if (g_guard.config.working_dir[0] != '\0') {
        MultiByteToWideChar(CP_UTF8, 0,
                           g_guard.config.working_dir, -1,
                           work_dir_buf, MAX_PATH);
        work_dir = work_dir_buf;
    }
    
    // 创建进程
    DWORD flags = CREATE_NEW_PROCESS_GROUP;
    if (g_guard.config.hide_window) {
        flags |= CREATE_NO_WINDOW;
    }
    
    if (!CreateProcessW(NULL, cmd_line, NULL, NULL, FALSE,
                        flags, NULL, work_dir, &si, &pi)) {
        LOG_ERROR("Failed to create process: %lu", GetLastError());
        return FALSE;
    }
    
    // 保存进程信息
    g_guard.process_handle = pi.hProcess;
    g_guard.process_id = pi.dwProcessId;
    
    // 关闭线程句柄（不需要）
    CloseHandle(pi.hThread);
    
    LOG_INFO("Process started: PID=%lu", g_guard.process_id);
    
    return TRUE;
}

// =========================================================
// 进程停止
// =========================================================
static void guard_stop_process(BOOL force) {
    if (g_guard.process_handle == NULL) return;
    
    if (force) {
        // 强制终止
        LOG_WARN("Force terminating process: PID=%lu", g_guard.process_id);
        TerminateProcess(g_guard.process_handle, 1);
    } else {
        // 尝试优雅关闭
        // 发送 CTRL+BREAK 信号
        GenerateConsoleCtrlEvent(CTRL_BREAK_EVENT, g_guard.process_id);
        
        // 等待进程退出
        DWORD result = WaitForSingleObject(g_guard.process_handle, 
                                           g_guard.config.stop_timeout_ms);
        
        if (result == WAIT_TIMEOUT) {
            LOG_WARN("Process did not stop gracefully, force terminating");
            TerminateProcess(g_guard.process_handle, 1);
        }
    }
    
    CloseHandle(g_guard.process_handle);
    g_guard.process_handle = NULL;
    g_guard.process_id = 0;
}

// =========================================================
// 健康检查
// =========================================================
static BOOL guard_health_check(void) {
    if (g_guard.process_handle == NULL) return FALSE;
    
    // 检查进程是否还在运行
    DWORD exit_code;
    if (!GetExitCodeProcess(g_guard.process_handle, &exit_code)) {
        return FALSE;
    }
    
    if (exit_code != STILL_ACTIVE) {
        return FALSE;
    }
    
    // 如果配置了健康检查回调，调用它
    if (g_guard.config.health_check_fn) {
        return g_guard.config.health_check_fn(g_guard.callback_ctx);
    }
    
    return TRUE;
}

// =========================================================
// 监控线程
// =========================================================
static DWORD WINAPI guard_monitor_thread(LPVOID param) {
    (void)param;
    
    LOG_INFO("Monitor thread started");
    
    while (g_guard.running) {
        // 等待进程退出或停止信号
        HANDLE handles[2] = {
            g_guard.process_handle,
            g_guard.stop_event
        };
        
        DWORD wait_count = (g_guard.process_handle != NULL) ? 2 : 1;
        if (wait_count == 1) {
            handles[0] = g_guard.stop_event;
        }
        
        DWORD result = WaitForMultipleObjects(
            wait_count, 
            handles, 
            FALSE, 
            g_guard.config.check_interval_ms
        );
        
        // 停止信号
        if (!g_guard.running) break;
        
        if (wait_count == 2 && result == WAIT_OBJECT_0) {
            // 进程退出
            DWORD exit_code;
            GetExitCodeProcess(g_guard.process_handle, &exit_code);
            
            LOG_WARN("Process exited: PID=%lu, code=%lu", 
                     g_guard.process_id, exit_code);
            
            CloseHandle(g_guard.process_handle);
            g_guard.process_handle = NULL;
            g_guard.process_id = 0;
            
            // 触发崩溃回调
            if (g_guard.on_crash) {
                g_guard.on_crash(g_guard.callback_ctx);
            }
            
            // 检查是否应重启
            if (g_guard.config.auto_restart && guard_should_restart()) {
                LOG_INFO("Scheduling restart in %d ms", 
                         g_guard.config.restart_delay_ms);
                
                Sleep(g_guard.config.restart_delay_ms);
                
                if (!g_guard.running) break;
                
                guard_record_restart();
                
                if (guard_start_process()) {
                    if (g_guard.on_restart) {
                        g_guard.on_restart(g_guard.callback_ctx);
                    }
                } else {
                    LOG_ERROR("Failed to restart process");
                }
            } else if (!g_guard.config.auto_restart) {
                LOG_INFO("Auto-restart disabled, stopping guard");
                g_guard.running = FALSE;
                break;
            }
        }
        else if (result == WAIT_TIMEOUT) {
            // 定期健康检查
            if (g_guard.process_handle != NULL && !guard_health_check()) {
                LOG_WARN("Health check failed");
                
                if (g_guard.config.restart_on_health_fail) {
                    guard_stop_process(TRUE);
                    // 下次循环会处理重启
                }
            }
        }
    }
    
    LOG_INFO("Monitor thread stopped");
    return 0;
}

// =========================================================
// 公开 API 实现
// =========================================================

int v3_guard_init(const v3_guard_config_t *config) {
    if (config == NULL) return -1;
    
    // 初始化临界区
    InitializeCriticalSection(&g_guard.log_lock);
    
    // 复制配置
    memcpy(&g_guard.config, config, sizeof(v3_guard_config_t));
    
    // 设置默认值
    if (g_guard.config.check_interval_ms == 0) {
        g_guard.config.check_interval_ms = GUARD_CHECK_INTERVAL_MS;
    }
    if (g_guard.config.restart_delay_ms == 0) {
        g_guard.config.restart_delay_ms = GUARD_RESTART_DELAY_MS;
    }
    if (g_guard.config.max_restarts == 0) {
        g_guard.config.max_restarts = GUARD_MAX_RESTARTS;
    }
    if (g_guard.config.stop_timeout_ms == 0) {
        g_guard.config.stop_timeout_ms = 5000;
    }
    
    // 打开日志文件
    g_guard.log_file = INVALID_HANDLE_VALUE;
    if (g_guard.config.enable_logging && g_guard.config.log_path[0] != '\0') {
        WCHAR log_path[MAX_PATH];
        MultiByteToWideChar(CP_UTF8, 0, g_guard.config.log_path, -1,
                           log_path, MAX_PATH);
        
        g_guard.log_file = CreateFileW(log_path,
                                       GENERIC_WRITE,
                                       FILE_SHARE_READ,
                                       NULL,
                                       OPEN_ALWAYS,
                                       FILE_ATTRIBUTE_NORMAL,
                                       NULL);
        
        if (g_guard.log_file != INVALID_HANDLE_VALUE) {
            SetFilePointer(g_guard.log_file, 0, NULL, FILE_END);
        }
    }
    
    // 创建停止事件
    g_guard.stop_event = CreateEvent(NULL, TRUE, FALSE, NULL);
    if (g_guard.stop_event == NULL) {
        LOG_ERROR("Failed to create stop event");
        return -1;
    }
    
    LOG_INFO("Guard initialized");
    LOG_INFO("  Command: %s", g_guard.config.command_line);
    LOG_INFO("  Auto-restart: %s", g_guard.config.auto_restart ? "yes" : "no");
    LOG_INFO("  Max restarts: %d", g_guard.config.max_restarts);
    
    return 0;
}

int v3_guard_start(void) {
    if (g_guard.running) {
        LOG_WARN("Guard already running");
        return 0;
    }
    
    // 启动被监控进程
    if (!guard_start_process()) {
        return -1;
    }
    
    g_guard.running = TRUE;
    ResetEvent(g_guard.stop_event);
    
    // 启动监控线程
    g_guard.monitor_thread = CreateThread(NULL, 0,
                                          guard_monitor_thread,
                                          NULL, 0, NULL);
    
    if (g_guard.monitor_thread == NULL) {
        LOG_ERROR("Failed to create monitor thread");
        guard_stop_process(TRUE);
        g_guard.running = FALSE;
        return -1;
    }
    
    LOG_INFO("Guard started");
    return 0;
}

int v3_guard_stop(void) {
    if (!g_guard.running) return 0;
    
    LOG_INFO("Stopping guard...");
    
    g_guard.running = FALSE;
    SetEvent(g_guard.stop_event);
    
    // 等待监控线程结束
    if (g_guard.monitor_thread != NULL) {
        WaitForSingleObject(g_guard.monitor_thread, 5000);
        CloseHandle(g_guard.monitor_thread);
        g_guard.monitor_thread = NULL;
    }
    
    // 停止被监控进程
    guard_stop_process(FALSE);
    
    LOG_INFO("Guard stopped");
    return 0;
}

void v3_guard_cleanup(void) {
    v3_guard_stop();
    
    if (g_guard.stop_event != NULL) {
        CloseHandle(g_guard.stop_event);
        g_guard.stop_event = NULL;
    }
    
    if (g_guard.log_file != INVALID_HANDLE_VALUE) {
        CloseHandle(g_guard.log_file);
        g_guard.log_file = INVALID_HANDLE_VALUE;
    }
    
    DeleteCriticalSection(&g_guard.log_lock);
    
    memset(&g_guard, 0, sizeof(g_guard));
}

void v3_guard_set_callbacks(v3_guard_callback_t on_crash,
                            v3_guard_callback_t on_restart,
                            v3_guard_callback_t on_max_restarts,
                            void *ctx) {
    g_guard.on_crash = on_crash;
    g_guard.on_restart = on_restart;
    g_guard.on_max_restarts = on_max_restarts;
    g_guard.callback_ctx = ctx;
}

BOOL v3_guard_is_running(void) {
    return g_guard.running;
}

DWORD v3_guard_get_process_id(void) {
    return g_guard.process_id;
}

int v3_guard_get_restart_count(void) {
    return g_guard.restart_count;
}

void v3_guard_reset_restart_count(void) {
    guard_reset_restart_count();
    LOG_INFO("Restart count reset");
}

int v3_guard_send_signal(int signal) {
    if (g_guard.process_id == 0) return -1;
    
    switch (signal) {
        case V3_SIGNAL_RELOAD:
            // 发送自定义信号通知重载配置
            // 可以通过 IPC 实现
            LOG_INFO("Sending reload signal to process");
            break;
            
        case V3_SIGNAL_STOP:
            GenerateConsoleCtrlEvent(CTRL_BREAK_EVENT, g_guard.process_id);
            LOG_INFO("Sending stop signal to process");
            break;
            
        default:
            return -1;
    }
    
    return 0;
}



