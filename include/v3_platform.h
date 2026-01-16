#ifndef V3_PLATFORM_H
#define V3_PLATFORM_H

#include "v3_core.h"

// =========================================================
// 平台检测
// =========================================================
#ifdef _WIN32
    #define V3_PLATFORM_WINDOWS 1
    #define V3_PLATFORM_NAME    "Windows"
#elif defined(__linux__)
    #define V3_PLATFORM_LINUX   1
    #define V3_PLATFORM_NAME    "Linux"
#elif defined(__APPLE__)
    #define V3_PLATFORM_MACOS   1
    #define V3_PLATFORM_NAME    "macOS"
#else
    #define V3_PLATFORM_UNKNOWN 1
    #define V3_PLATFORM_NAME    "Unknown"
#endif

// =========================================================
// 平台类型定义
// =========================================================
#ifdef V3_PLATFORM_WINDOWS
    #include <windows.h>
    typedef HANDLE          v3_socket_t;
    typedef HANDLE          v3_thread_t;
    typedef HANDLE          v3_mutex_t;
    typedef HANDLE          v3_event_t;
    typedef DWORD           v3_thread_id_t;
    #define V3_INVALID_SOCKET   INVALID_HANDLE_VALUE
#else
    typedef int             v3_socket_t;
    typedef pthread_t       v3_thread_t;
    typedef pthread_mutex_t v3_mutex_t;
    typedef int             v3_event_t;
    typedef pid_t           v3_thread_id_t;
    #define V3_INVALID_SOCKET   (-1)
#endif

// =========================================================
// 时间函数
// =========================================================

/**
 * @brief 获取单调递增时间（纳秒）
 */
V3_API uint64_t v3_time_ns(void);

/**
 * @brief 获取单调递增时间（毫秒）
 */
V3_API uint64_t v3_time_ms(void);

/**
 * @brief 获取 Unix 时间戳（秒）
 */
V3_API uint64_t v3_time_unix(void);

/**
 * @brief 睡眠（毫秒）
 */
V3_API void v3_sleep_ms(uint32_t ms);

/**
 * @brief 高精度睡眠（微秒）
 */
V3_API void v3_sleep_us(uint32_t us);

// =========================================================
// 线程函数
// =========================================================

typedef void* (*v3_thread_func_t)(void *arg);

/**
 * @brief 创建线程
 */
V3_API v3_error_t v3_thread_create(
    v3_thread_t *thread,
    v3_thread_func_t func,
    void *arg
);

/**
 * @brief 等待线程结束
 */
V3_API v3_error_t v3_thread_join(v3_thread_t thread, void **retval);

/**
 * @brief 分离线程
 */
V3_API void v3_thread_detach(v3_thread_t thread);

/**
 * @brief 获取当前线程 ID
 */
V3_API v3_thread_id_t v3_thread_self(void);

/**
 * @brief 设置线程名称（调试用）
 */
V3_API void v3_thread_set_name(const char *name);

// =========================================================
// 互斥锁
// =========================================================

V3_API v3_error_t v3_mutex_init(v3_mutex_t *mutex);
V3_API void v3_mutex_destroy(v3_mutex_t *mutex);
V3_API void v3_mutex_lock(v3_mutex_t *mutex);
V3_API bool v3_mutex_trylock(v3_mutex_t *mutex);
V3_API void v3_mutex_unlock(v3_mutex_t *mutex);

// =========================================================
// 事件/条件变量
// =========================================================

V3_API v3_error_t v3_event_init(v3_event_t *event, bool manual_reset);
V3_API void v3_event_destroy(v3_event_t *event);
V3_API void v3_event_set(v3_event_t *event);
V3_API void v3_event_reset(v3_event_t *event);
V3_API v3_error_t v3_event_wait(v3_event_t *event, uint32_t timeout_ms);

// =========================================================
// 原子操作
// =========================================================

V3_API int32_t v3_atomic_inc32(volatile int32_t *val);
V3_API int32_t v3_atomic_dec32(volatile int32_t *val);
V3_API int64_t v3_atomic_inc64(volatile int64_t *val);
V3_API int64_t v3_atomic_dec64(volatile int64_t *val);
V3_API int32_t v3_atomic_add32(volatile int32_t *val, int32_t add);
V3_API int64_t v3_atomic_add64(volatile int64_t *val, int64_t add);
V3_API bool v3_atomic_cas32(volatile int32_t *val, int32_t expected, int32_t desired);
V3_API bool v3_atomic_cas64(volatile int64_t *val, int64_t expected, int64_t desired);

// =========================================================
// 网络函数
// =========================================================

/**
 * @brief 初始化网络子系统（Windows 需要 WSAStartup）
 */
V3_API v3_error_t v3_net_init(void);

/**
 * @brief 清理网络子系统
 */
V3_API void v3_net_cleanup(void);

/**
 * @brief 创建 UDP 套接字
 */
V3_API v3_socket_t v3_socket_udp_create(bool ipv6);

/**
 * @brief 关闭套接字
 */
V3_API void v3_socket_close(v3_socket_t sock);

/**
 * @brief 设置套接字非阻塞
 */
V3_API v3_error_t v3_socket_set_nonblock(v3_socket_t sock, bool nonblock);

/**
 * @brief 设置套接字接收超时
 */
V3_API v3_error_t v3_socket_set_recv_timeout(v3_socket_t sock, uint32_t ms);

/**
 * @brief 设置套接字发送超时
 */
V3_API v3_error_t v3_socket_set_send_timeout(v3_socket_t sock, uint32_t ms);

/**
 * @brief 绑定套接字
 */
V3_API v3_error_t v3_socket_bind(
    v3_socket_t sock,
    const char *addr,
    uint16_t port
);

/**
 * @brief 发送 UDP 数据
 */
V3_API int v3_socket_sendto(
    v3_socket_t sock,
    const uint8_t *data,
    size_t len,
    const char *addr,
    uint16_t port
);

/**
 * @brief 接收 UDP 数据
 */
V3_API int v3_socket_recvfrom(
    v3_socket_t sock,
    uint8_t *buf,
    size_t buflen,
    char *addr,
    size_t addrlen,
    uint16_t *port
);

/**
 * @brief 获取最后的网络错误码
 */
V3_API int v3_socket_get_error(void);

/**
 * @brief 获取网络错误描述
 */
V3_API const char* v3_socket_error_string(int error);

// =========================================================
// 文件系统
// =========================================================

/**
 * @brief 检查文件是否存在
 */
V3_API bool v3_file_exists(const char *path);

/**
 * @brief 检查目录是否存在
 */
V3_API bool v3_dir_exists(const char *path);

/**
 * @brief 创建目录（递归）
 */
V3_API v3_error_t v3_mkdir_recursive(const char *path);

/**
 * @brief 获取可执行文件路径
 */
V3_API int v3_get_exe_path(char *buf, size_t buflen);

/**
 * @brief 获取可执行文件目录
 */
V3_API int v3_get_exe_dir(char *buf, size_t buflen);

/**
 * @brief 获取应用数据目录（%APPDATA%/v3）
 */
V3_API int v3_get_app_data_dir(char *buf, size_t buflen);

/**
 * @brief 获取临时目录
 */
V3_API int v3_get_temp_dir(char *buf, size_t buflen);

// =========================================================
// 随机数
// =========================================================

/**
 * @brief 生成加密安全的随机字节
 */
V3_API v3_error_t v3_random_bytes(uint8_t *buf, size_t len);

/**
 * @brief 生成随机 32 位整数
 */
V3_API uint32_t v3_random_u32(void);

/**
 * @brief 生成随机 64 位整数
 */
V3_API uint64_t v3_random_u64(void);

// =========================================================
// 内存
// =========================================================

/**
 * @brief 分配对齐内存
 */
V3_API void* v3_aligned_alloc(size_t alignment, size_t size);

/**
 * @brief 释放对齐内存
 */
V3_API void v3_aligned_free(void *ptr);

/**
 * @brief 安全清除内存（防止编译器优化）
 */
V3_API void v3_secure_zero(void *ptr, size_t len);

/**
 * @brief 锁定内存页（防止换页到磁盘）
 */
V3_API v3_error_t v3_mlock(void *ptr, size_t len);

/**
 * @brief 解锁内存页
 */
V3_API void v3_munlock(void *ptr, size_t len);

// =========================================================
// 系统信息
// =========================================================

typedef struct {
    char        os_name[64];
    char        os_version[64];
    char        hostname[256];
    uint32_t    cpu_count;
    uint64_t    total_memory_mb;
    uint64_t    available_memory_mb;
} v3_system_info_t;

V3_API void v3_get_system_info(v3_system_info_t *info);

// =========================================================
// 进程
// =========================================================

/**
 * @brief 获取当前进程 ID
 */
V3_API uint32_t v3_getpid(void);

/**
 * @brief 检查进程是否存在
 */
V3_API bool v3_process_exists(uint32_t pid);

/**
 * @brief 终止进程
 */
V3_API v3_error_t v3_process_kill(uint32_t pid);

#endif // V3_PLATFORM_H



