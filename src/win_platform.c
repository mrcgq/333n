
#define _WIN32_WINNT 0x0601
#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <iphlpapi.h>
#include <bcrypt.h>
#include <stdio.h>
#include <stdlib.h>

#include "v3_platform.h"
#include "version.h"

#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "bcrypt.lib")

// =========================================================
// 全局状态
// =========================================================
typedef struct {
    BOOL                initialized;
    BOOL                winsock_init;
    LARGE_INTEGER       perf_freq;      // 高精度计时器频率
    DWORD               main_thread_id;
    HANDLE              heap;           // 私有堆
    CRITICAL_SECTION    global_lock;
    
    // 系统信息缓存
    v3_system_info_t    sys_info;
    BOOL                sys_info_valid;
    
} platform_state_t;

static platform_state_t g_platform = {0};

// =========================================================
// 初始化
// =========================================================

int v3_platform_init(void) {
    if (g_platform.initialized) return 0;
    
    // 初始化临界区
    InitializeCriticalSection(&g_platform.global_lock);
    
    // 获取主线程 ID
    g_platform.main_thread_id = GetCurrentThreadId();
    
    // 初始化高精度计时器
    if (!QueryPerformanceFrequency(&g_platform.perf_freq)) {
        g_platform.perf_freq.QuadPart = 1000;  // 回退到毫秒
    }
    
    // 创建私有堆
    g_platform.heap = HeapCreate(0, 1024 * 1024, 0);  // 1MB 初始大小
    if (g_platform.heap == NULL) {
        g_platform.heap = GetProcessHeap();
    }
    
    // 初始化 Winsock
    WSADATA wsa_data;
    int result = WSAStartup(MAKEWORD(2, 2), &wsa_data);
    if (result != 0) {
        fprintf(stderr, "[Platform] WSAStartup failed: %d\n", result);
        return -1;
    }
    g_platform.winsock_init = TRUE;
    
    // 设置进程 DPI 感知（Windows 8.1+）
    typedef BOOL (WINAPI *SetProcessDpiAwarenessContext_t)(DPI_AWARENESS_CONTEXT);
    HMODULE user32 = GetModuleHandleW(L"user32.dll");
    if (user32) {
        SetProcessDpiAwarenessContext_t fn = 
            (SetProcessDpiAwarenessContext_t)GetProcAddress(user32, 
                "SetProcessDpiAwarenessContext");
        if (fn) {
            fn(DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2);
        }
    }
    
    // 启用 UTF-8 控制台输出
    SetConsoleOutputCP(CP_UTF8);
    SetConsoleCP(CP_UTF8);
    
    g_platform.initialized = TRUE;
    
    return 0;
}

void v3_platform_cleanup(void) {
    if (!g_platform.initialized) return;
    
    if (g_platform.winsock_init) {
        WSACleanup();
        g_platform.winsock_init = FALSE;
    }
    
    if (g_platform.heap != NULL && g_platform.heap != GetProcessHeap()) {
        HeapDestroy(g_platform.heap);
    }
    g_platform.heap = NULL;
    
    DeleteCriticalSection(&g_platform.global_lock);
    
    g_platform.initialized = FALSE;
}

// =========================================================
// 时间函数
// =========================================================

uint64_t v3_time_now_ns(void) {
    LARGE_INTEGER counter;
    QueryPerformanceCounter(&counter);
    
    // 转换为纳秒
    return (uint64_t)(counter.QuadPart * 1000000000ULL / 
                      g_platform.perf_freq.QuadPart);
}

uint64_t v3_time_now_us(void) {
    return v3_time_now_ns() / 1000;
}

uint64_t v3_time_now_ms(void) {
    return v3_time_now_ns() / 1000000;
}

uint64_t v3_time_unix_sec(void) {
    FILETIME ft;
    GetSystemTimeAsFileTime(&ft);
    
    ULARGE_INTEGER uli;
    uli.LowPart = ft.dwLowDateTime;
    uli.HighPart = ft.dwHighDateTime;
    
    // FILETIME 是从 1601-01-01 开始的 100ns 间隔
    // Unix 时间戳从 1970-01-01 开始
    return (uli.QuadPart - 116444736000000000ULL) / 10000000ULL;
}

void v3_time_sleep_ns(uint64_t ns) {
    if (ns == 0) return;
    
    // Windows 没有纳秒级睡眠，使用高精度等待
    if (ns < 1000000) {
        // 小于 1ms，使用自旋等待
        uint64_t start = v3_time_now_ns();
        while (v3_time_now_ns() - start < ns) {
            YieldProcessor();
        }
    } else {
        // 使用 Sleep
        Sleep((DWORD)(ns / 1000000));
    }
}

void v3_time_sleep_ms(uint32_t ms) {
    Sleep(ms);
}

// =========================================================
// 系统信息
// =========================================================

int v3_get_system_info(v3_system_info_t *info) {
    if (info == NULL) return -1;
    
    // 检查缓存
    if (g_platform.sys_info_valid) {
        memcpy(info, &g_platform.sys_info, sizeof(v3_system_info_t));
        return 0;
    }
    
    memset(info, 0, sizeof(v3_system_info_t));
    
    // 操作系统版本
    info->os_major = 10;
    info->os_minor = 0;
    
    // 使用 RtlGetVersion 获取真实版本
    typedef NTSTATUS (WINAPI *RtlGetVersion_t)(PRTL_OSVERSIONINFOW);
    HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
    if (ntdll) {
        RtlGetVersion_t RtlGetVersion = 
            (RtlGetVersion_t)GetProcAddress(ntdll, "RtlGetVersion");
        if (RtlGetVersion) {
            RTL_OSVERSIONINFOW osvi = {0};
            osvi.dwOSVersionInfoSize = sizeof(osvi);
            if (RtlGetVersion(&osvi) == 0) {
                info->os_major = osvi.dwMajorVersion;
                info->os_minor = osvi.dwMinorVersion;
                info->os_build = osvi.dwBuildNumber;
            }
        }
    }
    
    snprintf(info->os_name, sizeof(info->os_name),
             "Windows %lu.%lu.%lu",
             info->os_major, info->os_minor, info->os_build);
    
    // CPU 信息
    SYSTEM_INFO si;
    GetNativeSystemInfo(&si);
    
    info->cpu_count = si.dwNumberOfProcessors;
    
    switch (si.wProcessorArchitecture) {
        case PROCESSOR_ARCHITECTURE_AMD64:
            strncpy(info->cpu_arch, "x86_64", sizeof(info->cpu_arch) - 1);
            break;
        case PROCESSOR_ARCHITECTURE_INTEL:
            strncpy(info->cpu_arch, "x86", sizeof(info->cpu_arch) - 1);
            break;
        case PROCESSOR_ARCHITECTURE_ARM64:
            strncpy(info->cpu_arch, "arm64", sizeof(info->cpu_arch) - 1);
            break;
        default:
            strncpy(info->cpu_arch, "unknown", sizeof(info->cpu_arch) - 1);
    }
    
    // CPU 型号（从注册表读取）
    HKEY hKey;
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE,
                      L"HARDWARE\\DESCRIPTION\\System\\CentralProcessor\\0",
                      0, KEY_READ, &hKey) == ERROR_SUCCESS) {
        WCHAR cpu_name[256];
        DWORD size = sizeof(cpu_name);
        if (RegQueryValueExW(hKey, L"ProcessorNameString", NULL, NULL,
                            (LPBYTE)cpu_name, &size) == ERROR_SUCCESS) {
            WideCharToMultiByte(CP_UTF8, 0, cpu_name, -1,
                               info->cpu_model, sizeof(info->cpu_model) - 1,
                               NULL, NULL);
        }
        RegCloseKey(hKey);
    }
    
    // 内存信息
    MEMORYSTATUSEX memstat;
    memstat.dwLength = sizeof(memstat);
    if (GlobalMemoryStatusEx(&memstat)) {
        info->total_memory = memstat.ullTotalPhys;
        info->available_memory = memstat.ullAvailPhys;
    }
    
    // 检测 SIMD 支持
    info->has_sse2 = IsProcessorFeaturePresent(PF_XMMI64_INSTRUCTIONS_AVAILABLE);
    info->has_sse42 = FALSE;
    info->has_avx = FALSE;
    info->has_avx2 = FALSE;
    
    // 使用 __cpuid 检测更多特性
    #if defined(_MSC_VER)
    int cpu_info[4];
    __cpuid(cpu_info, 1);
    info->has_sse42 = (cpu_info[2] & (1 << 20)) != 0;
    info->has_avx = (cpu_info[2] & (1 << 28)) != 0;
    
    __cpuidex(cpu_info, 7, 0);
    info->has_avx2 = (cpu_info[1] & (1 << 5)) != 0;
    #elif defined(__GNUC__)
    unsigned int eax, ebx, ecx, edx;
    if (__get_cpuid(1, &eax, &ebx, &ecx, &edx)) {
        info->has_sse42 = (ecx & (1 << 20)) != 0;
        info->has_avx = (ecx & (1 << 28)) != 0;
    }
    if (__get_cpuid_count(7, 0, &eax, &ebx, &ecx, &edx)) {
        info->has_avx2 = (ebx & (1 << 5)) != 0;
    }
    #endif
    
    // 缓存结果
    memcpy(&g_platform.sys_info, info, sizeof(v3_system_info_t));
    g_platform.sys_info_valid = TRUE;
    
    return 0;
}

// =========================================================
// 网络功能
// =========================================================

int v3_socket_set_nonblocking(SOCKET sock, BOOL nonblock) {
    u_long mode = nonblock ? 1 : 0;
    return ioctlsocket(sock, FIONBIO, &mode);
}

int v3_socket_set_buffer_size(SOCKET sock, int recv_size, int send_size) {
    int result = 0;
    
    if (recv_size > 0) {
        result = setsockopt(sock, SOL_SOCKET, SO_RCVBUF,
                           (char*)&recv_size, sizeof(recv_size));
        if (result != 0) return result;
    }
    
    if (send_size > 0) {
        result = setsockopt(sock, SOL_SOCKET, SO_SNDBUF,
                           (char*)&send_size, sizeof(send_size));
    }
    
    return result;
}

int v3_socket_set_reuse_addr(SOCKET sock, BOOL reuse) {
    int opt = reuse ? 1 : 0;
    return setsockopt(sock, SOL_SOCKET, SO_REUSEADDR,
                     (char*)&opt, sizeof(opt));
}

// =========================================================
// 随机数生成（使用 BCrypt）
// =========================================================

int v3_random_bytes(void *buf, size_t len) {
    NTSTATUS status = BCryptGenRandom(NULL, (PUCHAR)buf, (ULONG)len,
                                      BCRYPT_USE_SYSTEM_PREFERRED_RNG);
    return (status == 0) ? 0 : -1;
}

uint32_t v3_random_u32(void) {
    uint32_t value;
    v3_random_bytes(&value, sizeof(value));
    return value;
}

uint64_t v3_random_u64(void) {
    uint64_t value;
    v3_random_bytes(&value, sizeof(value));
    return value;
}

// =========================================================
// 错误处理
// =========================================================

int v3_get_last_error(void) {
    return (int)GetLastError();
}

int v3_get_socket_error(void) {
    return WSAGetLastError();
}

const char* v3_strerror(int error) {
    static __thread char buf[256];
    
    FormatMessageA(FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
                  NULL, error, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
                  buf, sizeof(buf), NULL);
    
    // 移除尾部换行
    size_t len = strlen(buf);
    while (len > 0 && (buf[len-1] == '\n' || buf[len-1] == '\r')) {
        buf[--len] = '\0';
    }
    
    return buf;
}

// =========================================================
// 文件路径
// =========================================================

int v3_get_exe_path(char *buf, size_t size) {
    WCHAR path[MAX_PATH];
    DWORD len = GetModuleFileNameW(NULL, path, MAX_PATH);
    
    if (len == 0 || len >= MAX_PATH) return -1;
    
    // 转换为 UTF-8
    int result = WideCharToMultiByte(CP_UTF8, 0, path, -1,
                                     buf, (int)size, NULL, NULL);
    
    return (result > 0) ? 0 : -1;
}

int v3_get_exe_dir(char *buf, size_t size) {
    if (v3_get_exe_path(buf, size) != 0) return -1;
    
    // 找到最后一个路径分隔符
    char *last_sep = strrchr(buf, '\\');
    if (last_sep == NULL) last_sep = strrchr(buf, '/');
    
    if (last_sep != NULL) {
        *last_sep = '\0';
    }
    
    return 0;
}

int v3_get_temp_dir(char *buf, size_t size) {
    WCHAR path[MAX_PATH];
    DWORD len = GetTempPathW(MAX_PATH, path);
    
    if (len == 0 || len >= MAX_PATH) return -1;
    
    int result = WideCharToMultiByte(CP_UTF8, 0, path, -1,
                                     buf, (int)size, NULL, NULL);
    
    return (result > 0) ? 0 : -1;
}

// =========================================================
// 调试功能
// =========================================================

void v3_debug_break(void) {
    if (IsDebuggerPresent()) {
        DebugBreak();
    }
}

BOOL v3_is_debugger_present(void) {
    return IsDebuggerPresent();
}

void v3_output_debug_string(const char *fmt, ...) {
    char buf[1024];
    va_list args;
    va_start(args, fmt);
    vsnprintf(buf, sizeof(buf), fmt, args);
    va_end(args);
    
    OutputDebugStringA(buf);
}


