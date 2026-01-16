
#define _WIN32_WINNT 0x0601
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "v3_platform.h"

// =========================================================
// 基础内存分配
// =========================================================

static HANDLE g_private_heap = NULL;

int v3_memory_init(void) {
    if (g_private_heap != NULL) return 0;
    
    // 创建私有堆，初始大小 1MB，可增长
    g_private_heap = HeapCreate(0, 1024 * 1024, 0);
    
    if (g_private_heap == NULL) {
        g_private_heap = GetProcessHeap();
    }
    
    return 0;
}

void v3_memory_cleanup(void) {
    if (g_private_heap != NULL && g_private_heap != GetProcessHeap()) {
        HeapDestroy(g_private_heap);
    }
    g_private_heap = NULL;
}

void* v3_malloc(size_t size) {
    HANDLE heap = g_private_heap ? g_private_heap : GetProcessHeap();
    return HeapAlloc(heap, 0, size);
}

void* v3_calloc(size_t count, size_t size) {
    HANDLE heap = g_private_heap ? g_private_heap : GetProcessHeap();
    return HeapAlloc(heap, HEAP_ZERO_MEMORY, count * size);
}

void* v3_realloc(void *ptr, size_t size) {
    HANDLE heap = g_private_heap ? g_private_heap : GetProcessHeap();
    
    if (ptr == NULL) {
        return HeapAlloc(heap, 0, size);
    }
    
    if (size == 0) {
        HeapFree(heap, 0, ptr);
        return NULL;
    }
    
    return HeapReAlloc(heap, 0, ptr, size);
}

void v3_free(void *ptr) {
    if (ptr == NULL) return;
    
    HANDLE heap = g_private_heap ? g_private_heap : GetProcessHeap();
    HeapFree(heap, 0, ptr);
}

// =========================================================
// 对齐内存分配
// =========================================================

void* v3_aligned_alloc(size_t alignment, size_t size) {
    // Windows 10 1703+ 支持 _aligned_malloc
    // 这里使用手动对齐方式保证兼容性
    
    if (alignment < sizeof(void*)) {
        alignment = sizeof(void*);
    }
    
    // 确保 alignment 是 2 的幂
    if ((alignment & (alignment - 1)) != 0) {
        return NULL;
    }
    
    size_t total = size + alignment + sizeof(void*);
    void *raw = v3_malloc(total);
    
    if (raw == NULL) return NULL;
    
    // 计算对齐后的地址
    uintptr_t aligned = ((uintptr_t)raw + sizeof(void*) + alignment - 1) 
                        & ~(alignment - 1);
    
    // 存储原始指针
    ((void**)aligned)[-1] = raw;
    
    return (void*)aligned;
}

void v3_aligned_free(void *ptr) {
    if (ptr == NULL) return;
    
    void *raw = ((void**)ptr)[-1];
    v3_free(raw);
}

// =========================================================
// 安全内存操作
// =========================================================

void v3_secure_zero(void *ptr, size_t size) {
    if (ptr == NULL || size == 0) return;
    
    // 使用 SecureZeroMemory 或 RtlSecureZeroMemory
    // 这些函数不会被编译器优化掉
    SecureZeroMemory(ptr, size);
}

void* v3_secure_alloc(size_t size) {
    // 分配不可交换的内存
    void *ptr = VirtualAlloc(NULL, size, 
                             MEM_COMMIT | MEM_RESERVE,
                             PAGE_READWRITE);
    
    if (ptr == NULL) return NULL;
    
    // 锁定内存，防止被交换到磁盘
    VirtualLock(ptr, size);
    
    return ptr;
}

void v3_secure_free(void *ptr, size_t size) {
    if (ptr == NULL) return;
    
    // 安全清零
    v3_secure_zero(ptr, size);
    
    // 解锁并释放
    VirtualUnlock(ptr, size);
    VirtualFree(ptr, 0, MEM_RELEASE);
}

// =========================================================
// 内存池
// =========================================================

typedef struct v3_pool_block {
    struct v3_pool_block *next;
} v3_pool_block_t;

typedef struct {
    size_t              block_size;
    size_t              block_count;
    size_t              total_blocks;
    void               *memory;
    v3_pool_block_t    *free_list;
    CRITICAL_SECTION    lock;
} v3_mempool_t;

v3_mempool_t* v3_mempool_create(size_t block_size, size_t initial_blocks) {
    if (block_size < sizeof(v3_pool_block_t)) {
        block_size = sizeof(v3_pool_block_t);
    }
    
    // 对齐到 8 字节
    block_size = (block_size + 7) & ~7;
    
    v3_mempool_t *pool = (v3_mempool_t*)v3_calloc(1, sizeof(v3_mempool_t));
    if (pool == NULL) return NULL;
    
    pool->block_size = block_size;
    pool->total_blocks = initial_blocks;
    
    InitializeCriticalSection(&pool->lock);
    
    // 分配内存块
    pool->memory = VirtualAlloc(NULL, block_size * initial_blocks,
                                MEM_COMMIT | MEM_RESERVE,
                                PAGE_READWRITE);
    
    if (pool->memory == NULL) {
        DeleteCriticalSection(&pool->lock);
        v3_free(pool);
        return NULL;
    }
    
    // 初始化空闲链表
    pool->free_list = NULL;
    
    uint8_t *ptr = (uint8_t*)pool->memory;
    for (size_t i = 0; i < initial_blocks; i++) {
        v3_pool_block_t *block = (v3_pool_block_t*)(ptr + i * block_size);
        block->next = pool->free_list;
        pool->free_list = block;
    }
    
    pool->block_count = initial_blocks;
    
    return pool;
}

void* v3_mempool_alloc(v3_mempool_t *pool) {
    if (pool == NULL) return NULL;
    
    EnterCriticalSection(&pool->lock);
    
    if (pool->free_list == NULL) {
        // 池已满，返回 NULL（或可以扩展）
        LeaveCriticalSection(&pool->lock);
        return NULL;
    }
    
    v3_pool_block_t *block = pool->free_list;
    pool->free_list = block->next;
    pool->block_count--;
    
    LeaveCriticalSection(&pool->lock);
    
    return block;
}

void v3_mempool_free(v3_mempool_t *pool, void *ptr) {
    if (pool == NULL || ptr == NULL) return;
    
    EnterCriticalSection(&pool->lock);
    
    v3_pool_block_t *block = (v3_pool_block_t*)ptr;
    block->next = pool->free_list;
    pool->free_list = block;
    pool->block_count++;
    
    LeaveCriticalSection(&pool->lock);
}

void v3_mempool_destroy(v3_mempool_t *pool) {
    if (pool == NULL) return;
    
    DeleteCriticalSection(&pool->lock);
    
    if (pool->memory != NULL) {
        VirtualFree(pool->memory, 0, MEM_RELEASE);
    }
    
    v3_free(pool);
}

size_t v3_mempool_available(v3_mempool_t *pool) {
    if (pool == NULL) return 0;
    return pool->block_count;
}

// =========================================================
// 内存映射文件
// =========================================================

typedef struct {
    HANDLE  file;
    HANDLE  mapping;
    void   *view;
    size_t  size;
    BOOL    writable;
} v3_mmap_t;

v3_mmap_t* v3_mmap_open(const char *path, size_t size, BOOL writable) {
    v3_mmap_t *mmap = (v3_mmap_t*)v3_calloc(1, sizeof(v3_mmap_t));
    if (mmap == NULL) return NULL;
    
    WCHAR path_wide[MAX_PATH];
    MultiByteToWideChar(CP_UTF8, 0, path, -1, path_wide, MAX_PATH);
    
    DWORD access = GENERIC_READ;
    DWORD share = FILE_SHARE_READ;
    DWORD create = OPEN_EXISTING;
    
    if (writable) {
        access |= GENERIC_WRITE;
        share |= FILE_SHARE_WRITE;
        create = OPEN_ALWAYS;
    }
    
    mmap->file = CreateFileW(path_wide, access, share, NULL,
                             create, FILE_ATTRIBUTE_NORMAL, NULL);
    
    if (mmap->file == INVALID_HANDLE_VALUE) {
        v3_free(mmap);
        return NULL;
    }
    
    // 获取或设置文件大小
    LARGE_INTEGER file_size;
    GetFileSizeEx(mmap->file, &file_size);
    
    if (size == 0) {
        size = (size_t)file_size.QuadPart;
    } else if (writable && (size_t)file_size.QuadPart < size) {
        // 扩展文件
        LARGE_INTEGER new_size;
        new_size.QuadPart = size;
        SetFilePointerEx(mmap->file, new_size, NULL, FILE_BEGIN);
        SetEndOfFile(mmap->file);
    }
    
    if (size == 0) {
        CloseHandle(mmap->file);
        v3_free(mmap);
        return NULL;
    }
    
    // 创建文件映射
    DWORD protect = writable ? PAGE_READWRITE : PAGE_READONLY;
    
    mmap->mapping = CreateFileMappingW(mmap->file, NULL, protect,
                                       (DWORD)(size >> 32),
                                       (DWORD)(size & 0xFFFFFFFF),
                                       NULL);
    
    if (mmap->mapping == NULL) {
        CloseHandle(mmap->file);
        v3_free(mmap);
        return NULL;
    }
    
    // 映射视图
    DWORD view_access = writable ? FILE_MAP_WRITE : FILE_MAP_READ;
    
    mmap->view = MapViewOfFile(mmap->mapping, view_access, 0, 0, size);
    
    if (mmap->view == NULL) {
        CloseHandle(mmap->mapping);
        CloseHandle(mmap->file);
        v3_free(mmap);
        return NULL;
    }
    
    mmap->size = size;
    mmap->writable = writable;
    
    return mmap;
}

void* v3_mmap_data(v3_mmap_t *mmap) {
    return mmap ? mmap->view : NULL;
}

size_t v3_mmap_size(v3_mmap_t *mmap) {
    return mmap ? mmap->size : 0;
}

int v3_mmap_flush(v3_mmap_t *mmap) {
    if (mmap == NULL || mmap->view == NULL) return -1;
    
    if (!FlushViewOfFile(mmap->view, mmap->size)) {
        return -1;
    }
    
    if (!FlushFileBuffers(mmap->file)) {
        return -1;
    }
    
    return 0;
}

void v3_mmap_close(v3_mmap_t *mmap) {
    if (mmap == NULL) return;
    
    if (mmap->view) {
        UnmapViewOfFile(mmap->view);
    }
    if (mmap->mapping) {
        CloseHandle(mmap->mapping);
    }
    if (mmap->file && mmap->file != INVALID_HANDLE_VALUE) {
        CloseHandle(mmap->file);
    }
    
    v3_free(mmap);
}

// =========================================================
// 内存统计
// =========================================================

void v3_memory_get_stats(size_t *total, size_t *available, size_t *used) {
    MEMORYSTATUSEX memstat;
    memstat.dwLength = sizeof(memstat);
    
    if (GlobalMemoryStatusEx(&memstat)) {
        if (total) *total = (size_t)memstat.ullTotalPhys;
        if (available) *available = (size_t)memstat.ullAvailPhys;
        if (used) *used = (size_t)(memstat.ullTotalPhys - memstat.ullAvailPhys);
    } else {
        if (total) *total = 0;
        if (available) *available = 0;
        if (used) *used = 0;
    }
}

size_t v3_memory_get_process_usage(void) {
    PROCESS_MEMORY_COUNTERS pmc;
    pmc.cb = sizeof(pmc);
    
    if (GetProcessMemoryInfo(GetCurrentProcess(), &pmc, sizeof(pmc))) {
        return pmc.WorkingSetSize;
    }
    
    return 0;
}































1. version.h


/*
 * v3 Core - Version Information
 * 
 * 此文件定义 v3 Windows 内核的版本信息
 * 必须与服务端协议版本保持兼容
 */

#ifndef V3_VERSION_H
#define V3_VERSION_H

// =========================================================
// 版本号定义
// =========================================================
#define V3_VERSION_MAJOR        1
#define V3_VERSION_MINOR        0
#define V3_VERSION_PATCH        0
#define V3_VERSION_BUILD        1

// 版本字符串
#define V3_VERSION_STRING       "1.0.0"
#define V3_VERSION_FULL         "1.0.0.1"

// =========================================================
// 协议版本（必须与服务端一致）
// =========================================================
#define V3_PROTOCOL_VERSION     3       // v3 协议
#define V3_PROTOCOL_MAGIC_VER   1       // Magic 派生算法版本

// =========================================================
// 协议常量（来自服务端 v3_common.h）
// =========================================================
#define V3_DEFAULT_PORT         51820   // 默认 UDP 端口
#define V3_HEADER_SIZE          52      // v3 协议头大小
#define V3_MAGIC_WINDOW_SEC     60      // Magic 时间窗口（秒）
#define V3_MAGIC_TOLERANCE      1       // Magic 容差窗口数

// =========================================================
// 加密参数（ChaCha20-Poly1305 IETF）
// =========================================================
#define V3_KEY_SIZE             32      // 256-bit key
#define V3_NONCE_SIZE           12      // 96-bit nonce
#define V3_TAG_SIZE             16      // 128-bit auth tag
#define V3_SALT_SIZE            16      // Salt for key derivation

// =========================================================
// FEC 参数（对应服务端 v3_fec_simd.h）
// =========================================================
#define V3_FEC_MAX_DATA_SHARDS      20
#define V3_FEC_MAX_PARITY_SHARDS    10
#define V3_FEC_MAX_TOTAL_SHARDS     30
#define V3_FEC_SHARD_SIZE           1400
#define V3_FEC_XOR_GROUP_SIZE       4

// =========================================================
// 缓冲区大小
// =========================================================
#define V3_MTU_DEFAULT          1500
#define V3_MTU_MIN              576
#define V3_MTU_MAX              9000
#define V3_RECV_BUFFER_SIZE     (4 * 1024 * 1024)   // 4MB
#define V3_SEND_BUFFER_SIZE     (4 * 1024 * 1024)   // 4MB
#define V3_PACKET_BUFFER_SIZE   2048

// =========================================================
// 连接参数
// =========================================================
#define V3_MAX_CONNECTIONS      256
#define V3_KEEPALIVE_INTERVAL   30      // 秒
#define V3_CONNECT_TIMEOUT      10000   // 毫秒
#define V3_RETRY_INTERVAL       1000    // 毫秒
#define V3_MAX_RETRIES          5

// =========================================================
// IPC 参数
// =========================================================
#define V3_IPC_PIPE_NAME        "\\\\.\\pipe\\v3_core_ipc"
#define V3_IPC_BUFFER_SIZE      65536
#define V3_IPC_TIMEOUT          5000    // 毫秒

// =========================================================
// 构建信息
// =========================================================
#ifndef V3_BUILD_TIME
#define V3_BUILD_TIME           __DATE__ " " __TIME__
#endif

#ifndef V3_BUILD_COMPILER
#if defined(_MSC_VER)
#define V3_BUILD_COMPILER       "MSVC " _CRT_STRINGIZE(_MSC_VER)
#elif defined(__MINGW64__)
#define V3_BUILD_COMPILER       "MinGW-w64"
#elif defined(__MINGW32__)
#define V3_BUILD_COMPILER       "MinGW"
#elif defined(__GNUC__)
#define V3_BUILD_COMPILER       "GCC " __VERSION__
#else
#define V3_BUILD_COMPILER       "Unknown"
#endif
#endif

// =========================================================
// 平台信息
// =========================================================
#if defined(_WIN64)
#define V3_PLATFORM             "Windows x64"
#define V3_ARCH                 "x86_64"
#elif defined(_WIN32)
#define V3_PLATFORM             "Windows x86"
#define V3_ARCH                 "i686"
#else
#define V3_PLATFORM             "Unknown"
#define V3_ARCH                 "Unknown"
#endif

// =========================================================
// 功能开关
// =========================================================
#define V3_FEATURE_FEC          1       // FEC 纠错
#define V3_FEATURE_PACING       1       // 流量控制
#define V3_FEATURE_ANTIDETECT   1       // 流量伪装
#define V3_FEATURE_GUARD        1       // 守护进程

// =========================================================
// 调试开关
// =========================================================
#ifndef NDEBUG
#define V3_DEBUG                1
#else
#define V3_DEBUG                0
#endif

// =========================================================
// 版本信息结构
// =========================================================
typedef struct {
    int         major;
    int         minor;
    int         patch;
    int         build;
    const char *version_string;
    const char *build_time;
    const char *compiler;
    const char *platform;
    const char *arch;
    int         protocol_version;
} v3_version_info_t;

// 获取版本信息
static inline v3_version_info_t v3_get_version_info(void) {
    v3_version_info_t info = {
        .major = V3_VERSION_MAJOR,
        .minor = V3_VERSION_MINOR,
        .patch = V3_VERSION_PATCH,
        .build = V3_VERSION_BUILD,
        .version_string = V3_VERSION_STRING,
        .build_time = V3_BUILD_TIME,
        .compiler = V3_BUILD_COMPILER,
        .platform = V3_PLATFORM,
        .arch = V3_ARCH,
        .protocol_version = V3_PROTOCOL_VERSION,
    };
    return info;
}

// 版本兼容性检查
static inline int v3_check_protocol_compat(int server_version) {
    // v3 协议向后兼容 v3.x
    return (server_version >= 3 && server_version < 4);
}

#endif // V3_VERSION_H







