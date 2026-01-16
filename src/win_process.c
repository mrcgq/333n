
#define _WIN32_WINNT 0x0601
#include <windows.h>
#include <tlhelp32.h>
#include <psapi.h>
#include <sddl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "v3_platform.h"
#include "version.h"

#pragma comment(lib, "psapi.lib")

// =========================================================
// 单实例互斥锁
// =========================================================
static HANDLE g_instance_mutex = NULL;
static const WCHAR *INSTANCE_MUTEX_NAME = L"Global\\v3_core_instance_mutex";

BOOL v3_process_ensure_single_instance(void) {
    // 尝试创建全局互斥锁
    g_instance_mutex = CreateMutexW(NULL, TRUE, INSTANCE_MUTEX_NAME);
    
    if (g_instance_mutex == NULL) {
        return FALSE;
    }
    
    if (GetLastError() == ERROR_ALREADY_EXISTS) {
        // 已有实例在运行
        CloseHandle(g_instance_mutex);
        g_instance_mutex = NULL;
        return FALSE;
    }
    
    return TRUE;
}

void v3_process_release_single_instance(void) {
    if (g_instance_mutex != NULL) {
        ReleaseMutex(g_instance_mutex);
        CloseHandle(g_instance_mutex);
        g_instance_mutex = NULL;
    }
}

// =========================================================
// 进程信息
// =========================================================

DWORD v3_process_get_current_id(void) {
    return GetCurrentProcessId();
}

DWORD v3_process_get_parent_id(void) {
    DWORD current_pid = GetCurrentProcessId();
    DWORD parent_pid = 0;
    
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot == INVALID_HANDLE_VALUE) {
        return 0;
    }
    
    PROCESSENTRY32W pe;
    pe.dwSize = sizeof(pe);
    
    if (Process32FirstW(snapshot, &pe)) {
        do {
            if (pe.th32ProcessID == current_pid) {
                parent_pid = pe.th32ParentProcessID;
                break;
            }
        } while (Process32NextW(snapshot, &pe));
    }
    
    CloseHandle(snapshot);
    return parent_pid;
}

BOOL v3_process_is_elevated(void) {
    BOOL elevated = FALSE;
    HANDLE token = NULL;
    
    if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token)) {
        TOKEN_ELEVATION elevation;
        DWORD size;
        
        if (GetTokenInformation(token, TokenElevation, 
                               &elevation, sizeof(elevation), &size)) {
            elevated = elevation.TokenIsElevated;
        }
        
        CloseHandle(token);
    }
    
    return elevated;
}

// =========================================================
// 进程枚举
// =========================================================

int v3_process_find_by_name(const char *name, DWORD *pids, int max_count) {
    if (name == NULL || pids == NULL || max_count <= 0) return 0;
    
    WCHAR name_wide[MAX_PATH];
    MultiByteToWideChar(CP_UTF8, 0, name, -1, name_wide, MAX_PATH);
    
    int count = 0;
    
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot == INVALID_HANDLE_VALUE) return 0;
    
    PROCESSENTRY32W pe;
    pe.dwSize = sizeof(pe);
    
    if (Process32FirstW(snapshot, &pe)) {
        do {
            if (_wcsicmp(pe.szExeFile, name_wide) == 0) {
                if (count < max_count) {
                    pids[count] = pe.th32ProcessID;
                }
                count++;
            }
        } while (Process32NextW(snapshot, &pe));
    }
    
    CloseHandle(snapshot);
    return count;
}

BOOL v3_process_exists(DWORD pid) {
    HANDLE process = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (process == NULL) return FALSE;
    
    DWORD exit_code;
    BOOL result = GetExitCodeProcess(process, &exit_code);
    CloseHandle(process);
    
    return result && exit_code == STILL_ACTIVE;
}

// =========================================================
// 进程创建
// =========================================================

typedef struct {
    DWORD   pid;
    HANDLE  process;
    HANDLE  thread;
    int     exit_code;
} v3_process_t;

v3_process_t* v3_process_create(const char *cmd_line, 
                                 const char *work_dir,
                                 BOOL hidden,
                                 BOOL wait) {
    v3_process_t *proc = (v3_process_t*)calloc(1, sizeof(v3_process_t));
    if (proc == NULL) return NULL;
    
    STARTUPINFOW si = {0};
    PROCESS_INFORMATION pi = {0};
    
    si.cb = sizeof(si);
    
    if (hidden) {
        si.dwFlags = STARTF_USESHOWWINDOW;
        si.wShowWindow = SW_HIDE;
    }
    
    WCHAR cmd_wide[4096];
    MultiByteToWideChar(CP_UTF8, 0, cmd_line, -1, cmd_wide, 4096);
    
    WCHAR *work_dir_wide = NULL;
    WCHAR work_dir_buf[MAX_PATH];
    if (work_dir && work_dir[0] != '\0') {
        MultiByteToWideChar(CP_UTF8, 0, work_dir, -1, work_dir_buf, MAX_PATH);
        work_dir_wide = work_dir_buf;
    }
    
    DWORD flags = CREATE_NEW_PROCESS_GROUP;
    if (hidden) {
        flags |= CREATE_NO_WINDOW;
    }
    
    if (!CreateProcessW(NULL, cmd_wide, NULL, NULL, FALSE,
                        flags, NULL, work_dir_wide, &si, &pi)) {
        free(proc);
        return NULL;
    }
    
    proc->pid = pi.dwProcessId;
    proc->process = pi.hProcess;
    proc->thread = pi.hThread;
    proc->exit_code = -1;
    
    if (wait) {
        WaitForSingleObject(proc->process, INFINITE);
        GetExitCodeProcess(proc->process, (DWORD*)&proc->exit_code);
    }
    
    return proc;
}

int v3_process_wait(v3_process_t *proc, int timeout_ms) {
    if (proc == NULL || proc->process == NULL) return -1;
    
    DWORD result = WaitForSingleObject(proc->process, 
                                       timeout_ms < 0 ? INFINITE : timeout_ms);
    
    if (result == WAIT_OBJECT_0) {
        GetExitCodeProcess(proc->process, (DWORD*)&proc->exit_code);
        return proc->exit_code;
    }
    
    return -1;
}

void v3_process_terminate(v3_process_t *proc, int exit_code) {
    if (proc == NULL || proc->process == NULL) return;
    
    TerminateProcess(proc->process, exit_code);
}

void v3_process_free(v3_process_t *proc) {
    if (proc == NULL) return;
    
    if (proc->process) CloseHandle(proc->process);
    if (proc->thread) CloseHandle(proc->thread);
    
    free(proc);
}

DWORD v3_process_get_id(v3_process_t *proc) {
    return proc ? proc->pid : 0;
}

int v3_process_get_exit_code(v3_process_t *proc) {
    return proc ? proc->exit_code : -1;
}

// =========================================================
// 进程终止
// =========================================================

BOOL v3_process_kill(DWORD pid, int exit_code) {
    HANDLE process = OpenProcess(PROCESS_TERMINATE, FALSE, pid);
    if (process == NULL) return FALSE;
    
    BOOL result = TerminateProcess(process, exit_code);
    CloseHandle(process);
    
    return result;
}

BOOL v3_process_kill_tree(DWORD parent_pid) {
    // 首先终止所有子进程
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot == INVALID_HANDLE_VALUE) return FALSE;
    
    PROCESSENTRY32W pe;
    pe.dwSize = sizeof(pe);
    
    // 收集所有子进程
    DWORD child_pids[256];
    int child_count = 0;
    
    if (Process32FirstW(snapshot, &pe)) {
        do {
            if (pe.th32ParentProcessID == parent_pid && 
                pe.th32ProcessID != parent_pid) {
                if (child_count < 256) {
                    child_pids[child_count++] = pe.th32ProcessID;
                }
            }
        } while (Process32NextW(snapshot, &pe));
    }
    
    CloseHandle(snapshot);
    
    // 递归终止子进程
    for (int i = 0; i < child_count; i++) {
        v3_process_kill_tree(child_pids[i]);
    }
    
    // 终止父进程
    return v3_process_kill(parent_pid, 1);
}

// =========================================================
// 权限提升
// =========================================================

BOOL v3_process_elevate(const char *params) {
    char exe_path[MAX_PATH];
    if (v3_get_exe_path(exe_path, MAX_PATH) != 0) {
        return FALSE;
    }
    
    WCHAR exe_path_wide[MAX_PATH];
    MultiByteToWideChar(CP_UTF8, 0, exe_path, -1, exe_path_wide, MAX_PATH);
    
    WCHAR params_wide[4096] = {0};
    if (params && params[0] != '\0') {
        MultiByteToWideChar(CP_UTF8, 0, params, -1, params_wide, 4096);
    }
    
    SHELLEXECUTEINFOW sei = {0};
    sei.cbSize = sizeof(sei);
    sei.lpVerb = L"runas";
    sei.lpFile = exe_path_wide;
    sei.lpParameters = params_wide;
    sei.nShow = SW_SHOWNORMAL;
    sei.fMask = SEE_MASK_NOCLOSEPROCESS;
    
    if (!ShellExecuteExW(&sei)) {
        return FALSE;
    }
    
    if (sei.hProcess) {
        CloseHandle(sei.hProcess);
    }
    
    return TRUE;
}

// =========================================================
// 进程内存信息
// =========================================================

BOOL v3_process_get_memory_info(DWORD pid, 
                                 size_t *working_set,
                                 size_t *peak_working_set,
                                 size_t *private_bytes) {
    HANDLE process = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, 
                                 FALSE, pid);
    if (process == NULL) return FALSE;
    
    PROCESS_MEMORY_COUNTERS_EX pmc;
    pmc.cb = sizeof(pmc);
    
    BOOL result = GetProcessMemoryInfo(process, 
                                       (PROCESS_MEMORY_COUNTERS*)&pmc, 
                                       sizeof(pmc));
    
    if (result) {
        if (working_set) *working_set = pmc.WorkingSetSize;
        if (peak_working_set) *peak_working_set = pmc.PeakWorkingSetSize;
        if (private_bytes) *private_bytes = pmc.PrivateUsage;
    }
    
    CloseHandle(process);
    return result;
}


