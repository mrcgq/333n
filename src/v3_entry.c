#define _CRT_SECURE_NO_WARNINGS
#define V3_BUILDING_CORE

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>

#include "v3_core.h"
#include "v3_lifecycle.h"
#include "v3_config.h"
#include "v3_ipc.h"
#include "v3_guard.h"
#include "v3_platform.h"
#include "version.h"

// =========================================================
// 全局状态
// =========================================================
static v3_lifecycle_t *g_lifecycle = NULL;
static volatile int g_signal_received = 0;

// =========================================================
// 信号处理
// =========================================================
static void signal_handler(int sig) {
    g_signal_received = sig;
    
    if (g_lifecycle) {
        if (sig == SIGINT || sig == SIGTERM) {
            v3_lifecycle_stop(g_lifecycle, V3_EXIT_SIGNAL);
        }
    }
}

static void setup_signal_handlers(void) {
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);
#ifdef SIGPIPE
    signal(SIGPIPE, SIG_IGN);
#endif
}

// =========================================================
// 版本信息
// =========================================================
static void print_version(void) {
    printf("v3 Windows Core %s\n", V3_VERSION_STRING);
    printf("Build: %s %s\n", V3_BUILD_DATE, V3_BUILD_TIME);
    printf("Compiler: %s\n", V3_COMPILER_INFO);
    printf("Protocol Version: %d.%d\n", 
           V3_PROTOCOL_VERSION_MAJOR, 
           V3_PROTOCOL_VERSION_MINOR);
}

static void print_banner(void) {
    printf("\n");
    printf("╔═══════════════════════════════════════════════════════════════╗\n");
    printf("║              v3 Windows Core Engine %s                    ║\n", V3_VERSION_STRING);
    printf("║         Compatible with v3 Server Protocol                    ║\n");
    printf("╚═══════════════════════════════════════════════════════════════╝\n");
    printf("\n");
}

// =========================================================
// 帮助信息
// =========================================================
static void print_usage(const char *prog) {
    printf("Usage: %s [OPTIONS]\n\n", prog);
    printf("Options:\n");
    printf("  -c, --config <file>     Configuration file path\n");
    printf("  -d, --daemon            Run as daemon (background)\n");
    printf("  -s, --service           Run as Windows service\n");
    printf("  --install-service       Install as Windows service\n");
    printf("  --uninstall-service     Uninstall Windows service\n");
    printf("  --start-service         Start the Windows service\n");
    printf("  --stop-service          Stop the Windows service\n");
    printf("  -v, --verbose           Verbose output\n");
    printf("  -q, --quiet             Quiet mode (minimal output)\n");
    printf("  --version               Show version and exit\n");
    printf("  -h, --help              Show this help\n");
    printf("\n");
    printf("IPC Commands (when core is running):\n");
    printf("  --ping                  Ping the running core\n");
    printf("  --status                Get core status\n");
    printf("  --connect               Request connection\n");
    printf("  --disconnect            Request disconnection\n");
    printf("  --shutdown              Shutdown the core\n");
    printf("\n");
    printf("Examples:\n");
    printf("  %s -c config.json       Start with config file\n", prog);
    printf("  %s -d                   Start as daemon\n", prog);
    printf("  %s --install-service    Install as Windows service\n", prog);
    printf("\n");
}

// =========================================================
// 命令行参数解析
// =========================================================
typedef struct {
    const char *config_path;
    bool        daemon_mode;
    bool        service_mode;
    bool        verbose;
    bool        quiet;
    
    // 服务管理
    bool        install_service;
    bool        uninstall_service;
    bool        start_service;
    bool        stop_service;
    
    // IPC 命令
    bool        ipc_ping;
    bool        ipc_status;
    bool        ipc_connect;
    bool        ipc_disconnect;
    bool        ipc_shutdown;
    
    // 其他
    bool        show_version;
    bool        show_help;
} cmdline_args_t;

static int parse_cmdline(int argc, char **argv, cmdline_args_t *args) {
    memset(args, 0, sizeof(*args));
    
    for (int i = 1; i < argc; i++) {
        const char *arg = argv[i];
        
        if (strcmp(arg, "-c") == 0 || strcmp(arg, "--config") == 0) {
            if (i + 1 < argc) {
                args->config_path = argv[++i];
            } else {
                fprintf(stderr, "Error: %s requires a path\n", arg);
                return -1;
            }
        }
        else if (strcmp(arg, "-d") == 0 || strcmp(arg, "--daemon") == 0) {
            args->daemon_mode = true;
        }
        else if (strcmp(arg, "-s") == 0 || strcmp(arg, "--service") == 0) {
            args->service_mode = true;
        }
        else if (strcmp(arg, "--install-service") == 0) {
            args->install_service = true;
        }
        else if (strcmp(arg, "--uninstall-service") == 0) {
            args->uninstall_service = true;
        }
        else if (strcmp(arg, "--start-service") == 0) {
            args->start_service = true;
        }
        else if (strcmp(arg, "--stop-service") == 0) {
            args->stop_service = true;
        }
        else if (strcmp(arg, "-v") == 0 || strcmp(arg, "--verbose") == 0) {
            args->verbose = true;
        }
        else if (strcmp(arg, "-q") == 0 || strcmp(arg, "--quiet") == 0) {
            args->quiet = true;
        }
        else if (strcmp(arg, "--ping") == 0) {
            args->ipc_ping = true;
        }
        else if (strcmp(arg, "--status") == 0) {
            args->ipc_status = true;
        }
        else if (strcmp(arg, "--connect") == 0) {
            args->ipc_connect = true;
        }
        else if (strcmp(arg, "--disconnect") == 0) {
            args->ipc_disconnect = true;
        }
        else if (strcmp(arg, "--shutdown") == 0) {
            args->ipc_shutdown = true;
        }
        else if (strcmp(arg, "--version") == 0) {
            args->show_version = true;
        }
        else if (strcmp(arg, "-h") == 0 || strcmp(arg, "--help") == 0) {
            args->show_help = true;
        }
        else {
            fprintf(stderr, "Unknown option: %s\n", arg);
            return -1;
        }
    }
    
    return 0;
}

// =========================================================
// IPC 命令处理
// =========================================================
static int handle_ipc_command(const cmdline_args_t *args) {
    v3_ipc_client_t *client = v3_ipc_client_create();
    if (!client) {
        fprintf(stderr, "Failed to create IPC client\n");
        return 1;
    }
    
    v3_error_t err = v3_ipc_client_connect(client, NULL, V3_IPC_TIMEOUT_MS);
    if (err != V3_OK) {
        fprintf(stderr, "Cannot connect to core process: %s\n", v3_error_string(err));
        fprintf(stderr, "Is v3 core running?\n");
        v3_ipc_client_destroy(client);
        return 1;
    }
    
    int result = 0;
    
    if (args->ipc_ping) {
        printf("Pinging core...\n");
        err = v3_ipc_ping(client, 5000);
        if (err == V3_OK) {
            printf("Core is alive!\n");
        } else {
            fprintf(stderr, "Ping failed: %s\n", v3_error_string(err));
            result = 1;
        }
    }
    
    if (args->ipc_status) {
        v3_conn_state_t state;
        err = v3_ipc_get_state(client, &state, 5000);
        if (err == V3_OK) {
            printf("Core Status:\n");
            printf("  Connection State: %s\n", v3_state_string(state));
            
            v3_stats_t stats;
            if (v3_ipc_get_stats(client, &stats, 5000) == V3_OK) {
                printf("  Packets Sent:     %llu\n", (unsigned long long)stats.packets_sent);
                printf("  Packets Recv:     %llu\n", (unsigned long long)stats.packets_recv);
                printf("  Bytes Sent:       %llu\n", (unsigned long long)stats.bytes_sent);
                printf("  Bytes Recv:       %llu\n", (unsigned long long)stats.bytes_recv);
                printf("  RTT:              %llu us\n", (unsigned long long)stats.rtt_us);
            }
        } else {
            fprintf(stderr, "Failed to get status: %s\n", v3_error_string(err));
            result = 1;
        }
    }
    
    if (args->ipc_connect) {
        printf("Requesting connection...\n");
        err = v3_ipc_request_connect(client, 10000);
        if (err == V3_OK) {
            printf("Connection request sent.\n");
        } else {
            fprintf(stderr, "Failed: %s\n", v3_error_string(err));
            result = 1;
        }
    }
    
    if (args->ipc_disconnect) {
        printf("Requesting disconnection...\n");
        err = v3_ipc_request_disconnect(client, 5000);
        if (err == V3_OK) {
            printf("Disconnection request sent.\n");
        } else {
            fprintf(stderr, "Failed: %s\n", v3_error_string(err));
            result = 1;
        }
    }
    
    if (args->ipc_shutdown) {
        printf("Requesting shutdown...\n");
        err = v3_ipc_request_shutdown(client, 5000);
        if (err == V3_OK) {
            printf("Shutdown request sent.\n");
        } else {
            fprintf(stderr, "Failed: %s\n", v3_error_string(err));
            result = 1;
        }
    }
    
    v3_ipc_client_disconnect(client);
    v3_ipc_client_destroy(client);
    
    return result;
}

// =========================================================
// 服务管理
// =========================================================
#ifdef V3_PLATFORM_WINDOWS

#define V3_SERVICE_NAME         "v3core"
#define V3_SERVICE_DISPLAY      "v3 Core Service"
#define V3_SERVICE_DESCRIPTION  "v3 Windows Core Engine - Secure Network Tunnel"

static int handle_service_management(const cmdline_args_t *args) {
    if (args->install_service) {
        printf("Installing v3 service...\n");
        v3_error_t err = v3_service_install(
            V3_SERVICE_NAME,
            V3_SERVICE_DISPLAY,
            V3_SERVICE_DESCRIPTION,
            NULL
        );
        if (err == V3_OK) {
            printf("Service installed successfully.\n");
            printf("Use 'sc start %s' or '--start-service' to start.\n", V3_SERVICE_NAME);
            return 0;
        } else {
            fprintf(stderr, "Failed to install service: %s\n", v3_error_string(err));
            return 1;
        }
    }
    
    if (args->uninstall_service) {
        printf("Uninstalling v3 service...\n");
        
        if (v3_service_is_running(V3_SERVICE_NAME)) {
            printf("Stopping running service...\n");
            v3_service_stop(V3_SERVICE_NAME);
            v3_sleep_ms(2000);
        }
        
        v3_error_t err = v3_service_uninstall(V3_SERVICE_NAME);
        if (err == V3_OK) {
            printf("Service uninstalled successfully.\n");
            return 0;
        } else {
            fprintf(stderr, "Failed to uninstall service: %s\n", v3_error_string(err));
            return 1;
        }
    }
    
    if (args->start_service) {
        printf("Starting v3 service...\n");
        v3_error_t err = v3_service_start(V3_SERVICE_NAME);
        if (err == V3_OK) {
            printf("Service started.\n");
            return 0;
        } else {
            fprintf(stderr, "Failed to start service: %s\n", v3_error_string(err));
            return 1;
        }
    }
    
    if (args->stop_service) {
        printf("Stopping v3 service...\n");
        v3_error_t err = v3_service_stop(V3_SERVICE_NAME);
        if (err == V3_OK) {
            printf("Service stopped.\n");
            return 0;
        } else {
            fprintf(stderr, "Failed to stop service: %s\n", v3_error_string(err));
            return 1;
        }
    }
    
    return -1;  // 没有服务管理命令
}

#endif // V3_PLATFORM_WINDOWS

// =========================================================
// 主程序
// =========================================================
int main(int argc, char **argv) {
    int exit_code = 0;
    cmdline_args_t args;
    
    // 解析命令行
    if (parse_cmdline(argc, argv, &args) != 0) {
        return 1;
    }
    
    // 显示版本
    if (args.show_version) {
        print_version();
        return 0;
    }
    
    // 显示帮助
    if (args.show_help) {
        print_usage(argv[0]);
        return 0;
    }
    
    // 初始化平台
    v3_error_t err = v3_init();
    if (err != V3_OK) {
        fprintf(stderr, "Failed to initialize v3: %s\n", v3_error_string(err));
        return 1;
    }
    
#ifdef V3_PLATFORM_WINDOWS
    // 服务管理命令
    int service_result = handle_service_management(&args);
    if (service_result >= 0) {
        v3_cleanup();
        return service_result;
    }
#endif
    
    // IPC 命令
    if (args.ipc_ping || args.ipc_status || args.ipc_connect || 
        args.ipc_disconnect || args.ipc_shutdown) {
        exit_code = handle_ipc_command(&args);
        v3_cleanup();
        return exit_code;
    }
    
    // 检查是否已有实例运行
    if (v3_is_instance_running()) {
        fprintf(stderr, "Another instance of v3 core is already running.\n");
        fprintf(stderr, "Use IPC commands (--status, --shutdown) to interact with it.\n");
        v3_cleanup();
        return 1;
    }
    
    // 打印横幅
    if (!args.quiet) {
        print_banner();
    }
    
    // 设置信号处理
    setup_signal_handlers();
    
    // 创建生命周期管理器
    g_lifecycle = v3_lifecycle_create();
    if (!g_lifecycle) {
        fprintf(stderr, "Failed to create lifecycle manager\n");
        v3_cleanup();
        return 1;
    }
    
    // 配置启动选项
    v3_startup_options_t options = {
        .daemon_mode = args.daemon_mode,
        .single_instance = true,
        .enable_ipc = true,
        .enable_guard = true,
        .config_path = args.config_path,
        .log_path = NULL,
        .pid_file = NULL,
        .verbosity = args.verbose ? 2 : (args.quiet ? 0 : 1),
    };
    
    // 初始化生命周期
    err = v3_lifecycle_init(g_lifecycle, argc, argv, &options);
    if (err != V3_OK) {
        fprintf(stderr, "Failed to initialize: %s\n", v3_error_string(err));
        v3_lifecycle_destroy(g_lifecycle);
        v3_cleanup();
        return 1;
    }
    
#ifdef V3_PLATFORM_WINDOWS
    // 服务模式
    if (args.service_mode) {
        exit_code = v3_service_run(V3_SERVICE_NAME, g_lifecycle);
    } else
#endif
    {
        // 普通模式或守护模式
        err = v3_lifecycle_start(g_lifecycle);
        if (err != V3_OK) {
            fprintf(stderr, "Failed to start: %s\n", v3_error_string(err));
            exit_code = 1;
        } else {
            // 运行主循环
            exit_code = v3_lifecycle_run(g_lifecycle);
        }
    }
    
    // 清理
    v3_lifecycle_destroy(g_lifecycle);
    g_lifecycle = NULL;
    
    v3_cleanup();
    
    if (!args.quiet) {
        printf("v3 core exited with code %d\n", exit_code);
    }
    
    return exit_code;
}

