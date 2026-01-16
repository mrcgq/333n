
#define _CRT_SECURE_NO_WARNINGS
#define V3_BUILDING_CORE

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

#include "v3_config.h"
#include "v3_platform.h"

// =========================================================
// 简易 JSON 解析器（避免外部依赖）
// =========================================================

typedef enum {
    JSON_NULL,
    JSON_BOOL,
    JSON_NUMBER,
    JSON_STRING,
    JSON_ARRAY,
    JSON_OBJECT,
} json_type_t;

typedef struct json_value_s json_value_t;

struct json_value_s {
    json_type_t type;
    union {
        bool boolean;
        double number;
        char *string;
        struct {
            json_value_t **items;
            int count;
        } array;
        struct {
            char **keys;
            json_value_t **values;
            int count;
        } object;
    } data;
};

static void json_free(json_value_t *val);
static json_value_t* json_parse(const char **p);
static json_value_t* json_get(json_value_t *obj, const char *key);
static bool json_get_bool(json_value_t *obj, const char *key, bool def);
static int json_get_int(json_value_t *obj, const char *key, int def);
static int64_t json_get_int64(json_value_t *obj, const char *key, int64_t def);
static const char* json_get_string(json_value_t *obj, const char *key, const char *def);

// =========================================================
// 配置 API 实现
// =========================================================

void v3_config_init_default(v3_config_t *config) {
    if (!config) return;
    
    memset(config, 0, sizeof(*config));
    
    config->version = 1;
    config->active_server = -1;
    
    // FEC 默认配置
    config->fec.enabled = false;
    config->fec.type = V3_FEC_AUTO;
    config->fec.data_shards = 5;
    config->fec.parity_shards = 2;
    config->fec.adaptive = true;
    
    // Pacing 默认配置
    config->pacing.enabled = false;
    config->pacing.initial_bps = 100 * 1000 * 1000;  // 100 Mbps
    config->pacing.min_bps = 1 * 1000 * 1000;        // 1 Mbps
    config->pacing.max_bps = 1000 * 1000 * 1000;     // 1 Gbps
    config->pacing.brutal_mode = false;
    
    // 反检测默认配置
    config->antidetect.enabled = false;
    config->antidetect.profile = V3_PROFILE_NONE;
    
    // 日志默认配置
    config->log.level = V3_LOG_LEVEL_INFO;
    config->log.to_file = false;
    config->log.to_console = true;
    config->log.max_file_size_mb = 10;
    config->log.max_files = 5;
    
    // 系统默认配置
    config->system.auto_start = false;
    config->system.minimize_to_tray = true;
    config->system.close_to_tray = true;
    config->system.auto_reconnect = true;
    config->system.reconnect_delay_sec = 5;
    config->system.reconnect_max_attempts = 0;  // 无限
    strcpy(config->system.language, "en");
}

v3_error_t v3_config_load(v3_config_t *config, const char *path) {
    if (!config) return V3_ERR_INVALID_PARAM;
    
    char config_path[V3_CONFIG_MAX_PATH];
    
    if (path) {
        strncpy(config_path, path, sizeof(config_path) - 1);
    } else {
        if (v3_config_get_default_path(config_path, sizeof(config_path)) <= 0) {
            return V3_ERR_CONFIG;
        }
    }
    
    // 读取文件
    FILE *fp = fopen(config_path, "r");
    if (!fp) {
        return V3_ERR_CONFIG;
    }
    
    fseek(fp, 0, SEEK_END);
    long size = ftell(fp);
    fseek(fp, 0, SEEK_SET);
    
    if (size <= 0 || size > 1024 * 1024) {  // 最大 1MB
        fclose(fp);
        return V3_ERR_CONFIG;
    }
    
    char *json = (char *)malloc(size + 1);
    if (!json) {
        fclose(fp);
        return V3_ERR_NO_MEMORY;
    }
    
    fread(json, 1, size, fp);
    json[size] = '\0';
    fclose(fp);
    
    v3_error_t err = v3_config_from_json(json, config);
    
    free(json);
    
    return err;
}

v3_error_t v3_config_save(const v3_config_t *config, const char *path) {
    if (!config) return V3_ERR_INVALID_PARAM;
    
    char config_path[V3_CONFIG_MAX_PATH];
    
    if (path) {
        strncpy(config_path, path, sizeof(config_path) - 1);
    } else {
        if (v3_config_get_default_path(config_path, sizeof(config_path)) <= 0) {
            return V3_ERR_CONFIG;
        }
    }
    
    // 确保目录存在
    char dir[V3_CONFIG_MAX_PATH];
    
    snprintf(dir, sizeof(dir), "%s", config_path); // 使用 snprintf 安全地复制字符串
    char *last_sep = strrchr(dir, '\\');
    
    if (!last_sep) last_sep = strrchr(dir, '/');
    if (last_sep) {
        *last_sep = '\0';
        v3_mkdir_recursive(dir);
    }
    
    // 生成 JSON
    char *json = (char *)malloc(65536);
    if (!json) return V3_ERR_NO_MEMORY;
    
    int len = v3_config_to_json(config, json, 65536);
    if (len < 0) {
        free(json);
        return V3_ERR_CONFIG;
    }
    
    // 写入文件
    FILE *fp = fopen(config_path, "w");
    if (!fp) {
        free(json);
        return V3_ERR_PLATFORM;
    }
    
    fwrite(json, 1, len, fp);
    fclose(fp);
    
    free(json);
    
    return V3_OK;
}

v3_error_t v3_config_validate(const v3_config_t *config, char *error_msg, size_t error_msg_len) {
    if (!config) {
        if (error_msg) strncpy(error_msg, "Config is NULL", error_msg_len - 1);
        return V3_ERR_INVALID_PARAM;
    }
    
    // 验证服务器配置
    for (int i = 0; i < config->server_count; i++) {
        const v3_server_config_t *srv = &config->servers[i];
        
        if (!srv->address[0]) {
            if (error_msg) {
                snprintf(error_msg, error_msg_len, 
                         "Server %d: address is empty", i);
            }
            return V3_ERR_CONFIG;
        }
        
        if (srv->port == 0) {
            if (error_msg) {
                snprintf(error_msg, error_msg_len,
                         "Server %d: port is 0", i);
            }
            return V3_ERR_CONFIG;
        }
    }
    
    // 验证 FEC 配置
    if (config->fec.enabled) {
        if (config->fec.data_shards == 0 || config->fec.data_shards > 20) {
            if (error_msg) {
                strncpy(error_msg, "FEC: data_shards must be 1-20", error_msg_len - 1);
            }
            return V3_ERR_CONFIG;
        }
        
        if (config->fec.parity_shards == 0 || config->fec.parity_shards > 10) {
            if (error_msg) {
                strncpy(error_msg, "FEC: parity_shards must be 1-10", error_msg_len - 1);
            }
            return V3_ERR_CONFIG;
        }
    }
    
    return V3_OK;
}

int v3_config_get_default_path(char *buf, size_t buflen) {
    char app_dir[V3_CONFIG_MAX_PATH];
    
    if (v3_get_app_data_dir(app_dir, sizeof(app_dir)) <= 0) {
        return -1;
    }
    
    return snprintf(buf, buflen, "%s\\%s", app_dir, V3_CONFIG_FILENAME);
}

// =========================================================
// 服务器配置操作
// =========================================================

int v3_config_add_server(v3_config_t *config, const v3_server_config_t *server) {
    if (!config || !server) return -1;
    
    if (config->server_count >= V3_CONFIG_MAX_SERVERS) {
        return -1;
    }
    
    int index = config->server_count++;
    memcpy(&config->servers[index], server, sizeof(*server));
    
    if (config->active_server < 0) {
        config->active_server = index;
    }
    
    return index;
}

v3_error_t v3_config_remove_server(v3_config_t *config, int index) {
    if (!config || index < 0 || index >= config->server_count) {
        return V3_ERR_INVALID_PARAM;
    }
    
    // 移动后面的元素
    for (int i = index; i < config->server_count - 1; i++) {
        memcpy(&config->servers[i], &config->servers[i + 1], 
               sizeof(v3_server_config_t));
    }
    
    config->server_count--;
    
    // 调整活动服务器索引
    if (config->active_server == index) {
        config->active_server = config->server_count > 0 ? 0 : -1;
    } else if (config->active_server > index) {
        config->active_server--;
    }
    
    return V3_OK;
}

v3_error_t v3_config_update_server(v3_config_t *config, int index,
                                    const v3_server_config_t *server) {
    if (!config || !server || index < 0 || index >= config->server_count) {
        return V3_ERR_INVALID_PARAM;
    }
    
    memcpy(&config->servers[index], server, sizeof(*server));
    
    return V3_OK;
}

v3_error_t v3_config_set_active_server(v3_config_t *config, int index) {
    if (!config) return V3_ERR_INVALID_PARAM;
    
    if (index < -1 || index >= config->server_count) {
        return V3_ERR_INVALID_PARAM;
    }
    
    config->active_server = index;
    
    return V3_OK;
}

const v3_server_config_t* v3_config_get_active_server(const v3_config_t *config) {
    if (!config || config->active_server < 0 || 
        config->active_server >= config->server_count) {
        return NULL;
    }
    
    return &config->servers[config->active_server];
}

// =========================================================
// JSON 序列化
// =========================================================

static void json_escape_string(char *out, size_t outlen, const char *str) {
    char *p = out;
    char *end = out + outlen - 2;
    
    *p++ = '"';
    while (*str && p < end) {
        switch (*str) {
            case '"':  if (p + 1 < end) { *p++ = '\\'; *p++ = '"'; } break;
            case '\\': if (p + 1 < end) { *p++ = '\\'; *p++ = '\\'; } break;
            case '\n': if (p + 1 < end) { *p++ = '\\'; *p++ = 'n'; } break;
            case '\r': if (p + 1 < end) { *p++ = '\\'; *p++ = 'r'; } break;
            case '\t': if (p + 1 < end) { *p++ = '\\'; *p++ = 't'; } break;
            default:   *p++ = *str; break;
        }
        str++;
    }
    *p++ = '"';
    *p = '\0';
}

int v3_config_to_json(const v3_config_t *config, char *buf, size_t buflen) {
    if (!config || !buf || buflen == 0) return -1;
    
    int pos = 0;
    char tmp[1024];
    
#define APPEND(...) do { \
    int n = snprintf(buf + pos, buflen - pos, __VA_ARGS__); \
    if (n < 0 || pos + n >= (int)buflen) return -1; \
    pos += n; \
} while(0)
    
    APPEND("{\n");
    APPEND("  \"version\": %u,\n", config->version);
    APPEND("  \"active_server\": %d,\n", config->active_server);
    
    // 服务器列表
    APPEND("  \"servers\": [\n");
    for (int i = 0; i < config->server_count; i++) {
        const v3_server_config_t *srv = &config->servers[i];
        
        json_escape_string(tmp, sizeof(tmp), srv->name);
        APPEND("    {\n");
        APPEND("      \"name\": %s,\n", tmp);
        
        json_escape_string(tmp, sizeof(tmp), srv->address);
        APPEND("      \"address\": %s,\n", tmp);
        APPEND("      \"port\": %u,\n", srv->port);
        APPEND("      \"enabled\": %s,\n", srv->enabled ? "true" : "false");
        APPEND("      \"mtu\": %u,\n", srv->mtu);
        APPEND("      \"timeout\": %d\n", srv->timeout_sec);
        APPEND("    }%s\n", i < config->server_count - 1 ? "," : "");
    }
    APPEND("  ],\n");
    
    // FEC 配置
    APPEND("  \"fec\": {\n");
    APPEND("    \"enabled\": %s,\n", config->fec.enabled ? "true" : "false");
    APPEND("    \"type\": %d,\n", config->fec.type);
    APPEND("    \"data_shards\": %u,\n", config->fec.data_shards);
    APPEND("    \"parity_shards\": %u,\n", config->fec.parity_shards);
    APPEND("    \"adaptive\": %s\n", config->fec.adaptive ? "true" : "false");
    APPEND("  },\n");
    
    // Pacing 配置
    APPEND("  \"pacing\": {\n");
    APPEND("    \"enabled\": %s,\n", config->pacing.enabled ? "true" : "false");
    APPEND("    \"initial_bps\": %llu,\n", (unsigned long long)config->pacing.initial_bps);
    APPEND("    \"min_bps\": %llu,\n", (unsigned long long)config->pacing.min_bps);
    APPEND("    \"max_bps\": %llu,\n", (unsigned long long)config->pacing.max_bps);
    APPEND("    \"brutal_mode\": %s\n", config->pacing.brutal_mode ? "true" : "false");
    APPEND("  },\n");
    
    // 系统配置
    APPEND("  \"system\": {\n");
    APPEND("    \"auto_start\": %s,\n", config->system.auto_start ? "true" : "false");
    APPEND("    \"minimize_to_tray\": %s,\n", config->system.minimize_to_tray ? "true" : "false");
    APPEND("    \"close_to_tray\": %s,\n", config->system.close_to_tray ? "true" : "false");
    APPEND("    \"auto_reconnect\": %s,\n", config->system.auto_reconnect ? "true" : "false");
    APPEND("    \"reconnect_delay_sec\": %d,\n", config->system.reconnect_delay_sec);
    APPEND("    \"reconnect_max_attempts\": %d,\n", config->system.reconnect_max_attempts);
    json_escape_string(tmp, sizeof(tmp), config->system.language);
    APPEND("    \"language\": %s\n", tmp);
    APPEND("  }\n");
    
    APPEND("}\n");
    
#undef APPEND
    
    return pos;
}

// 简易 JSON 解析实现（省略完整实现以节省空间，实际使用时需完整实现）
v3_error_t v3_config_from_json(const char *json, v3_config_t *config) {
    if (!json || !config) return V3_ERR_INVALID_PARAM;
    
    // 初始化默认值
    v3_config_init_default(config);
    
    // 这里应该有完整的 JSON 解析逻辑
    // 为了简化，这里仅作为框架
    
    // TODO: 实现完整的 JSON 解析
    
    return V3_OK;
}

// =========================================================
// 配置监听（文件变更通知）
// =========================================================

static v3_config_change_callback_t g_config_change_callback = NULL;
static void *g_config_change_userdata = NULL;
static v3_thread_t g_config_watch_thread;
static volatile bool g_config_watch_running = false;
static char g_config_watch_path[V3_CONFIG_MAX_PATH];

static void* config_watch_thread_func(void *arg) {
    (void)arg;
    
#ifdef V3_PLATFORM_WINDOWS
    char dir[V3_CONFIG_MAX_PATH];
    
	snprintf(dir, sizeof(dir), "%s", g_config_watch_path); // 使用 snprintf
    
    char *last_sep = strrchr(dir, '\\');
    if (last_sep) *last_sep = '\0';
    
    HANDLE hDir = CreateFileA(
        dir,
        FILE_LIST_DIRECTORY,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        NULL,
        OPEN_EXISTING,
        FILE_FLAG_BACKUP_SEMANTICS,
        NULL
    );
    
    if (hDir == INVALID_HANDLE_VALUE) {
        return NULL;
    }
    
    char buffer[4096];
    DWORD bytes;
    
    while (g_config_watch_running) {
        if (ReadDirectoryChangesW(
                hDir,
                buffer,
                sizeof(buffer),
                FALSE,
                FILE_NOTIFY_CHANGE_LAST_WRITE,
                &bytes,
                NULL,
                NULL)) {
            
            // 文件变更，重新加载配置
            v3_sleep_ms(100);  // 等待写入完成
            
            v3_config_t new_config;
            if (v3_config_load(&new_config, g_config_watch_path) == V3_OK) {
                if (g_config_change_callback) {
                    g_config_change_callback(&new_config, g_config_change_userdata);
                }
            }
        }
    }
    
    CloseHandle(hDir);
#endif
    
    return NULL;
}

v3_error_t v3_config_watch(const char *path, v3_config_change_callback_t callback,
                            void *userdata) {
    if (!path || !callback) return V3_ERR_INVALID_PARAM;
    
    if (g_config_watch_running) {
        v3_config_unwatch();
    }
    
    strncpy(g_config_watch_path, path, sizeof(g_config_watch_path) - 1);
    g_config_change_callback = callback;
    g_config_change_userdata = userdata;
    g_config_watch_running = true;
    
    return v3_thread_create(&g_config_watch_thread, config_watch_thread_func, NULL);
}

void v3_config_unwatch(void) {
    if (!g_config_watch_running) return;
    
    g_config_watch_running = false;
    v3_thread_join(g_config_watch_thread, NULL);
    
    g_config_change_callback = NULL;
    g_config_change_userdata = NULL;
}





