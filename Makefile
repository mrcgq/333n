
# =========================================================================
# v3 Core Windows Makefile
# 用于 MinGW-w64 编译 v3 Windows 内核
# =========================================================================

# --- 编译器设置 ---
CC = gcc
WINDRES = windres

# 检测是否为交叉编译
ifeq ($(OS),Windows_NT)
    # 原生 Windows 编译
    EXE_EXT = .exe
    RM = del /Q
    MKDIR = mkdir
    PATHSEP = \\
else
    # Linux 交叉编译到 Windows
    CC = x86_64-w64-mingw32-gcc
    WINDRES = x86_64-w64-mingw32-windres
    EXE_EXT = .exe
    RM = rm -f
    MKDIR = mkdir -p
    PATHSEP = /
endif

# --- 目录设置 ---
SRC_DIR = src
INC_DIR = include
BUILD_DIR = build
OBJ_DIR = $(BUILD_DIR)/obj

# --- 目标文件 ---
TARGET = $(BUILD_DIR)/v3_core$(EXE_EXT)

# --- 编译标志 ---
CFLAGS_COMMON = -Wall -Wextra -Werror -std=c11 -I$(INC_DIR) -I.

# Release 优化
CFLAGS_RELEASE = $(CFLAGS_COMMON) -O3 -DNDEBUG -flto \
                 -fomit-frame-pointer -march=x86-64

# Debug 配置
CFLAGS_DEBUG = $(CFLAGS_COMMON) -O0 -g3 -DV3_DEBUG=1 \
               -fsanitize=address -fno-omit-frame-pointer

# Windows 特定标志
CFLAGS_WIN = -D_WIN32_WINNT=0x0601 -DWIN32_LEAN_AND_MEAN \
             -D_CRT_SECURE_NO_WARNINGS -DUNICODE -D_UNICODE

# 链接标志
LDFLAGS_COMMON = -static-libgcc -static-libstdc++
LDFLAGS_RELEASE = $(LDFLAGS_COMMON) -s -flto
LDFLAGS_DEBUG = $(LDFLAGS_COMMON) -g

# Windows 系统库
LIBS = -lws2_32 -ladvapi32 -lkernel32 -luser32 -lbcrypt -lntdll

# --- 源文件列表 ---
SRCS = $(SRC_DIR)/v3_entry.c \
       $(SRC_DIR)/v3_exit.c \
       $(SRC_DIR)/v3_lifecycle.c \
       $(SRC_DIR)/v3_ipc.c \
       $(SRC_DIR)/v3_config.c \
       $(SRC_DIR)/v3_guard.c \
       $(SRC_DIR)/win_platform.c \
       $(SRC_DIR)/win_pipe.c \
       $(SRC_DIR)/win_process.c \
       $(SRC_DIR)/win_memory.c

# 协议实现源文件
SRCS_PROTO = $(SRC_DIR)/v3_protocol.c \
             $(SRC_DIR)/v3_crypto.c \
             $(SRC_DIR)/v3_fec.c \
             $(SRC_DIR)/v3_pacing.c \
             $(SRC_DIR)/v3_connection.c

# 头文件列表（用于依赖）
HEADERS = $(INC_DIR)/v3_core.h \
          $(INC_DIR)/v3_ipc.h \
          $(INC_DIR)/v3_config.h \
          $(INC_DIR)/v3_lifecycle.h \
          $(INC_DIR)/v3_platform.h \
          $(INC_DIR)/v3_guard.h \
          version.h

# 对象文件
OBJS = $(patsubst $(SRC_DIR)/%.c,$(OBJ_DIR)/%.o,$(SRCS))
OBJS_PROTO = $(patsubst $(SRC_DIR)/%.c,$(OBJ_DIR)/%.o,$(SRCS_PROTO))
ALL_OBJS = $(OBJS) $(OBJS_PROTO)

# 资源文件（可选）
RES_SRC = res/v3_core.rc
RES_OBJ = $(OBJ_DIR)/v3_core_res.o

# --- 默认目标 ---
.PHONY: all clean release debug dirs help install test

all: release

# --- Release 构建 ---
release: CFLAGS = $(CFLAGS_RELEASE) $(CFLAGS_WIN)
release: LDFLAGS = $(LDFLAGS_RELEASE)
release: dirs $(TARGET)
	@echo "═══════════════════════════════════════════════════════════════"
	@echo "  v3 Core (Release) built successfully!"
	@echo "  Output: $(TARGET)"
	@echo "═══════════════════════════════════════════════════════════════"

# --- Debug 构建 ---
debug: CFLAGS = $(CFLAGS_DEBUG) $(CFLAGS_WIN)
debug: LDFLAGS = $(LDFLAGS_DEBUG)
debug: dirs $(TARGET)
	@echo "═══════════════════════════════════════════════════════════════"
	@echo "  v3 Core (Debug) built successfully!"
	@echo "═══════════════════════════════════════════════════════════════"

# --- 创建目录 ---
dirs:
ifeq ($(OS),Windows_NT)
	@if not exist $(BUILD_DIR) $(MKDIR) $(BUILD_DIR)
	@if not exist $(OBJ_DIR) $(MKDIR) $(OBJ_DIR)
else
	@$(MKDIR) $(BUILD_DIR)
	@$(MKDIR) $(OBJ_DIR)
endif

# --- 链接目标 ---
$(TARGET): $(ALL_OBJS)
	@echo "[LINK] $@"
	$(CC) $(LDFLAGS) -o $@ $^ $(LIBS)

# --- 编译规则 ---
$(OBJ_DIR)/%.o: $(SRC_DIR)/%.c $(HEADERS)
	@echo "[CC] $<"
	$(CC) $(CFLAGS) -c $< -o $@

# --- 资源文件编译 ---
$(RES_OBJ): $(RES_SRC)
	@echo "[RES] $<"
	$(WINDRES) $< -o $@

# --- 清理 ---
clean:
ifeq ($(OS),Windows_NT)
	@if exist $(BUILD_DIR) rmdir /S /Q $(BUILD_DIR)
else
	$(RM) -r $(BUILD_DIR)
endif
	@echo "Clean complete."

# --- 安装 ---
install: release
ifeq ($(OS),Windows_NT)
	@echo "Installing to C:\Program Files\v3..."
	@if not exist "C:\Program Files\v3" mkdir "C:\Program Files\v3"
	@copy $(TARGET) "C:\Program Files\v3\"
else
	@echo "Use 'make install' on Windows"
endif

# --- 测试 ---
test: release
	@echo "Running tests..."
	$(TARGET) --test

# --- 帮助 ---
help:
	@echo ""
	@echo "╔═════════════════════════════════════════════════════════════════╗"
	@echo "║                  v3 Core Windows Makefile                       ║"
	@echo "╚═════════════════════════════════════════════════════════════════╝"
	@echo ""
	@echo "Usage: make [target]"
	@echo ""
	@echo "Targets:"
	@echo "  all       Build release version (default)"
	@echo "  release   Build optimized release binary"
	@echo "  debug     Build debug binary with symbols"
	@echo "  clean     Remove build artifacts"
	@echo "  install   Install to system directory"
	@echo "  test      Run unit tests"
	@echo "  help      Show this help"
	@echo ""
	@echo "Cross-compile from Linux:"
	@echo "  make CC=x86_64-w64-mingw32-gcc release"
	@echo ""

# --- 依赖追踪 ---
-include $(ALL_OBJS:.o=.d)

$(OBJ_DIR)/%.d: $(SRC_DIR)/%.c
	@$(CC) $(CFLAGS) -MM -MT '$(@:.d=.o)' $< -o $@



