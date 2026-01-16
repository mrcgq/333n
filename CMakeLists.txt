# =========================================================================
# v3 Core - CMake Build Configuration
# 支持 Visual Studio / MinGW / Clang 等多种编译器
# =========================================================================

cmake_minimum_required(VERSION 3.16)

# 项目定义
project(v3_core
    VERSION 1.0.0
    DESCRIPTION "v3 Protocol Windows Core"
    LANGUAGES C
)

# =========================================================================
# 选项配置
# =========================================================================
option(V3_STATIC_LINK "Static link runtime" ON)

# =========================================================================
# 编译器检测与配置
# =========================================================================
set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)

if(NOT WIN32)
    message(FATAL_ERROR "v3_core is Windows-only. Use cross-compiler for other platforms.")
endif()

# 设置输出目录
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)
set(GENERATED_INCLUDE_DIR ${CMAKE_BINARY_DIR}/generated_include) # 定义生成头文件的目录

# =========================================================================
# 版本信息
# =========================================================================
configure_file(
    "${CMAKE_SOURCE_DIR}/version.h.in"
    "${GENERATED_INCLUDE_DIR}/v3_version_gen.h" # 将生成的文件放入新目录
    @ONLY
)

# =========================================================================
# 源文件定义
# =========================================================================
set(V3_CORE_SOURCES
    src/v3_entry.c
    src/v3_exit.c
    src/v3_lifecycle.c
    src/v3_ipc.c
    src/v3_config.c
    src/v3_guard.c
    src/win_platform.c
    src/win_pipe.c
    src/win_process.c
    src/win_memory.c
    src/v3_connection.c
    src/v3_crypto.c
    src/v3_protocol.c
    src/v3_fec.c
    src/v3_pacing.c
)

# =========================================================================
# 编译定义
# =========================================================================
set(V3_COMPILE_DEFINITIONS
    WIN32_LEAN_AND_MEAN
    _WIN32_WINNT=0x0601
    UNICODE
    _UNICODE
    _CRT_SECURE_NO_WARNINGS
)

# =========================================================================
# Windows 系统库
# =========================================================================
set(V3_WINDOWS_LIBS
    ws2_32
    advapi32
    kernel32
    user32
    bcrypt
    ntdll
    sodium
)

# =========================================================================
# 主程序目标
# =========================================================================
add_executable(v3_core WIN32
    ${V3_CORE_SOURCES}
)

# 包含目录
target_include_directories(v3_core PRIVATE
    ${CMAKE_SOURCE_DIR}/include
    ${CMAKE_SOURCE_DIR}
    ${GENERATED_INCLUDE_DIR} # 将生成头文件的目录添加到包含路径
)

# 编译定义
target_compile_definitions(v3_core PRIVATE
    ${V3_COMPILE_DEFINITIONS}
)

# 链接库
target_link_libraries(v3_core PRIVATE
    ${V3_WINDOWS_LIBS}
)

# 设置属性
set_target_properties(v3_core PROPERTIES
    OUTPUT_NAME "v3_core"
)

# =========================================================================
# 安装规则和打包
# =========================================================================
install(TARGETS v3_core RUNTIME DESTINATION bin)
install(FILES ${CMAKE_SOURCE_DIR}/LICENSE DESTINATION . OPTIONAL)
set(CPACK_GENERATOR "ZIP")
set(CPACK_PACKAGE_NAME "v3_core")
set(CPACK_PACKAGE_VERSION ${PROJECT_VERSION})
set(CPACK_RESOURCE_FILE_LICENSE "${CMAKE_SOURCE_DIR}/LICENSE")
include(CPack)
