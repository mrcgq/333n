
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
option(V3_BUILD_TESTS    "Build unit tests"           OFF)
option(V3_ENABLE_FEC     "Enable FEC support"         ON)
option(V3_ENABLE_PACING  "Enable pacing support"      ON)
option(V3_ENABLE_GUARD   "Enable guard process"       ON)
option(V3_STATIC_LINK    "Static link runtime"        ON)
option(V3_USE_SIMD       "Enable SIMD optimizations"  ON)

# =========================================================================
# 编译器检测与配置
# =========================================================================
set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)

# Windows 平台检查
if(NOT WIN32)
    message(FATAL_ERROR "v3_core is Windows-only. Use cross-compiler for other platforms.")
endif()

# 设置输出目录
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)

# =========================================================================
# 版本信息
# =========================================================================
configure_file(
    "${CMAKE_SOURCE_DIR}/version.h.in"
    "${CMAKE_BINARY_DIR}/generated/version_gen.h"
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
)

# 协议实现（与服务端对应）
set(V3_PROTO_SOURCES
    src/v3_protocol.c
    src/v3_crypto.c
    src/v3_fec.c
    src/v3_pacing.c
    src/v3_connection.c
)

# 头文件
set(V3_HEADERS
    include/v3_core.h
    include/v3_ipc.h
    include/v3_config.h
    include/v3_lifecycle.h
    include/v3_platform.h
    include/v3_guard.h
    version.h
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

if(V3_ENABLE_FEC)
    list(APPEND V3_COMPILE_DEFINITIONS V3_FEATURE_FEC=1)
endif()

if(V3_ENABLE_PACING)
    list(APPEND V3_COMPILE_DEFINITIONS V3_FEATURE_PACING=1)
endif()

if(V3_ENABLE_GUARD)
    list(APPEND V3_COMPILE_DEFINITIONS V3_FEATURE_GUARD=1)
endif()

# =========================================================================
# 编译器标志
# =========================================================================
if(MSVC)
    # Visual Studio
    set(V3_COMPILE_OPTIONS
        /W4         # 高警告级别
        /WX         # 警告视为错误
        /utf-8      # UTF-8 源文件
        /MP         # 多处理器编译
        /Gy         # 函数级链接
        /GS         # 安全检查
    )
    
    set(V3_COMPILE_OPTIONS_RELEASE
        /O2         # 最大速度优化
        /GL         # 全程序优化
        /DNDEBUG
    )
    
    set(V3_COMPILE_OPTIONS_DEBUG
        /Od         # 禁用优化
        /Zi         # 调试信息
        /RTC1       # 运行时检查
    )
    
    set(V3_LINK_OPTIONS_RELEASE
        /LTCG       # 链接时代码生成
        /OPT:REF    # 删除未引用函数
        /OPT:ICF    # 相同 COMDAT 折叠
    )
    
    if(V3_STATIC_LINK)
        set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")
    endif()
    
else()
    # MinGW / GCC / Clang
    set(V3_COMPILE_OPTIONS
        -Wall
        -Wextra
        -Werror
        -Wpedantic
        -Wno-unused-parameter
    )
    
    set(V3_COMPILE_OPTIONS_RELEASE
        -O3
        -DNDEBUG
        -flto
        -fomit-frame-pointer
    )
    
    set(V3_COMPILE_OPTIONS_DEBUG
        -O0
        -g3
        -DV3_DEBUG=1
    )
    
    if(V3_USE_SIMD)
        list(APPEND V3_COMPILE_OPTIONS_RELEASE -march=x86-64 -mtune=generic)
    endif()
    
    if(V3_STATIC_LINK)
        set(V3_LINK_OPTIONS
            -static-libgcc
            -static-libstdc++
            -static
        )
    endif()
endif()

# =========================================================================
# Windows 系统库
# =========================================================================
set(V3_WINDOWS_LIBS
    ws2_32      # Winsock
    advapi32    # 注册表/服务
    kernel32    # 核心 API
    user32      # 用户界面
    bcrypt      # 加密 API
    ntdll       # NT 原生 API
)

# =========================================================================
# 主程序目标
# =========================================================================
add_executable(v3_core WIN32
    ${V3_CORE_SOURCES}
    ${V3_PROTO_SOURCES}
    ${V3_HEADERS}
)

# 包含目录
target_include_directories(v3_core PRIVATE
    ${CMAKE_SOURCE_DIR}/include
    ${CMAKE_SOURCE_DIR}
    ${CMAKE_BINARY_DIR}/generated
)

# 编译定义
target_compile_definitions(v3_core PRIVATE
    ${V3_COMPILE_DEFINITIONS}
)

# 编译选项
target_compile_options(v3_core PRIVATE
    ${V3_COMPILE_OPTIONS}
    $<$<CONFIG:Release>:${V3_COMPILE_OPTIONS_RELEASE}>
    $<$<CONFIG:Debug>:${V3_COMPILE_OPTIONS_DEBUG}>
)

# 链接选项
if(MSVC)
    target_link_options(v3_core PRIVATE
        $<$<CONFIG:Release>:${V3_LINK_OPTIONS_RELEASE}>
    )
else()
    target_link_options(v3_core PRIVATE
        ${V3_LINK_OPTIONS}
    )
endif()

# 链接库
target_link_libraries(v3_core PRIVATE
    ${V3_WINDOWS_LIBS}
)

# 设置属性
set_target_properties(v3_core PROPERTIES
    OUTPUT_NAME "v3_core"
    RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin"
    VS_DEBUGGER_WORKING_DIRECTORY "${CMAKE_SOURCE_DIR}"
)

# =========================================================================
# 测试目标（可选）
# =========================================================================
if(V3_BUILD_TESTS)
    enable_testing()
    
    add_executable(v3_test
        test/test_main.c
        test/test_crypto.c
        test/test_fec.c
        test/test_protocol.c
        ${V3_PROTO_SOURCES}
    )
    
    target_include_directories(v3_test PRIVATE
        ${CMAKE_SOURCE_DIR}/include
        ${CMAKE_SOURCE_DIR}
    )
    
    target_compile_definitions(v3_test PRIVATE
        ${V3_COMPILE_DEFINITIONS}
        V3_TESTING=1
    )
    
    target_link_libraries(v3_test PRIVATE
        ${V3_WINDOWS_LIBS}
    )
    
    add_test(NAME v3_core_tests COMMAND v3_test)
endif()

# =========================================================================
# 安装规则
# =========================================================================
install(TARGETS v3_core
    RUNTIME DESTINATION bin
)

install(FILES
    ${CMAKE_SOURCE_DIR}/README.md
    ${CMAKE_SOURCE_DIR}/LICENSE
    DESTINATION .
    OPTIONAL
)

# =========================================================================
# 打包配置（CPack）
# =========================================================================
set(CPACK_GENERATOR "ZIP")
set(CPACK_PACKAGE_NAME "v3_core")
set(CPACK_PACKAGE_VERSION ${PROJECT_VERSION})
set(CPACK_PACKAGE_VENDOR "v3 Project")
set(CPACK_PACKAGE_DESCRIPTION_SUMMARY "v3 Protocol Windows Core")
set(CPACK_RESOURCE_FILE_LICENSE "${CMAKE_SOURCE_DIR}/LICENSE")

include(CPack)

# =========================================================================
# 打印配置摘要
# =========================================================================
message(STATUS "")
message(STATUS "╔═══════════════════════════════════════════════════════════════╗")
message(STATUS "║                v3 Core Build Configuration                    ║")
message(STATUS "╠═══════════════════════════════════════════════════════════════╣")
message(STATUS "║  Version:     ${PROJECT_VERSION}")
message(STATUS "║  Platform:    ${CMAKE_SYSTEM_NAME} ${CMAKE_SYSTEM_PROCESSOR}")
message(STATUS "║  Compiler:    ${CMAKE_C_COMPILER_ID} ${CMAKE_C_COMPILER_VERSION}")
message(STATUS "║  Build Type:  ${CMAKE_BUILD_TYPE}")
message(STATUS "╠═══════════════════════════════════════════════════════════════╣")
message(STATUS "║  Features:")
message(STATUS "║    FEC:       ${V3_ENABLE_FEC}")
message(STATUS "║    Pacing:    ${V3_ENABLE_PACING}")
message(STATUS "║    Guard:     ${V3_ENABLE_GUARD}")
message(STATUS "║    SIMD:      ${V3_USE_SIMD}")
message(STATUS "║    Static:    ${V3_STATIC_LINK}")
message(STATUS "║    Tests:     ${V3_BUILD_TESTS}")
message(STATUS "╚═══════════════════════════════════════════════════════════════╝")
message(STATUS "")





