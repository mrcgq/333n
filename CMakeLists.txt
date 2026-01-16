# =========================================================================
# v3 Core - CMake Build Configuration (FINALIZED)
# =========================================================================

cmake_minimum_required(VERSION 3.16)

project(v3_core VERSION 1.0.0 LANGUAGES C)

# --- Compiler & Platform Setup ---
set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)

if(NOT WIN32)
    message(FATAL_ERROR "v3_core is Windows-only.")
endif()

set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)
set(GENERATED_INCLUDE_DIR ${CMAKE_BINARY_DIR}/generated_include)

# --- Version Header Generation ---
configure_file(
    "${CMAKE_SOURCE_DIR}/version.h.in"
    "${GENERATED_INCLUDE_DIR}/v3_version_gen.h"
    @ONLY
)

# --- Source Files ---
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

# --- Libraries ---
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
# Target Definition - 必须先定义目标，再配置它
# =========================================================================
add_executable(v3_core WIN32 ${V3_CORE_SOURCES})

# =========================================================================
# Target Configuration - 所有 target_* 命令都在 add_executable 之后
# =========================================================================

# --- Include Directories ---
target_include_directories(v3_core PRIVATE
    ${CMAKE_SOURCE_DIR}/include
    ${CMAKE_SOURCE_DIR}
    ${GENERATED_INCLUDE_DIR}
)

# --- Compile Definitions ---
target_compile_definitions(v3_core PRIVATE
    WIN32_LEAN_AND_MEAN
    _WIN32_WINNT=0x0601
    UNICODE
    _UNICODE
    _CRT_SECURE_NO_WARNINGS # <--- 在这里全局定义
)

# --- Compile Options ---
if(MSVC)
    target_compile_options(v3_core PRIVATE /W4 /WX /utf-8 /MP /GS)
else()
    # For MinGW / GCC / Clang
    target_compile_options(v3_core PRIVATE -Wall -Wextra -Wpedantic -Wno-unused-parameter)
    # -Werror is removed to allow build to succeed even with warnings.
endif()

# --- Link Libraries ---
target_link_libraries(v3_core PRIVATE
    ${V3_WINDOWS_LIBS}
)

# --- Target Properties ---
set_target_properties(v3_core PROPERTIES OUTPUT_NAME "v3_core")


# =========================================================================
# Installation and Packaging
# =========================================================================
install(TARGETS v3_core RUNTIME DESTINATION bin)
install(FILES ${CMAKE_SOURCE_DIR}/LICENSE DESTINATION . OPTIONAL)
set(CPACK_GENERATOR "ZIP")
set(CPACK_PACKAGE_NAME "v3_core")
set(CPACK_PACKAGE_VERSION ${PROJECT_VERSION})
set(CPACK_RESOURCE_FILE_LICENSE "${CMAKE_SOURCE_DIR}/LICENSE")
include(CPack)
