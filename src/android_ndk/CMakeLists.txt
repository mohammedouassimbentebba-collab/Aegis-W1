# ==============================================================================
# W1™ Aerospace Anti-Stealth Radar: Android NDK CMake Build Configuration
# File: src/android_ndk/CMakeLists.txt
# Target: Android NDK r25+ (arm64-v8a, armeabi-v7a, x86_64)
# ==============================================================================

cmake_minimum_required(VERSION 3.22.1)

project(w1_radar_neon CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Optimization and Vectorization Flags for ARM architectures
if (${ANDROID_ABI} STREQUAL "arm64-v8a")
    add_compile_options(-O3 -fvectorize -Wall -Wextra -D__ARM_NEON)
elseif (${ANDROID_ABI} STREQUAL "armeabi-v7a")
    add_compile_options(-O3 -mfpu=neon -mfloat-abi=softfp -Wall -Wextra -D__ARM_NEON)
else ()
    # Host / x86_64 emulator fallback
    add_compile_options(-O3 -Wall -Wextra)
endif ()

# Source files
set(SOURCE_FILES
    w1_radar_neon.cpp
    w1_jni_bridge.cpp
)

# Build shared library for Android JNI
add_library(w1_radar_neon SHARED ${SOURCE_FILES})

# Link Android standard logging and math libraries
find_library(log-lib log)
find_library(math-lib m)

target_link_libraries(w1_radar_neon
    ${log-lib}
    ${math-lib}
)

target_include_directories(w1_radar_neon PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${CMAKE_CURRENT_SOURCE_DIR}/../radar_machine_code/linux_kernel
)
