cmake_minimum_required(VERSION 3.10)
project(fix_kaslr_arm64 C)

set(CMAKE_C_STANDARD 99)
set(CMAKE_C_STANDARD_REQUIRED ON)

add_executable(fix_kaslr_arm64 fix_kaslr_arm64_win32.c)

if(MSVC)
    target_compile_options(fix_kaslr_arm64 PRIVATE /W3)
else()
    target_compile_options(fix_kaslr_arm64 PRIVATE -O2 -Wall)
endif()
