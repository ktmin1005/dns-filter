cmake_minimum_required(VERSION 3.16)
project(dnsfilter CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# Default to a Debug build unless told otherwise:
#   Development:  cmake -B build
#   Deployment:   cmake -B build-release -DCMAKE_BUILD_TYPE=Release
if(NOT CMAKE_BUILD_TYPE)
  set(CMAKE_BUILD_TYPE Debug)
endif()

add_compile_options(-Wall -Wextra)

# Debug: debug symbols + UndefinedBehaviorSanitizer to catch bugs early.
add_compile_options("$<$<CONFIG:Debug>:-g;-fsanitize=undefined>")
add_link_options("$<$<CONFIG:Debug>:-fsanitize=undefined>")

# Release: optimization plus compiler/linker hardening. Each flag makes a
# memory-safety bug harder to turn into a working exploit:
#   _FORTIFY_SOURCE=3        bounds checks on memcpy, strcpy, printf, ...
#   -fstack-protector-strong canaries that detect stack buffer overflows
#   -fstack-clash-protection stops stack growth from jumping over guard pages
#   PIE                      the program loads at a random address (ASLR)
#   -z relro -z now          makes function-pointer tables read-only at startup
add_compile_options("$<$<CONFIG:Release>:-O2;-U_FORTIFY_SOURCE;-D_FORTIFY_SOURCE=3;-fstack-protector-strong;-fstack-clash-protection>")
add_link_options("$<$<CONFIG:Release>:-Wl,-z,relro,-z,now>")
include(CheckPIESupported)
check_pie_supported()
set(CMAKE_POSITION_INDEPENDENT_CODE ON)

# On ARM64 (the Pi): pointer authentication + branch target identification,
# hardware checks against return-address and jump hijacking.
if(CMAKE_SYSTEM_PROCESSOR MATCHES "aarch64|arm64")
  add_compile_options("$<$<CONFIG:Release>:-mbranch-protection=standard>")
endif()

find_package(Threads REQUIRED)
find_package(OpenSSL 3.0 REQUIRED)   # DNS over TLS

# Standalone DNS-over-TLS check: ./build/dot_probe
add_executable(dot_probe tools/dot_probe.cpp src/dot_client.cpp)
target_include_directories(dot_probe PRIVATE src)
target_link_libraries(dot_probe PRIVATE OpenSSL::SSL)

add_executable(dnsfilter
  src/main.cpp
  src/blocklist.cpp
  src/dns_parser.cpp
  src/access_control.cpp
)
target_link_libraries(dnsfilter PRIVATE Threads::Threads)
