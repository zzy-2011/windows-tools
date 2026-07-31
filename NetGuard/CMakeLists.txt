cmake_minimum_required(VERSION 3.10)
project(NetGuard VERSION 2.0 LANGUAGES CXX RC)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

add_executable(NetGuard WIN32 main.cpp netguard.rc)

target_link_libraries(NetGuard
    iphlpapi
    psapi
    ws2_32
    winhttp
    comctl32
)

# 复制黑名单和 manifest 到构建目录
configure_file(${CMAKE_SOURCE_DIR}/blacklist.txt ${CMAKE_BINARY_DIR}/blacklist.txt COPYONLY)
configure_file(${CMAKE_SOURCE_DIR}/netguard.manifest ${CMAKE_BINARY_DIR}/netguard.manifest COPYONLY)
