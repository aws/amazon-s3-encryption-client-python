cmake_minimum_required(VERSION 3.16)
project(s3ec-cpp-server)

set(CMAKE_CXX_STANDARD 17)

find_package(PkgConfig REQUIRED)
pkg_check_modules(LIBMICROHTTPD REQUIRED libmicrohttpd)

find_package(AWSSDK REQUIRED COMPONENTS s3 s3-encryption kms)
find_package(nlohmann_json REQUIRED)

add_executable(s3ec-server main.cpp)

target_include_directories(s3ec-server PRIVATE 
    ${LIBMICROHTTPD_INCLUDE_DIRS}
    /opt/homebrew/include
)

target_link_directories(s3ec-server PRIVATE 
    ${LIBMICROHTTPD_LIBRARY_DIRS}
    /opt/homebrew/lib
)

target_link_libraries(s3ec-server 
    ${LIBMICROHTTPD_LIBRARIES}
    ${AWSSDK_LINK_LIBRARIES}
    nlohmann_json::nlohmann_json
    uuid
)