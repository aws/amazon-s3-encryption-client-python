cmake_minimum_required(VERSION 3.16)
project(s3ec-cpp-server)

set(CMAKE_CXX_STANDARD 17)

# Configure AWS SDK build options
set(BUILD_ONLY "kms;s3;s3-encryption" CACHE STRING "Build only KMS, S3, and S3-encryption components")
set(ENABLE_TESTING OFF CACHE BOOL "Disable testing")
set(BUILD_SHARED_LIBS OFF CACHE BOOL "Build static libraries")

# Add AWS SDK as subdirectory
add_subdirectory(aws-sdk-cpp)

find_package(PkgConfig REQUIRED)
pkg_check_modules(LIBMICROHTTPD REQUIRED libmicrohttpd)

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
    aws-cpp-sdk-core
    aws-cpp-sdk-kms
    aws-cpp-sdk-s3
    aws-cpp-sdk-s3-encryption
    nlohmann_json::nlohmann_json
    uuid
)