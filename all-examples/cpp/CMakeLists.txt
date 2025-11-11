cmake_minimum_required(VERSION 3.16)
project(s3ec-test)

set(CMAKE_CXX_STANDARD 14)

# Configure AWS SDK build options
set(BUILD_ONLY "kms;s3;s3-encryption" CACHE STRING "Build only KMS, S3, and S3-encryption components")
set(ENABLE_TESTING OFF CACHE BOOL "Disable testing")
set(BUILD_SHARED_LIBS OFF CACHE BOOL "Build static libraries")

# Add AWS SDK as subdirectory
add_subdirectory(aws-sdk-cpp)

find_package(PkgConfig REQUIRED)

add_executable(s3ec-test main.cpp)

target_link_libraries(s3ec-test
    aws-cpp-sdk-core
    aws-cpp-sdk-kms
    aws-cpp-sdk-s3
    aws-cpp-sdk-s3-encryption
)
