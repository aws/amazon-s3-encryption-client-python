cmake_minimum_required(VERSION 3.16)
project(s3ec-cpp-v3-example)

set(CMAKE_CXX_STANDARD 17)

# Find AWS SDK for C++
# Note: S3 Encryption Client is not part of standard AWS SDK
# This example demonstrates the concept but requires the full S3EC library
find_package(AWSSDK REQUIRED COMPONENTS core kms)

add_executable(s3ec-example main.cpp)

target_link_libraries(s3ec-example 
    ${AWSSDK_LINK_LIBRARIES}
)

# Add include directories for AWS SDK
target_include_directories(s3ec-example PRIVATE ${AWSSDK_INCLUDE_DIRS})

# Set compiler flags
target_compile_features(s3ec-example PRIVATE cxx_std_17)
