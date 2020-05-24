cmake_minimum_required(VERSION 2.8)

project(aes128_192_256_ECB_CBC_CFB)

enable_testing()
find_package(GTest REQUIRED)
include_directories(${GTEST_INCLUDE_DIR})


add_executable(tests
    AES.cpp
    tests.cpp
    )

target_link_libraries(tests ${GTEST_LIBRARIES} pthread)