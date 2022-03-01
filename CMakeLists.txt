cmake_minimum_required(VERSION 3.16)
project(simplenet)
enable_testing()
set(CMAKE_CXX_STANDARD 17)

# OpenSSL
find_package(OpenSSL)
if(OpenSSL_FOUND)
    add_compile_definitions(KISSNET_USE_OPENSSL)
endif()

# Header search paths
include_directories(kissnet)
include_directories(${OPENSSL_INCLUDE_DIR})

# Include tests
add_subdirectory(tests)

# Build simple net application
add_executable(simplenet simplenet.cpp)
target_link_libraries(simplenet ${OPENSSL_LIBRARIES})
