cmake_minimum_required(VERSION 3.16)
project(simplenet)

set(CMAKE_CXX_STANDARD 17)

include_directories(kissnet)

add_executable(simplenet
        simplenet.cpp)
