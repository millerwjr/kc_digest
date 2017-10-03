cmake_minimum_required(VERSION 3.6)
project(kc_digest)

set(CMAKE_CXX_STANDARD 11)

set(SOURCE_FILES main.cpp kc_digest.h kc_digest.cpp)
add_executable(kc_digest ${SOURCE_FILES})