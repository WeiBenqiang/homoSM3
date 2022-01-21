cmake_minimum_required(VERSION 3.10)

project(TFHE_SM3)

add_executable(testSM3 SM3test.c SM3.c)

add_executable(homoSM3 homoSM3.cpp SM3.c)

target_link_libraries(homoSM3 tfhe-spqlios-fma)