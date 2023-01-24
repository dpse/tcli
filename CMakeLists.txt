cmake_minimum_required(VERSION 3.22)
set(CMAKE_C_STANDARD 23)
project(tcli C)
add_definitions(-Wall)

include_directories(include)
add_library(tcli source/tcli.c source/tclie.c)

add_executable(example_linux examples/linux.c)
target_link_libraries(example_linux tcli)
