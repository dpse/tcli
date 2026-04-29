cmake_minimum_required(VERSION 3.22)
project(tcli C)

option(TCLI_BUILD_EXAMPLES "Build TinyCLI examples" ${PROJECT_IS_TOP_LEVEL})
option(TCLI_BUILD_TESTS "Build TinyCLI unit tests" ${PROJECT_IS_TOP_LEVEL})
option(TCLI_BUILD_FUZZERS "Build TinyCLI libFuzzer harnesses (Clang only)" OFF)
option(TCLI_WERROR "Treat compiler warnings as errors" OFF)

add_library(tcli STATIC source/tcli.c source/tclie.c)
add_library(tcli::tcli ALIAS tcli)

target_include_directories(tcli PUBLIC include)
target_compile_features(tcli PUBLIC c_std_11)

if(CMAKE_C_COMPILER_ID MATCHES "GNU|Clang")
    target_compile_options(tcli PRIVATE
        -Wall
        -Wextra
        -Wpedantic
        -Wshadow
        -Wundef
        -Wformat=2
        -Wstrict-prototypes
        -Wmissing-prototypes
        -Wcast-qual
        -Wimplicit-fallthrough
        -Wnull-dereference
    )
    if(TCLI_WERROR)
        target_compile_options(tcli PRIVATE -Werror)
    endif()
endif()

if(TCLI_BUILD_EXAMPLES)
    add_executable(example_linux examples/linux/main.c)
    target_link_libraries(example_linux PRIVATE tcli::tcli)
endif()

if(TCLI_BUILD_TESTS)
    enable_testing()
    add_subdirectory(tests)
endif()

if(TCLI_BUILD_FUZZERS)
    add_subdirectory(fuzz)
endif()
