cmake_minimum_required(VERSION 3.22)
project(tcli VERSION 1.0.0 LANGUAGES C)

option(TCLI_BUILD_EXAMPLES "Build TinyCLI examples" ${PROJECT_IS_TOP_LEVEL})
option(TCLI_BUILD_TESTS "Build TinyCLI unit tests" ${PROJECT_IS_TOP_LEVEL})
option(TCLI_BUILD_FUZZERS "Build TinyCLI libFuzzer harnesses (Clang only)" OFF)
option(TCLI_WERROR "Treat compiler warnings as errors" OFF)
set(TCLI_CONFIG_DEFINITIONS "" CACHE STRING
    "Compile-time configuration passed to the library, its tests and examples \
(e.g. TCLIE_ENABLE_USERS=0;TCLI_COMPLETE=0)")

add_library(tcli STATIC source/tcli.c source/tclie.c)
add_library(tcli::tcli ALIAS tcli)

target_include_directories(tcli PUBLIC include)
target_compile_features(tcli PUBLIC c_std_11)

# PUBLIC: everything built against the library has to agree with it, since the
# configuration changes the layout of the public types.
if(TCLI_CONFIG_DEFINITIONS)
    target_compile_definitions(tcli PUBLIC ${TCLI_CONFIG_DEFINITIONS})
endif()

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
    if(WIN32)
        add_executable(example_windows examples/windows/main.c)
        target_link_libraries(example_windows PRIVATE tcli::tcli)
    elseif(UNIX)
        add_executable(example_linux examples/linux/main.c)
        target_link_libraries(example_linux PRIVATE tcli::tcli)
    endif()
endif()

if(TCLI_BUILD_TESTS)
    enable_testing()
    add_subdirectory(tests)
endif()

if(TCLI_BUILD_FUZZERS)
    add_subdirectory(fuzz)
endif()
