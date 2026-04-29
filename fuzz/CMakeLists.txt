if(NOT CMAKE_C_COMPILER_ID MATCHES "Clang")
    message(FATAL_ERROR "TCLI_BUILD_FUZZERS requires Clang.")
endif()

function(tcli_add_fuzzer name)
    add_executable(${name} ${name}.c)
    target_link_libraries(${name} PRIVATE tcli::tcli)
    target_compile_options(${name} PRIVATE -g -O1 -fsanitize=fuzzer,address,undefined)
    target_link_options(${name} PRIVATE -fsanitize=fuzzer,address,undefined)
endfunction()

tcli_add_fuzzer(fuzz_stateless)
tcli_add_fuzzer(fuzz_stateful)
