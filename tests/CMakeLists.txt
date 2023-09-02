set(TESTS cbc_tests cfb_tests context_tests ecb_tests ofb_tests)

add_test(NAME build_tests
        COMMAND "${CMAKE_COMMAND}" --build "${CMAKE_BINARY_DIR}" --config "$<CONFIG>" --target ${TESTS})
set_tests_properties(build_tests PROPERTIES FIXTURES_SETUP build_tests)

foreach (test ${TESTS})
    add_test(NAME ${test} COMMAND ${test})
    add_executable(${test} "${test}.c" test-lib.c test-lib.h)
    target_link_libraries(${test} blowfish-static)
    target_include_directories(${test} PRIVATE "${CMAKE_SOURCE_DIR}/src")
    set_tests_properties(${test} PROPERTIES FIXTURES_REQUIRED build_tests)
endforeach (test)
