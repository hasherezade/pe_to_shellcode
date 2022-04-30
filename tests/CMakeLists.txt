cmake_minimum_required (VERSION 3.0)
project (tests)

set(CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE} /MT")

#add the application that will be used for tests:
add_subdirectory ( test_case1 )
add_subdirectory ( dcp_test )

enable_testing()

#WARNING: in order for tests to work, all the binaries must be installed by: cmake --build . --target install

# 0) does pe2shc run
add_test(RunPe2Shc "${CMAKE_INSTALL_PREFIX}//pe2shc.exe" "${CMAKE_INSTALL_PREFIX}//pe2shc.exe" "${CMAKE_INSTALL_PREFIX}//demo.shc.exe")
set_tests_properties(RunPe2Shc PROPERTIES DEPENDS pe2shc)

# 1) does runshc run
add_test(RunRunShc "${CMAKE_INSTALL_PREFIX}//runshc.exe" "${CMAKE_INSTALL_PREFIX}//demo.shc.exe")
set_tests_properties(RunRunShc PROPERTIES PASS_REGULAR_EXPRESSION "Running the shellcode:")
set_tests_properties(RunPe2Shc PROPERTIES DEPENDS pe2shc)
set_tests_properties(RunPe2Shc PROPERTIES DEPENDS runshc)

# 2) does conversion of the test application work
add_test(ConvTestCase1 "${CMAKE_INSTALL_PREFIX}//pe2shc.exe" "${CMAKE_INSTALL_PREFIX}//test_case1.exe" "${CMAKE_INSTALL_PREFIX}//test_case1.shc.exe")
set_tests_properties(ConvTestCase1 PROPERTIES PASS_REGULAR_EXPRESSION "Saved as:")

# 3) does converted application run properly
add_test(RunTestCase1 "${CMAKE_INSTALL_PREFIX}//runshc.exe" "${CMAKE_INSTALL_PREFIX}//test_case1.shc.exe")
set_tests_properties(RunTestCase1 PROPERTIES DEPENDS test_case1)
set_tests_properties(RunTestCase1 PROPERTIES PASS_REGULAR_EXPRESSION "Test passed!")
