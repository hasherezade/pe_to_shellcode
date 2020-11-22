cmake_minimum_required (VERSION 2.8)

project ( runshc_dll_runner )

set(CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE} /MT")

set (srcs
#put your sources here
)

add_executable ( ${PROJECT_NAME} ${hdrs} ${srcs} ${rsrc} main.cpp )

target_link_libraries ( ${PROJECT_NAME} )

INSTALL( TARGETS ${PROJECT_NAME} DESTINATION ${CMAKE_INSTALL_PREFIX} COMPONENT ${PROJECT_NAME} )
