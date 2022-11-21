cmake_minimum_required ( VERSION 3.0 )
project (test_case2)

set(CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE} /MT")
include_directories ( include )

set (srcs
	main.cpp
)

set (hdrs
)

add_library ( ${PROJECT_NAME} SHARED ${hdrs} ${srcs} main.def)

#install
INSTALL( TARGETS ${PROJECT_NAME} DESTINATION ${CMAKE_INSTALL_PREFIX} COMPONENT ${PROJECT_NAME} )
