cmake_minimum_required ( VERSION 3.0 )

project ( pe2shc )

set(CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE} /MT")

option(OLD_STUB "Build with the old stub" OFF)

# include libpeconv headers:
include_directories ( ${PECONV_DIR}/include )

set (srcs
#put your sources here
)

# general headers - they will be used for both EXE and DLL:
set (hdrs
	resource.h
)

if( OLD_STUB)
set (rsrc
	resource1.rc
)
else()
set (rsrc
	resource2.rc
)
endif()

add_executable ( ${PROJECT_NAME} ${hdrs} ${srcs} ${rsrc} main.cpp )

# link with libpeconv.lib
target_link_libraries ( ${PROJECT_NAME} ${PECONV_LIB} )

#dependencies:
add_dependencies( ${PROJECT_NAME} libpeconv )

INSTALL( TARGETS ${PROJECT_NAME} DESTINATION ${CMAKE_INSTALL_PREFIX} COMPONENT ${PROJECT_NAME} )
