cmake_minimum_required (VERSION 2.8)

project ( pe2shc )

set(CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE} /MT")

# include libpeconv headers:
include_directories ( ${PECONV_DIR}/include )

set (srcs
#put your sources here
)

# general headers - they will be used for both EXE and DLL:
set (hdrs
	resource.h
)

set (rsrc
	resource.rc
)

add_executable ( ${PROJECT_NAME} ${hdrs} ${srcs} ${rsrc} main.cpp )


# link with libpeconv.lib
target_link_libraries ( ${PROJECT_NAME} ${PECONV_LIB} )

#dependencies:
add_dependencies( ${PROJECT_NAME} libpeconv )

if(PE2SHC_BUILD_TESTING)
	INSTALL(TARGETS pe2shc DESTINATION ${CMAKE_BINARY_DIR} COMPONENT pe2shc)
endif()
