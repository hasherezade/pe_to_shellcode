cmake_minimum_required (VERSION 2.8)

project ( runshc_dll )

add_definitions(-DUNICODE -D_UNICODE)
set(CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE} /MT")

# include libpeconv headers:
include_directories ( ${PECONV_DIR}/include )

set (srcs
#put your sources here
)

add_library ( ${PROJECT_NAME} SHARED ${hdrs} ${srcs} ${rsrc} main.cpp main.def )

# link with libpeconv.lib
target_link_libraries ( ${PROJECT_NAME} ${PECONV_LIB} )

#dependencies:
add_dependencies( ${PROJECT_NAME} libpeconv )

INSTALL( TARGETS ${PROJECT_NAME} DESTINATION ${CMAKE_INSTALL_PREFIX} COMPONENT ${PROJECT_NAME} )
