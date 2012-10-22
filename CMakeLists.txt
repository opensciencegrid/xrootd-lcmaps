
cmake_minimum_required( VERSION 2.6 )
project( xrootd-lcmaps )

set( CMAKE_MODULE_PATH ${PROJECT_SOURCE_DIR}/cmake )

find_package( Xrootd REQUIRED )
find_package( Lcmaps REQUIRED )

if( CMAKE_COMPILER_IS_GNUCXX )
  set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wall -Werror -DLCMAPS_GSI_MODE=1" )
endif()

if( CMAKE_COMPILER_IS_GNUCC )
  set(CMAKE_CXX_FLAGS "${CMAKE_C_FLAGS} -Wall -Werror -DLCMAPS_GSI_MODE=1" )
endif()

include_directories( "${PROJECT_SOURCE_DIR}" "${XROOTD_INCLUDES}"
"${LCMAPS_INCLUDES}" )

add_library(XrdLcmaps MODULE src/XrdLcmaps.cc)
target_link_libraries(XrdLcmaps ${XROOTD_SECGSI} ${XROOTD_CRYPTOSSL}
${LCMAPS_LIB} ${DL_LIB})

