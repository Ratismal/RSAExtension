# CMakeList.txt : CMake project for RSAExtension, include source and define
# project specific logic here.
#
cmake_minimum_required (VERSION 3.8)

# make cache variables for install destinations
include(GNUInstallDirs)

# Add source to this project's library.
add_library (RSAExtension SHARED "src/CryptoExtension.cpp" "api/CryptoExtension.h")

set_target_properties(RSAExtension PROPERTIES
    VERSION ${PROJECT_VERSION}
    SOVERSION 1
    PUBLIC_HEADER api/CryptoExtension.h)

target_include_directories(RSAExtension PRIVATE .)

include(GNUInstallDirs)

install(TARGETS RSAExtension
    LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
    PUBLIC_HEADER DESTINATION ${CMAKE_INSTALL_INCLUDEDIR})
