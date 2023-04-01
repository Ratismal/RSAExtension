# CMakeList.txt : CMake project for CryptoExtension, include source and define
# project specific logic here.
#
cmake_minimum_required (VERSION 3.8)

# make cache variables for install destinations
include(GNUInstallDirs)

# set(CMAKE_SHARED_LINKER_FLAGS "-Wl,--export-all-symbols")

# Add source to this project's executable.
# add_executable (CryptoExtension "CryptoExtension.cpp" "CryptoExtension.h")

add_library (CryptoExtension SHARED "src/CryptoExtension.cpp" "api/CryptoExtension.h")

# set_target_properties(CryptoExtension PROPERTIES VERSION ${PROJECT_VERSION})

set_target_properties(CryptoExtension PROPERTIES
    VERSION ${PROJECT_VERSION}
    SOVERSION 1
    PUBLIC_HEADER api/CryptoExtension.h)

target_include_directories(CryptoExtension PRIVATE .)

include(GNUInstallDirs)

install(TARGETS CryptoExtension
    LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
    PUBLIC_HEADER DESTINATION ${CMAKE_INSTALL_INCLUDEDIR})

# TODO: Add tests and install targets if needed.
