# CMakeList.txt : Top-level CMake project file, do global configuration
# and include sub-projects here.
#
cmake_minimum_required (VERSION 3.8)

project ("RSAExtension" VERSION 1.0.0 DESCRIPTION "A cryptopp RSA proxy for GMS2")

# specify the C++ standard
set(CMAKE_CXX_STANDARD 11)
set(CMAKE_CXX_STANDARD_REQUIRED True)
cmake_policy(SET CMP0079 NEW)

include(${CMAKE_CURRENT_LIST_DIR}/cmake/CPM.cmake)
set(CRYPTOPP_INCLUDE_PREFIX "cryptopp")
cpmaddpackage(
  NAME
  cryptopp-cmake
  GIT_REPOSITORY
  https://github.com./abdes/cryptopp-cmake
  GIT_TAG
  master
  OPTIONS
  "CRYPTOPP_BUILD_TESTING OFF"
  "CRYPTOPP_INSTALL ON")

# find_package(CryptoPP REQUIRED)
# target_link_libraries(CryptoExtension, CryptoPP)

# Include sub-projects.
add_subdirectory ("RSAExtension")

target_link_libraries(RSAExtension PUBLIC cryptopp::cryptopp)
target_compile_features(RSAExtension PRIVATE cxx_constexpr)