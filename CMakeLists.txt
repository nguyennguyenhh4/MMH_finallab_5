cmake_minimum_required(VERSION 3.16)
project(Lab5_Digital_Signatures CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

if(NOT CMAKE_BUILD_TYPE)
  set(CMAKE_BUILD_TYPE Release CACHE STRING "Build type" FORCE)
endif()

# ─── Find OpenSSL ──────────────────────────────────────────────
find_package(OpenSSL QUIET)

if(NOT OPENSSL_FOUND)
  find_library(OPENSSL_SSL_LIB
    NAMES ssl libssl
    PATHS
      "D:/CryptoLibs/openssl321/lib"
      "C:/msys64/mingw64/lib"
      /usr/lib /usr/local/lib
      /usr/lib/x86_64-linux-gnu
  )
  
  find_library(OPENSSL_CRYPTO_LIB
    NAMES crypto libcrypto
    PATHS
      "D:/CryptoLibs/openssl321/lib"
      "C:/msys64/mingw64/lib"
      /usr/lib /usr/local/lib
      /usr/lib/x86_64-linux-gnu
  )
  
  find_path(OPENSSL_INCLUDE
    NAMES openssl/evp.h
    PATHS
      "D:/CryptoLibs/openssl321/include"
      "C:/msys64/mingw64/include"
      /usr/include
      /usr/local/include
  )
  
  if(NOT OPENSSL_SSL_LIB OR NOT OPENSSL_CRYPTO_LIB OR NOT OPENSSL_INCLUDE)
    message(FATAL_ERROR
      "OpenSSL not found.\n"
      "  Linux  : sudo apt install libssl-dev\n"
      "  Windows: pacman -S mingw-w64-x86_64-openssl\n")
  endif()
  
  if(NOT TARGET OpenSSL::SSL)
    add_library(OpenSSL::SSL UNKNOWN IMPORTED)
    set_target_properties(OpenSSL::SSL PROPERTIES
      IMPORTED_LOCATION "${OPENSSL_SSL_LIB}"
      INTERFACE_INCLUDE_DIRECTORIES "${OPENSSL_INCLUDE}"
    )
  endif()
  
  if(NOT TARGET OpenSSL::Crypto)
    add_library(OpenSSL::Crypto UNKNOWN IMPORTED)
    set_target_properties(OpenSSL::Crypto PROPERTIES
      IMPORTED_LOCATION "${OPENSSL_CRYPTO_LIB}"
      INTERFACE_INCLUDE_DIRECTORIES "${OPENSSL_INCLUDE}"
    )
  endif()
endif()

# ─── Catch2 for Unit Testing ───────────────────────────────────
include(FetchContent)
FetchContent_Declare(
  Catch2
  GIT_REPOSITORY https://github.com/catchorg/Catch2.git
  GIT_TAG        v2.13.10
)
FetchContent_MakeAvailable(Catch2)
enable_testing()

# ─── sigtool (CLI) ─────────────────────────────────────────────
add_executable(sigtool digital_signatures.cpp)
target_link_libraries(sigtool PRIVATE OpenSSL::SSL OpenSSL::Crypto)

if(MSVC)
  target_compile_options(sigtool PRIVATE /W3 /O2)
else()
  target_compile_options(sigtool PRIVATE -Wall -O2)
endif()

# ─── test_signatures (Unit Tests) ──────────────────────────────
add_executable(unit_tests test_signatures.cpp digital_signatures.cpp)
target_compile_definitions(unit_tests PRIVATE LAB_CRYPTO_DLL_ONLY)
target_include_directories(unit_tests PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
target_link_libraries(unit_tests PRIVATE Catch2::Catch2 OpenSSL::SSL OpenSSL::Crypto)
add_test(NAME AllUnitTests COMMAND unit_tests)

if(MSVC)
  target_compile_options(unit_tests PRIVATE /W3 /O2)
else()
  target_compile_options(unit_tests PRIVATE -Wall -O2)
endif()

# ─── bench_signatures (Benchmark) ──────────────────────────────
add_executable(bench bench.cpp digital_signatures.cpp)
target_compile_definitions(bench PRIVATE LAB_CRYPTO_DLL_ONLY)
target_link_libraries(bench PRIVATE OpenSSL::SSL OpenSSL::Crypto)

if(MSVC)
  target_compile_options(bench PRIVATE /W3 /O2)
else()
  target_compile_options(bench PRIVATE -Wall -O3)
endif()

install(TARGETS sigtool unit_tests bench DESTINATION bin)

message(STATUS "Build type  : ${CMAKE_BUILD_TYPE}")
message(STATUS "C++ standard: C++${CMAKE_CXX_STANDARD}")
message(STATUS "Targets     : sigtool, unit_tests, bench")
