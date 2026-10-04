cmake_minimum_required(VERSION 3.26)
project(blrs_candidate LANGUAGES C CXX)
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

# The pinned LaZer backend currently requires Linux x86-64 with AVX512 and AES.
if(NOT CMAKE_SYSTEM_NAME STREQUAL "Linux" OR NOT CMAKE_SYSTEM_PROCESSOR MATCHES "x86_64|AMD64")
  message(FATAL_ERROR "Use the Linux x86-64 backend, including WSL on Windows. See README.md.")
endif()
find_package(OpenSSL REQUIRED COMPONENTS Crypto)
find_package(Threads REQUIRED)
find_path(GMP_INCLUDE_DIR gmpxx.h REQUIRED)
find_library(GMP_LIBRARY gmp REQUIRED)
find_library(GMPXX_LIBRARY gmpxx REQUIRED)
find_library(MPFR_LIBRARY mpfr REQUIRED)
set(LAZER_ROOT "${CMAKE_CURRENT_SOURCE_DIR}/vendor/lazer")
if(NOT EXISTS "${LAZER_ROOT}/liblazer.a")
  message(FATAL_ERROR "Build the pinned backend first with tools/build_lazer.py. See README.md.")
endif()
set(identity_sources src/candidate.cpp src/relation.cpp src/transcript.cpp src/sampler.cpp src/codec.cpp
  backend/backend.cpp backend/proof_params.h backend/lazer.patch
  include/blrs/candidate.hpp include/blrs/relation.hpp include/blrs/transcript.hpp include/blrs/codec.hpp
  include/blrs/random.hpp include/blrs/sampler.hpp backend/backend.hpp backend/blrs_callbacks.h)
set(identity_bytes "")
foreach(identity_source IN LISTS identity_sources)
  file(SHA256 "${CMAKE_CURRENT_SOURCE_DIR}/${identity_source}" identity_hash)
  string(APPEND identity_bytes "${identity_hash}")
  set_property(DIRECTORY APPEND PROPERTY CMAKE_CONFIGURE_DEPENDS "${identity_source}")
endforeach()
string(SHA256 BLRS_IMPLEMENTATION_DIGEST "${identity_bytes}")
configure_file(tools/build_identity.hpp.in generated/build_identity.hpp @ONLY)

add_library(blrs STATIC src/relation.cpp src/transcript.cpp src/sampler.cpp src/candidate.cpp src/codec.cpp backend/backend.cpp)
target_include_directories(blrs PUBLIC include backend ${GMP_INCLUDE_DIR})
target_include_directories(blrs PRIVATE "${CMAKE_CURRENT_BINARY_DIR}/generated")
target_include_directories(blrs SYSTEM PRIVATE "${LAZER_ROOT}")
target_compile_options(blrs PRIVATE -Wall -Wextra -Wconversion -Wshadow)
target_link_libraries(blrs PUBLIC OpenSSL::Crypto ${GMPXX_LIBRARY} ${GMP_LIBRARY} PRIVATE
  "${LAZER_ROOT}/liblazer.a"
  "${LAZER_ROOT}/third_party/hexl-development/build/hexl/lib/libhexl.a"
  ${MPFR_LIBRARY} Threads::Threads m)

add_executable(blrs_bench src/benchmark.cpp)
target_link_libraries(blrs_bench PRIVATE blrs)
target_compile_options(blrs_bench PRIVATE -Wall -Wextra -Wconversion -Wshadow)

enable_testing()
foreach(test IN ITEMS relation sampler candidate codec)
  add_executable(${test}_tests tests/${test}_tests.cpp)
  target_link_libraries(${test}_tests PRIVATE blrs)
  target_compile_options(${test}_tests PRIVATE -Wall -Wextra -Wconversion -Wshadow -UNDEBUG)
  add_test(NAME ${test} COMMAND ${test}_tests)
endforeach()
