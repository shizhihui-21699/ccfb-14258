cmake_minimum_required(VERSION 3.16)
project(puf_binding LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

if(NOT CMAKE_BUILD_TYPE)
  set(CMAKE_BUILD_TYPE Release)
endif()

if(CMAKE_CXX_COMPILER_ID MATCHES "GNU|Clang")
  add_compile_options(-Wall -Wextra -Wpedantic)
endif()

add_library(pufcore INTERFACE)
target_include_directories(pufcore INTERFACE ${CMAKE_CURRENT_SOURCE_DIR}/src)

enable_testing()

function(add_puf_test name src)
  add_executable(${name} ${src})
  target_link_libraries(${name} PRIVATE pufcore)
  add_test(NAME ${name} COMMAND ${name})
endfunction()

add_puf_test(test_crypto tests/test_crypto.cpp)
add_puf_test(test_bch    tests/test_bch.cpp)
add_puf_test(test_fuzzy  tests/test_fuzzy.cpp)

add_executable(experiments tools/experiments.cpp)
target_link_libraries(experiments PRIVATE pufcore)
add_executable(demo tools/demo.cpp)
target_link_libraries(demo PRIVATE pufcore)
