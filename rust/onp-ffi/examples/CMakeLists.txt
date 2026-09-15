cmake_minimum_required(VERSION 3.15)
project(onp_cpp_example CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

include_directories(${CMAKE_CURRENT_SOURCE_DIR}/../include)

add_executable(onp_example main.cpp)

# Target linking
if (WIN32)
    target_link_libraries(onp_example PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/../../target/release/onp_ffi.dll)
elseif (APPLE)
    target_link_libraries(onp_example PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/../../target/release/libonp_ffi.dylib)
else ()
    target_link_libraries(onp_example PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/../../target/release/libonp_ffi.so)
endif ()
