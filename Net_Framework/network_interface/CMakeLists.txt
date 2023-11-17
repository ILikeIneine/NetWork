cmake_minimum_required(VERSION 3.22)

set(CMAKE_CXX_STANDARD 20)
project(network_interface)

file(GLOB_RECURSE HEADERS ${CMAKE_CURRENT_SOURCE_DIR}/include/*.h include/*.hpp)

add_library(${PROJECT_NAME} INTERFACE ${HEADERS})
target_include_directories(${PROJECT_NAME} INTERFACE ${CMAKE_CURRENT_SOURCE_DIR}/include)

find_package(Boost REQUIRED)
if (Boost_FOUND)
    message("Boost Founded")
    message(STATUS "Boost include directories: ${Boost_INCLUDE_DIRS}")
    target_include_directories(${PROJECT_NAME} INTERFACE ${Boost_INCLUDE_DIRS})
else ()
    message(FATAL_ERROR "Not found boost")
endif ()