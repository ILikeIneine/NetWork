cmake_minimum_required(VERSION 3.22)

project(network_client_demo)
set(CMAKE_CXX_STANDARD 20)

# file
file(GLOB_RECURSE SOURCES CMAKE_CONFIGURE_DEPENDS *.cpp *.hpp *.h)

# executable
add_executable(${PROJECT_NAME} ${SOURCES})
target_include_directories(${PROJECT_NAME} PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/include)

# link
target_link_libraries(${PROJECT_NAME} network_interface)
target_include_directories(${PROJECT_NAME} PRIVATE ../network_interface/include)
