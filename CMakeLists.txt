project(secipc)
cmake_minimum_required(VERSION 3.23)

add_subdirectory(core)
configure_file(${CMAKE_SOURCE_DIR}/cert/cert.pem ${CMAKE_BINARY_DIR}/core COPYONLY)
configure_file(${CMAKE_SOURCE_DIR}/cert/key.pem ${CMAKE_BINARY_DIR}/core COPYONLY)