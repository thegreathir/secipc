project(secipc-core)

find_package(OpenSSL REQUIRED)

add_library(commons commons.cpp)
set_property(TARGET commons PROPERTY CXX_STANDARD 17)

add_executable(server server.cpp)
set_property(TARGET server PROPERTY CXX_STANDARD 17)
target_link_libraries(server OpenSSL::SSL)
target_link_libraries(server commons)

add_executable(client client.cpp)
set_property(TARGET client PROPERTY CXX_STANDARD 17)
target_link_libraries(client OpenSSL::SSL)
target_link_libraries(client commons)
