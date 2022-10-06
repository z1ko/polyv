cmake_minimum_required(VERSION 3.16)
project(polyv)

add_subdirectory(client)
add_subdirectory(ignite)
add_subdirectory(target)

# Install all in the bin directory
#install(TARGETS polyv_client   DESTINATION bin)
#install(TARGETS polyv_ignite   DESTINATION bin)