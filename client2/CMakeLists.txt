add_executable(polyv_client src/main.cpp)

target_include_directories(polyv_client
    PUBLIC ${CMAKE_SOURCE_DIR}/include
)

# Uses custom loader script 
target_link_options(polyv_client
    PUBLIC -T${CMAKE_SOURCE_DIR}/encrypted.ld
)

target_compile_options(polyv_client
    PUBLIC -std=c++17
)

# Client should use encryption
#target_compile_definitions(polyv_client 
#    PUBLIC POLYV_USE_ENCRYPTION
#)