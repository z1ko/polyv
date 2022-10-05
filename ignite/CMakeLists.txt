
add_executable(polyv_ignite src/main.cpp)
target_include_directories(polyv_ignite
    PUBLIC ${CMAKE_SOURCE_DIR}
)
target_compile_options(polyv_ignite
    PUBLIC -std=c++17
)