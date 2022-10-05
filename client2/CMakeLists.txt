add_executable(polyv_client src/main.cpp)

# Client should use encryption
target_compile_definitions(polyv_client 
    POLYV_USE_ENCRYPTION
)