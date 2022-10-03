

add_library(polyv_lib
    src/payload.hpp 
    src/payload.cpp 
    src/crypt.hpp 
    src/crypt.cpp
    src/platform/linux.cpp
)

target_compile_options(polyv_lib PUBLIC "-fPIC")
target_include_directories(polyv_lib PUBLIC src)

add_executable(polyv_client src/main.cpp)
target_link_libraries(polyv_client PUBLIC polyv_lib)