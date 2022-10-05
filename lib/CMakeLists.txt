
add_library(polyv
    src/polyv.hpp
    src/polyv.cpp
)

# Base c++ version should be 17
target_compile_options(polyv
    PUBLIC -std=c++17
)

# Library depends also on linker script
#set_target_properties(polyv PROPERTIES
#    LINK_DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/ld/encrypted.ld
#)

# Library file are shared to all importers
target_include_directories(polyv 
    PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/src
)

# Uses custom loader script 
target_link_options(polyv
    PUBLIC -T${CMAKE_CURRENT_SOURCE_DIR}/ld/encrypted.ld
)
