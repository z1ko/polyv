
add_executable(polyv_crypted main.cpp payload.cpp payload.hpp)

set_target_properties(polyv_crypted PROPERTIES
    LINK_DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/payload.ld 
)

target_include_directories(polyv_crypted 
    PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}
)

target_link_options(polyv_crypted
    # Place all code in the payload.o objecfile inside the xpayload section
    PUBLIC -T${CMAKE_CURRENT_SOURCE_DIR}/payload.ld
)