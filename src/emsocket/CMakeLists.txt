add_library(emsocket emsocket.cpp)

set_target_properties(emsocket PROPERTIES PUBLIC_HEADER "emsocket.h")
INSTALL(TARGETS emsocket
        LIBRARY DESTINATION lib
        PUBLIC_HEADER DESTINATION include
)
