add_library(emsocket emsocket.cpp emsocketctl.cpp ProxyLink.cpp VirtualSocket.cpp)

set_target_properties(emsocket PROPERTIES PUBLIC_HEADER "emsocket.h;emsocketctl.h")
INSTALL(TARGETS emsocket
        LIBRARY DESTINATION lib
        PUBLIC_HEADER DESTINATION include
)
