add_library(emcurl curl.cpp)

set_target_properties(emcurl PROPERTIES PUBLIC_HEADER "curl.h")
INSTALL(TARGETS emcurl
        LIBRARY DESTINATION lib
        PUBLIC_HEADER DESTINATION include/curl
)
