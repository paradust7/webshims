add_custom_command(
  OUTPUT proxyjs.gen.h
  COMMAND ${CMAKE_CURRENT_SOURCE_DIR}/gen.sh
  ARGS ${CMAKE_CURRENT_SOURCE_DIR}/proxy.js proxyjs.gen.h
  MAIN_DEPENDENCY ${CMAKE_CURRENT_SOURCE_DIR}/proxy.js
  DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/gen.sh
)
add_custom_target(proxyjs ALL DEPENDS proxyjs.gen.h)

add_library(emsocket emsocket.cpp emsocketctl.cpp ProxyLink.cpp VirtualSocket.cpp)
set_target_properties(emsocket PROPERTIES PUBLIC_HEADER "emsocket.h;emsocketctl.h")
target_include_directories(emsocket PRIVATE ${CMAKE_CURRENT_BINARY_DIR})
add_dependencies(emsocket proxyjs)

INSTALL(
  TARGETS emsocket
  LIBRARY DESTINATION lib
  PUBLIC_HEADER DESTINATION include
)
