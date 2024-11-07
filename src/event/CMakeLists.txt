libp2p_add_library(p2p_event INTERFACE)
target_include_directories(p2p_event INTERFACE "$<BUILD_INTERFACE:${CMAKE_SOURCE_DIR}/include>")
target_link_libraries(p2p_event INTERFACE soralog::soralog)