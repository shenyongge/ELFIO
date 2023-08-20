
set (CMAKE_CXX_FLAGS "-g")
add_executable(relocelf relocelf.cpp)
target_link_libraries(relocelf PRIVATE elfio::elfio)
