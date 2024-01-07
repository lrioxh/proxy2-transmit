cmake_minimum_required (VERSION 2.8)#规定cmake的最低版本要求
project(proxy)#项目的名称，不一定和你的文件夹名称一样
set(CMAKE_C_COMPILER "gcc")#设置c编译器
set(CMAKE_CXX_COMPILER "g++")

#dubug 模式
set (CMAKE_CXX_FLAGS  "${CMAKE_CXX_FLAGS} -g")

include_directories(${PROJECT_SOURCE_DIR}/include)#添加头文件的搜索路径

aux_source_directory(${PROJECT_SOURCE_DIR}/src SrcFiles)#将源文件列表写在变量SrcFiles中

set(EXECUTABLE_OUTPUT_PATH  ${PROJECT_SOURCE_DIR}/build)#设置可执行文件输出路径
add_executable(proxy-transmit ${SrcFiles})#设置可执行文件的名称