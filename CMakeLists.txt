cmake_minimum_required(VERSION "3.15")
set (CMAKE_CXX_STANDARD 17)
set(CMAKE_SYSTEM_NAME Windows)
set(CMAKE_GENERATOR_PLATFORM x64)

project("pettydbg")

option(ZYDIS_BUILD_TOOLS "" OFF)
option(ZYDIS_BUILD_EXAMPLES "" OFF)
add_subdirectory("deps/zydis")

include_directories(${PROJECT_SOURCE_DIR})

add_executable("pettydbg" "commandline.cpp" "debugger.cpp"
	"main.cpp" "splitstring.cpp" "unicodeStringEx.cpp" 
	"commandline.h" "debugger.h" "main.h" "splitstring.h" "thread_info.h" "unicodeStringEx.h")

target_link_libraries("pettydbg" PRIVATE "Zydis")