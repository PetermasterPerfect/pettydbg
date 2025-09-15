cmake_minimum_required(VERSION "3.15")
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_SYSTEM_NAME Windows)
set(CMAKE_GENERATOR_PLATFORM x64)
project("pettydbg")
set_property(DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR} PROPERTY VS_STARTUP_PROJECT "pettydbg")

file(
  DOWNLOAD https://www.antlr.org/download/antlr-4.13.0-complete.jar
  EXPECTED_HASH SHA256=bc6f4abc0d225a27570126c51402569f000a8deda3487b70e7642840e570e4a6
  SHOW_PROGRESS
  ${PROJECT_SOURCE_DIR}/antlr4.jar
)
list(APPEND CMAKE_MODULE_PATH ${CMAKE_CURRENT_SOURCE_DIR}/cmake)

add_definitions(-DANTLR4CPP_STATIC)

# using /MD flag for antlr4_runtime (for Visual C++ compilers only)
set(ANTLR4_WITH_STATIC_CRT OFF)
# add external build for antlrcpp
include(ExternalAntlr4Cpp)
# add antrl4cpp artifacts to project environment
include_directories(${ANTLR4_INCLUDE_DIRS})

set(ANTLR_EXECUTABLE ${PROJECT_SOURCE_DIR}/antlr4.jar)
# add macros to generate ANTLR Cpp code from grammar
find_package(ANTLR REQUIRED)

execute_process(
	COMMAND java -jar ${ANTLR_EXECUTABLE} -Dlanguage=Cpp ${PROJECT_SOURCE_DIR}/commands.g4)

set(BUILD_SHARED YES CACHE BOOL "Build shared libdwarf" FORCE)
set(BUILD_NON_SHARED NO CACHE BOOL "Disable static libdwarf" FORCE)

add_subdirectory(deps/libdwarf-code)

option(ZYDIS_BUILD_TOOLS "" OFF)
option(ZYDIS_BUILD_EXAMPLES "" OFF)
add_subdirectory("deps/zydis")

include_directories(${PROJECT_SOURCE_DIR})
include_directories(${PROJECT_SOURCE_DIR}/build)

file(GLOB BUILD
	${PROJECT_SOURCE_DIR}/build/*.cpp
	${PROJECT_SOURCE_DIR}/build/*.h)


file(GLOB SOURCE
	${PROJECT_SOURCE_DIR}/*.cpp
	${PROJECT_SOURCE_DIR}/*.h)

include_directories(${ANTLR_SampleGrammarLexer_OUTPUT_DIR})
include_directories(${ANTLR_SampleGrammarParser_OUTPUT_DIR})
add_executable(pettydbg ${SOURCE} ${BUILD})
#target_include_directories(pettydbg PRIVATE ${ANTLR4_INCLUDE_DIRS})
target_link_libraries(pettydbg PRIVATE antlr4_static)
target_link_libraries(pettydbg PRIVATE Zydis)
