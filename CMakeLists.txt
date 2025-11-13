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
  ${CMAKE_BINARY_DIR}/antlr4.jar
)
list(APPEND CMAKE_MODULE_PATH ${CMAKE_CURRENT_SOURCE_DIR}/cmake/)

add_definitions(-DANTLR4CPP_STATIC)

set(ANTLR4_WITH_STATIC_CRT OFF)
include(ExternalAntlr4Cpp)

include_directories(${ANTLR4_INCLUDE_DIRS})
set(ANTLR_EXECUTABLE ${CMAKE_BINARY_DIR}/antlr4.jar)
find_package(ANTLR REQUIRED)

execute_process(
	COMMAND java -jar ${ANTLR_EXECUTABLE} -Dlanguage=Cpp ${PROJECT_SOURCE_DIR}/commands.g4)


set(BUILD_SHARED YES CACHE BOOL "Build shared libdwarf" FORCE)
set(BUILD_NON_SHARED NO CACHE BOOL "Disable static libdwarf" FORCE)

add_subdirectory(deps/libdwarf-code)

option(ZYDIS_BUILD_TOOLS "" OFF)
option(ZYDIS_BUILD_EXAMPLES "" OFF)
add_subdirectory("deps/zydis")

include_directories(${PROJECT_SOURCE_DIR}/src)

include_directories(${CMAKE_BINARY_DIR})

file(GLOB BUILD
	${CMAKE_BINARY_DIR}/*.cpp
	${CMAKE_BINARY_DIR}/*.h)


file(GLOB SOURCE
	${PROJECT_SOURCE_DIR}/src/*.cpp
	${PROJECT_SOURCE_DIR}/src/*.h)

include_directories(${ANTLR_SampleGrammarLexer_OUTPUT_DIR})
include_directories(${ANTLR_SampleGrammarParser_OUTPUT_DIR})
add_executable(pettydbg ${SOURCE} ${BUILD})
target_link_libraries(pettydbg PRIVATE antlr4_static)
target_link_libraries(pettydbg PRIVATE Zydis)

include_directories(${PROJECT_SOURCE_DIR}/deps/libdwarf/src/lib/libdwarf)
target_link_libraries(pettydbg PRIVATE libdwarf::dwarf-shared)
add_custom_command(TARGET pettydbg POST_BUILD
  COMMAND ${CMAKE_COMMAND} -E copy_if_different
    $<TARGET_FILE:dwarf>
    $<TARGET_FILE_DIR:pettydbg>) 

