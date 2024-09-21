cmake_minimum_required(VERSION "3.15")
set (CMAKE_CXX_STANDARD 17)
set(CMAKE_SYSTEM_NAME Windows)
set(CMAKE_GENERATOR_PLATFORM x64)
project("pettydbg")

file(
  DOWNLOAD https://www.antlr.org/download/antlr-4.13.0-complete.jar
  EXPECTED_HASH SHA256=bc6f4abc0d225a27570126c51402569f000a8deda3487b70e7642840e570e4a6
  SHOW_PROGRESS
  ${PROJECT_SOURCE_DIR}/antlr4.jar
)
# -----
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

#antlr_target(SampleGrammarLexer ${PROJECT_SOURCE_DIR}/TLexer.g4 LEXER
#             PACKAGE pettydbg)
#antlr_target(SampleGrammarParser ${PROJECT_SOURCE_DIR}/TParser.g4 PARSER
#             PACKAGE pettydbg
#             DEPENDS_ANTLR SampleGrammarLexer
#             COMPILE_FLAGS -lib ${ANTLR_SampleGrammarLexer_OUTPUT_DIR})

execute_process(
	COMMAND java -jar ${PROJECT_SOURCE_DIR}/antlr4.jar -visitor -Dlanguage=Cpp ${PROJECT_SOURCE_DIR}/pdp7.g4)



# include generated files in project environment
include_directories(${ANTLR_SampleGrammarLexer_OUTPUT_DIR})
include_directories(${ANTLR_SampleGrammarParser_OUTPUT_DIR})

# -----
option(ZYDIS_BUILD_TOOLS "" OFF)
option(ZYDIS_BUILD_EXAMPLES "" OFF)
add_subdirectory("deps/zydis")

include_directories(${PROJECT_SOURCE_DIR})


file(GLOB BUILD
    "build/*.cpp"
    "build/*.h"
)


add_executable("pettydbg" "commandline.cpp" "debugger.cpp"
	"main.cpp" "splitstring.cpp" "unicodeStringEx.cpp" 
	"commandline.h" "debugger.h" "main.h" "splitstring.h" "thread_info.h" "unicodeStringEx.h"
	${BUILD})

target_link_libraries("pettydbg" PRIVATE "Zydis" "antlr4_static")
