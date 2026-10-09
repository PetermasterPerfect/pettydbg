cmake_minimum_required(VERSION "3.15")
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
project("pettydbg")

if(WIN32)
	set_property(DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR} PROPERTY VS_STARTUP_PROJECT "pettydbg")
else()
	add_compile_options(-g)
endif()

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
	COMMAND java -jar ${ANTLR_EXECUTABLE} -Dlanguage=Cpp -o ${CMAKE_BINARY_DIR} ${PROJECT_SOURCE_DIR}/commands.g4
	WORKING_DIRECTORY ${CMAKE_BINARY_DIR}
)

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

if(WIN32)
	file(GLOB SOURCE
		${PROJECT_SOURCE_DIR}/src/*.cpp
		${PROJECT_SOURCE_DIR}/src/*.h)
else()
	file(GLOB ALL_SOURCE
		${PROJECT_SOURCE_DIR}/src/*.cpp
		${PROJECT_SOURCE_DIR}/src/*.h)
	list(FILTER ALL_SOURCE EXCLUDE REGEX ".*windows_debug_backend.*")
	list(FILTER ALL_SOURCE EXCLUDE REGEX ".*unicodeStringEx.*")
	set(SOURCE ${ALL_SOURCE})
endif()

include_directories(${ANTLR_SampleGrammarLexer_OUTPUT_DIR})
include_directories(${ANTLR_SampleGrammarParser_OUTPUT_DIR})
include_directories(${PROJECT_SOURCE_DIR}/deps/libdwarf-code/src/lib/libdwarf)

add_executable(pettydbg ${SOURCE} ${BUILD})
target_link_libraries(pettydbg PRIVATE antlr4_static)
target_link_libraries(pettydbg PRIVATE Zydis)
target_link_libraries(pettydbg PRIVATE libdwarf::dwarf-shared)

if(UNIX)
	target_link_libraries(pettydbg PRIVATE pthread dl)
endif()

if(WIN32)
	add_custom_command(TARGET pettydbg POST_BUILD
	  COMMAND ${CMAKE_COMMAND} -E copy_if_different
	    $<TARGET_FILE:dwarf>
	    $<TARGET_FILE_DIR:pettydbg>) 
endif()

# Unit testing with GoogleTest
enable_testing()
include(FetchContent)
FetchContent_Declare(
  googletest
  URL https://github.com/google/googletest/archive/refs/tags/v1.14.0.tar.gz
)
# For Windows: Prevent overriding the parent project's compiler/linker settings
set(gtest_force_shared_crt ON CACHE BOOL "" FORCE)
FetchContent_MakeAvailable(googletest)

file(GLOB UNIT_TEST_SOURCES ${PROJECT_SOURCE_DIR}/tests/unit/*.cpp)
file(GLOB ANTLR_PARSER_GEN_SOURCES 
	${CMAKE_BINARY_DIR}/commandsLexer.cpp
	${CMAKE_BINARY_DIR}/commandsParser.cpp
	${CMAKE_BINARY_DIR}/commandsBaseListener.cpp
	${CMAKE_BINARY_DIR}/commandsListener.cpp)

add_executable(unit_tests ${UNIT_TEST_SOURCES} ${ANTLR_PARSER_GEN_SOURCES})
target_link_libraries(unit_tests PRIVATE 
	GTest::gtest_main 
	antlr4_static 
	libdwarf::dwarf-shared
)
if(UNIX)
	target_link_libraries(unit_tests PRIVATE pthread dl)
endif()

add_test(NAME unit_tests COMMAND unit_tests)

# End-to-end tests launch pettydbg against real, deterministic debuggees.
find_package(Python3 REQUIRED COMPONENTS Interpreter)

function(add_e2e_debuggee target_name source_file)
	add_executable(${target_name} ${source_file})
	if(MSVC)
		target_compile_options(${target_name} PRIVATE /Od /Zi)
	else()
		target_compile_options(${target_name} PRIVATE -O0 -g)
	endif()
endfunction()

add_e2e_debuggee(e2e_debuggee tests/e2e/debuggee.cpp)
add_e2e_debuggee(e2e_debuggee_state tests/e2e/debuggee_state.cpp)
add_e2e_debuggee(e2e_debuggee_call tests/e2e/debuggee_call.cpp)
add_e2e_debuggee(e2e_debuggee_source tests/e2e/debuggee_source.cpp)

add_test(
	NAME e2e_debugger_commands
	COMMAND ${Python3_EXECUTABLE} ${PROJECT_SOURCE_DIR}/tests/e2e/run_debugger.py
		$<TARGET_FILE:pettydbg>
		$<TARGET_FILE:e2e_debuggee>)
set_tests_properties(e2e_debugger_commands PROPERTIES TIMEOUT 20)

add_test(
	NAME e2e_debugger_register_state
	COMMAND ${Python3_EXECUTABLE} ${PROJECT_SOURCE_DIR}/tests/e2e/test_register_state.py
		$<TARGET_FILE:pettydbg>
		$<TARGET_FILE:e2e_debuggee_state>)
set_tests_properties(e2e_debugger_register_state PROPERTIES TIMEOUT 20)

add_test(
	NAME e2e_debugger_breakpoint_state
	COMMAND ${Python3_EXECUTABLE} ${PROJECT_SOURCE_DIR}/tests/e2e/test_breakpoint_state.py
		$<TARGET_FILE:pettydbg>
		$<TARGET_FILE:e2e_debuggee_call>)
set_tests_properties(e2e_debugger_breakpoint_state PROPERTIES TIMEOUT 20)

add_test(
	NAME e2e_debugger_source_state
	COMMAND ${Python3_EXECUTABLE} ${PROJECT_SOURCE_DIR}/tests/e2e/test_source_state.py
		$<TARGET_FILE:pettydbg>
		$<TARGET_FILE:e2e_debuggee_source>)
set_tests_properties(e2e_debugger_source_state PROPERTIES TIMEOUT 20)
