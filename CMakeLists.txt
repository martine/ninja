cmake_minimum_required(VERSION 3.15)

include(CheckSymbolExists)
include(CheckIPOSupported)

option(NINJA_BUILD_BINARY "Build ninja binary" ON)
option(NINJA_FORCE_PSELECT "Use pselect() even on platforms that provide ppoll()" OFF)

project(ninja CXX)

# --- optional link-time optimization
check_ipo_supported(RESULT lto_supported OUTPUT error)

if(lto_supported)
	message(STATUS "IPO / LTO enabled")
	set(CMAKE_POLICY_DEFAULT_CMP0069 NEW)
	set(CMAKE_INTERPROCEDURAL_OPTIMIZATION_RELEASE TRUE)
else()
	message(STATUS "IPO / LTO not supported: <${error}>")
endif()

# --- compiler flags
if(MSVC)
	set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")
	string(REPLACE "/GR" "" CMAKE_CXX_FLAGS ${CMAKE_CXX_FLAGS})
	# Note that these settings are separately specified in configure.py, and
	# these lists should be kept in sync.
	add_compile_options(/W4 /wd4100 /wd4267 /wd4706 /wd4702 /wd4244 /GR- /Zc:__cplusplus)
	add_compile_definitions(_CRT_SECURE_NO_WARNINGS)
else()
	include(CheckCXXCompilerFlag)
	check_cxx_compiler_flag(-Wno-deprecated flag_no_deprecated)
	if(flag_no_deprecated)
		add_compile_options(-Wno-deprecated)
	endif()
	if(CMAKE_VERSION VERSION_LESS 3.24)
		check_cxx_compiler_flag(-fdiagnostics-color flag_color_diag)
		if(flag_color_diag)
			add_compile_options(-fdiagnostics-color)
		endif()
	elseif(NOT DEFINED ENV{CMAKE_COLOR_DIAGNOSTICS})
		set(CMAKE_COLOR_DIAGNOSTICS ON)
	endif()

	if(NOT NINJA_FORCE_PSELECT)
		# Check whether ppoll() is usable on the target platform.
		# Set -DUSE_PPOLL=1 if this is the case.
		#
		# NOTE: Use check_cxx_symbol_exists() instead of check_symbol_exists()
		# because on Linux, <poll.h> only exposes the symbol when _GNU_SOURCE
		# is defined.
		#
		# Both g++ and clang++ define the symbol by default, because the C++
		# standard library headers require it, but *not* gcc and clang, which
		# are used by check_symbol_exists().
		include(CheckCXXSymbolExists)
		check_cxx_symbol_exists(ppoll poll.h HAVE_PPOLL)
		if(HAVE_PPOLL)
			add_compile_definitions(USE_PPOLL=1)
		endif()
	endif()
endif()

# --- optional re2c
set(RE2C_MAJOR_VERSION 0)
find_program(RE2C re2c)
if(RE2C)
	execute_process(COMMAND "${RE2C}" --vernum OUTPUT_VARIABLE RE2C_RAW_VERSION)
	math(EXPR RE2C_MAJOR_VERSION "${RE2C_RAW_VERSION} / 10000")
endif()
if(${RE2C_MAJOR_VERSION} GREATER 1)
	# the depfile parser and ninja lexers are generated using re2c.
	function(re2c IN OUT)
		add_custom_command(DEPENDS ${IN} OUTPUT ${OUT}
			COMMAND ${RE2C} -b -i --no-generation-date --no-version -o ${OUT} ${IN}
		)
	endfunction()
	re2c(${PROJECT_SOURCE_DIR}/src/depfile_parser.in.cc ${PROJECT_BINARY_DIR}/depfile_parser.cc)
	re2c(${PROJECT_SOURCE_DIR}/src/lexer.in.cc ${PROJECT_BINARY_DIR}/lexer.cc)
	add_library(libninja-re2c OBJECT ${PROJECT_BINARY_DIR}/depfile_parser.cc ${PROJECT_BINARY_DIR}/lexer.cc)
else()
	message(WARNING "re2c 2 or later was not found; changes to src/*.in.cc will not affect your build.")
	add_library(libninja-re2c OBJECT src/depfile_parser.cc src/lexer.cc)
endif()
target_include_directories(libninja-re2c PRIVATE src)

# --- Check for 'browse' mode support
function(check_platform_supports_browse_mode RESULT)
	# Make sure the inline.sh script works on this platform.
	# It uses the shell commands such as 'od', which may not be available.

	execute_process(
		COMMAND sh -c "echo 'TEST' | src/inline.sh var"
		WORKING_DIRECTORY ${PROJECT_SOURCE_DIR}
		RESULT_VARIABLE inline_result
		OUTPUT_QUIET
		ERROR_QUIET
	)
	if(NOT inline_result EQUAL "0")
		# The inline script failed, so browse mode is not supported.
		set(${RESULT} "0" PARENT_SCOPE)
		if(NOT WIN32)
			message(WARNING "browse feature omitted due to inline script failure")
		endif()
		return()
	endif()

	# Now check availability of the unistd header
	check_symbol_exists(fork "unistd.h" HAVE_FORK)
	check_symbol_exists(pipe "unistd.h" HAVE_PIPE)
	set(browse_supported 0)
	if (HAVE_FORK AND HAVE_PIPE)
		set(browse_supported 1)
	endif ()
	set(${RESULT} "${browse_supported}" PARENT_SCOPE)
	if(NOT browse_supported)
		message(WARNING "browse feature omitted due to missing `fork` and `pipe` functions")
	endif()

endfunction()

set(NINJA_PYTHON "python" CACHE STRING "Python interpreter to use for the browse tool")

check_platform_supports_browse_mode(platform_supports_ninja_browse)

# Core source files all build into ninja library.
add_library(libninja OBJECT
	src/build_log.cc
	src/build.cc
	src/clean.cc
	src/clparser.cc
	src/dyndep.cc
	src/dyndep_parser.cc
	src/debug_flags.cc
	src/deps_log.cc
	src/disk_interface.cc
	src/edit_distance.cc
	src/elide_middle.cc
	src/eval_env.cc
	src/graph.cc
	src/graphviz.cc
	src/jobserver.cc
	src/json.cc
	src/line_printer.cc
	src/manifest_parser.cc
	src/metrics.cc
	src/missing_deps.cc
	src/parser.cc
	src/real_command_runner.cc
	src/state.cc
	src/status_printer.cc
	src/string_piece_util.cc
	src/util.cc
	src/version.cc
)
if(WIN32)
	target_sources(libninja PRIVATE
		src/subprocess-win32.cc
		src/includes_normalize-win32.cc
		src/jobserver-win32.cc
		src/msvc_helper-win32.cc
		src/msvc_helper_main-win32.cc
		src/getopt.c
		src/minidump-win32.cc
	)
	# Build getopt.c, which can be compiled as either C or C++, as C++
	# so that build environments which lack a C compiler, but have a C++
	# compiler may build ninja.
	set_source_files_properties(src/getopt.c PROPERTIES LANGUAGE CXX)

	# windows.h defines min() and max() which conflict with std::min()
	# and std::max(), which both might be used in sources. Avoid compile
	# errors by telling windows.h to not define those two.
	add_compile_definitions(NOMINMAX)
else()
	target_sources(libninja PRIVATE
		src/jobserver-posix.cc
		src/subprocess-posix.cc
	)
	if(CMAKE_SYSTEM_NAME STREQUAL "OS400" OR CMAKE_SYSTEM_NAME STREQUAL "AIX")
		target_sources(libninja PRIVATE src/getopt.c)
		# Build getopt.c, which can be compiled as either C or C++, as C++
		# so that build environments which lack a C compiler, but have a C++
		# compiler may build ninja.
		set_source_files_properties(src/getopt.c PROPERTIES LANGUAGE CXX)
	endif()

	# Needed for perfstat_cpu_total
	if(CMAKE_SYSTEM_NAME STREQUAL "AIX")
		target_link_libraries(libninja PUBLIC "-lperfstat")
	endif()
endif()

target_compile_features(libninja PUBLIC cxx_std_11)
target_compile_features(libninja-re2c PUBLIC cxx_std_11)

#Fixes GetActiveProcessorCount on MinGW
if(MINGW)
target_compile_definitions(libninja PRIVATE _WIN32_WINNT=0x0601 __USE_MINGW_ANSI_STDIO=1)
endif()

# On IBM i (identified as "OS400" for compatibility reasons) and AIX, this fixes missing
# PRId64 (and others) at compile time in C++ sources
if(CMAKE_SYSTEM_NAME STREQUAL "OS400" OR CMAKE_SYSTEM_NAME STREQUAL "AIX")
	add_compile_definitions(__STDC_FORMAT_MACROS)
endif()

# Main executable is library plus main() function.
if(NINJA_BUILD_BINARY)
	add_executable(ninja src/ninja.cc)
	target_link_libraries(ninja PRIVATE libninja libninja-re2c)

	if(WIN32)
		target_sources(ninja PRIVATE windows/ninja.manifest)
	endif()

	option(NINJA_CLANG_TIDY "Run clang-tidy on source files" OFF)
	if(NINJA_CLANG_TIDY)
		set_target_properties(libninja PROPERTIES CXX_CLANG_TIDY "clang-tidy;--use-color")
		set_target_properties(ninja    PROPERTIES CXX_CLANG_TIDY "clang-tidy;--use-color")
	endif()
endif()

# Adds browse mode into the ninja binary if it's supported by the host platform.
if(platform_supports_ninja_browse)
	# Inlines src/browse.py into the browse_py.h header, so that it can be included
	# by src/browse.cc
	add_custom_command(
		OUTPUT build/browse_py.h
		MAIN_DEPENDENCY src/browse.py
		DEPENDS src/inline.sh
		COMMAND ${CMAKE_COMMAND} -E make_directory ${PROJECT_BINARY_DIR}/build
		COMMAND src/inline.sh kBrowsePy
						< src/browse.py
						> ${PROJECT_BINARY_DIR}/build/browse_py.h
		WORKING_DIRECTORY ${PROJECT_SOURCE_DIR}
		VERBATIM
	)

	if(NINJA_BUILD_BINARY)
		target_compile_definitions(ninja PRIVATE NINJA_HAVE_BROWSE)
		target_sources(ninja PRIVATE src/browse.cc)
	endif()
	set_source_files_properties(src/browse.cc
		PROPERTIES
			OBJECT_DEPENDS "${PROJECT_BINARY_DIR}/build/browse_py.h"
			INCLUDE_DIRECTORIES "${PROJECT_BINARY_DIR}"
			COMPILE_DEFINITIONS NINJA_PYTHON="${NINJA_PYTHON}"
	)
endif()

include(CTest)
if(BUILD_TESTING)

  # Can be removed if cmake min version is >=3.24
  if (POLICY CMP0135)
    cmake_policy(SET CMP0135 NEW)
  endif()

  find_package(GTest)
  if(NOT GTest_FOUND)
    include(FetchContent)
    FetchContent_Declare(
      googletest
      URL https://github.com/google/googletest/archive/refs/tags/release-1.12.1.tar.gz
      URL_HASH SHA256=81964fe578e9bd7c94dfdb09c8e4d6e6759e19967e397dbea48d1c10e45d0df2
    )
    FetchContent_MakeAvailable(googletest)
  endif()

  # Tests all build into ninja_test executable.
  add_executable(ninja_test
    src/build_log_test.cc
    src/build_test.cc
    src/clean_test.cc
    src/clparser_test.cc
    src/depfile_parser_test.cc
    src/deps_log_test.cc
    src/disk_interface_test.cc
    src/dyndep_parser_test.cc
    src/edit_distance_test.cc
    src/elide_middle_test.cc
    src/explanations_test.cc
    src/graph_test.cc
    src/jobserver_test.cc
    src/json_test.cc
    src/lexer_test.cc
    src/manifest_parser_test.cc
    src/missing_deps_test.cc
    src/ninja_test.cc
    src/state_test.cc
    src/string_piece_util_test.cc
    src/subprocess_test.cc
    src/test.cc
    src/util_test.cc
  )
  if(WIN32)
    target_sources(ninja_test PRIVATE src/includes_normalize_test.cc src/msvc_helper_test.cc
      windows/ninja.manifest)

    if(MSVC)
      # Silence warnings about using unlink rather than _unlink
      target_compile_definitions(ninja_test PRIVATE _CRT_NONSTDC_NO_DEPRECATE)
    endif()
  endif()
  find_package(Threads REQUIRED)
  target_link_libraries(ninja_test PRIVATE libninja libninja-re2c GTest::gtest Threads::Threads)

  foreach(perftest
    build_log_perftest
    canon_perftest
    clparser_perftest
    depfile_parser_perftest
    elide_middle_perftest
    hash_collision_bench
    manifest_parser_perftest
  )
    add_executable(${perftest} src/${perftest}.cc)
    target_link_libraries(${perftest} PRIVATE libninja libninja-re2c)
  endforeach()

  if(CMAKE_SYSTEM_NAME STREQUAL "AIX" AND CMAKE_SIZEOF_VOID_P EQUAL 4)
    # These tests require more memory than will fit in the standard AIX shared stack/heap (256M)
    target_link_options(hash_collision_bench PRIVATE "-Wl,-bmaxdata:0x80000000")
    target_link_options(manifest_parser_perftest PRIVATE "-Wl,-bmaxdata:0x80000000")
  endif()

  add_test(NAME NinjaTest COMMAND ninja_test)
endif()

if(NINJA_BUILD_BINARY)
	install(TARGETS ninja)
endif()
