cmake_minimum_required(VERSION 3.26)
project(blowfish_8bit
		LANGUAGES C
		VERSION 0.0.1)

set(CMAKE_C_STANDARD 11)

add_library(blowfish SHARED
	${CMAKE_SOURCE_DIR}/src/blowfish.c
	${CMAKE_SOURCE_DIR}/src/lua_blowfish.c
)
set_target_properties(blowfish PROPERTIES
	PREFIX ""
	OUTPUT_NAME blowfish
	SUFFIX .so
)

add_executable(bf-decrypt
	${CMAKE_SOURCE_DIR}/src/blowfish.c
	${CMAKE_SOURCE_DIR}/src/cli-lib.c
	${CMAKE_SOURCE_DIR}/src/decrypt-main.c
)
add_executable(bf-encrypt
	${CMAKE_SOURCE_DIR}/src/blowfish.c
	${CMAKE_SOURCE_DIR}/src/cli-lib.c
	${CMAKE_SOURCE_DIR}/src/encrypt-main.c
)

find_package(Lua REQUIRED)
target_include_directories(blowfish PRIVATE ${LUA_INCLUDE_DIR})
install(TARGETS blowfish DESTINATION lib/lua/${LUA_VERSION_MAJOR}.${LUA_VERSION_MINOR})
install(TARGETS bf-decrypt bf-encrypt DESTINATION bin)

find_program(LUAROCKS NAMES luarocks luarocks-${LUA_VERSION_MAJOR}.${LUA_VERSION_MINOR})
if (NOT LUAROCKS STREQUAL "LUAROCKS-NOTFOUND")
	execute_process(COMMAND ${LUAROCKS} config arch OUTPUT_VARIABLE luarocks_arch OUTPUT_STRIP_TRAILING_WHITESPACE)
	set(LUAROCKS_ARCH "${luarocks_arch}" CACHE STRING "Architecture suffix for rock file")
	if (NOT LUAROCKS_ARCH)
		message(WARNING "Cannot determine rock file suffix, consider using -DLUAROCKS_ARCH=...")
	endif ()
	add_custom_target(
		rock
		COMMAND ${LUAROCKS} make --pack-binary-rock ${CMAKE_SOURCE_DIR}/rockspecs/blowfish-multimode-${PROJECT_VERSION_MAJOR}.${PROJECT_VERSION_MINOR}-${PROJECT_VERSION_PATCH}.rockspec
		SOURCES ${CMAKE_SOURCE_DIR}/rockspecs/blowfish-multimode-${PROJECT_VERSION_MAJOR}.${PROJECT_VERSION_MINOR}-${PROJECT_VERSION_PATCH}.rockspec
		BYPRODUCTS blowfish-multimode-${PROJECT_VERSION_MAJOR}.${PROJECT_VERSION_MINOR}-${PROJECT_VERSION_PATCH}.${LUAROCKS_ARCH}.rock
	)
	execute_process(COMMAND ${LUAROCKS} config variables.LIBFLAG OUTPUT_VARIABLE linker_flags OUTPUT_STRIP_TRAILING_WHITESPACE)
	string(REPLACE " " "," linker_options "${linker_flags}")
	message(STATUS "Found luarocks: ${LUAROCKS}")
	message(VERBOSE "... rock architecture: ${LUAROCKS_ARCH}")
elseif (APPLE)
	set(linker_options, "-bundle,-undefined,dynamic_lookup,-all_load")
elseif (WIN32)
	set(linker_options, "/WHOLEARCHIVE")
else ()
	set(linker_options, "--whole-archive")
endif ()

set(LINKER_OPTIONS, "${linker_options}" CACHE STRING "Comma-separated linker flags")
target_link_options(blowfish PRIVATE "LINKER:${linker_options}")
message(VERBOSE "Using link options: ${linker_options}")
