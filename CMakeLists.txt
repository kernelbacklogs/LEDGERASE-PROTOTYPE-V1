cmake_minimum_required(VERSION 3.20)
project(Sanitizer
    VERSION 1.0.0
    LANGUAGES CXX
    DESCRIPTION "Storage Media Sanitization Platform"
)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)

if(CMAKE_BUILD_TYPE STREQUAL "")
    set(CMAKE_BUILD_TYPE Release)
endif()

option(BUILD_GUI "Build Qt6 GUI" OFF)
option(BUILD_CLI "Build CLI" ON)
option(BUILD_TESTS "Build tests" ON)
option(BUILD_MOCK "Build mock backend" ON)
option(ENABLE_SANITIZERS "Enable address/thread sanitizers" OFF)

set(CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG} -Wall -Wextra -Wpedantic -Werror -g -O0")
set(CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE} -Wall -Wextra -Wpedantic -Werror -O3 -DNDEBUG")

if(ENABLE_SANITIZERS)
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fsanitize=address,undefined -fno-omit-frame-pointer")
    set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -fsanitize=address,undefined")
endif()

find_package(PkgConfig REQUIRED)
find_package(Threads REQUIRED)

pkg_check_modules(LIBUDEV REQUIRED libudev)
pkg_check_modules(LIBUUID REQUIRED uuid)
pkg_check_modules(LIBBLKID REQUIRED blkid)
pkg_check_modules(OPENSSL openssl)

# nlohmann/json is fetched at configure time, so it is a supply-chain input to a
# tool whose entire purpose is trustworthy erasure. It is therefore pinned to an
# immutable commit, not to the moving tag "v3.11.2".
#
# The commit below is the one the v3.11.2 tag resolves to (the v3.11.2 release
# merge). Pinning the tag instead would mean re-resolving it on every fresh
# configure: a tag can be moved to a different commit after the fact, and this
# build would silently compile against whatever it points at then.
#
# The first configure of a pinned FetchContent still needs network access. To
# verify what was actually checked out rather than trusting the pin alone, run
#
#   git -C build/_deps/nlohmann_json-src rev-parse HEAD
#
# and confirm it prints the SHA below. GIT_SHALLOW is not used, because a pinned
# commit is not reachable by depth-limited clone unless it happens to be a branch
# tip.
include(FetchContent)
set(LEDGERASE_NLOHMANN_JSON_SHA "bc889afb4c5bf1c0d8ee29ef35eaaf4c8bef8a5d" CACHE STRING
    "Pinned nlohmann/json commit. Update deliberately, never automatically.")
FetchContent_Declare(
    nlohmann_json
    GIT_REPOSITORY https://github.com/nlohmann/json.git
    GIT_TAG ${LEDGERASE_NLOHMANN_JSON_SHA}
)
FetchContent_MakeAvailable(nlohmann_json)

# Defence in depth: confirm the dependency that was actually populated is the
# pinned revision. A stale _deps directory from an earlier configure, or an
# upstream mistake, then fails the build instead of being compiled in silently.
if(EXISTS "${nlohmann_json_SOURCE_DIR}/.git")
    find_package(Git QUIET)
    if(GIT_FOUND)
        execute_process(
            COMMAND "${GIT_EXECUTABLE}" -C "${nlohmann_json_SOURCE_DIR}" rev-parse HEAD
            OUTPUT_VARIABLE LEDGERASE_NLOHMANN_JSON_ACTUAL
            OUTPUT_STRIP_TRAILING_WHITESPACE
            RESULT_VARIABLE LEDGERASE_NLOHMANN_JSON_GIT_RESULT
            ERROR_QUIET)
        if(LEDGERASE_NLOHMANN_JSON_GIT_RESULT EQUAL 0
           AND NOT LEDGERASE_NLOHMANN_JSON_ACTUAL STREQUAL LEDGERASE_NLOHMANN_JSON_SHA)
            message(FATAL_ERROR
                "nlohmann/json is checked out at ${LEDGERASE_NLOHMANN_JSON_ACTUAL} "
                "but this project pins ${LEDGERASE_NLOHMANN_JSON_SHA}. Refusing to "
                "build against an unverified dependency. Delete build/_deps and "
                "re-run cmake to re-fetch the pinned revision.")
        endif()
    endif()
endif()

if(BUILD_GUI)
    find_package(Qt6 REQUIRED COMPONENTS Core Widgets Charts)
    if(Qt6_VERSION VERSION_LESS 6.5)
        message(WARNING "Qt6 version ${Qt6_VERSION} found, 6.5+ recommended")
    endif()
endif()

add_subdirectory(src)

if(BUILD_CLI)
    add_subdirectory(cli)
endif()

if(BUILD_GUI)
    add_subdirectory(gui)
endif()

if(BUILD_TESTS)
    enable_testing()
    add_subdirectory(tests)
endif()

install(TARGETS ledgerase-core
    RUNTIME DESTINATION bin
    LIBRARY DESTINATION lib
    ARCHIVE DESTINATION lib
)

# The applications are optional (BUILD_CLI / BUILD_GUI), so install each only
# when its target exists.
if(TARGET ledgerase-cli)
    install(TARGETS ledgerase-cli RUNTIME DESTINATION bin)
endif()

if(TARGET ledgerase-gui)
    install(TARGETS ledgerase-gui RUNTIME DESTINATION bin)
endif()

install(DIRECTORY include/ DESTINATION include)