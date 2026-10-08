# Command-line application. Consumes ledgerase-core; the core does not depend
# on anything in this directory.
file(GLOB_RECURSE CLI_SOURCES
    *.cpp
)

add_executable(ledgerase-cli
    ${CLI_SOURCES}
)

target_link_libraries(ledgerase-cli PRIVATE ledgerase-core)

# The CLI wires up the mock backend (--simulation) and the progress reporter,
# both of which are internal to the core library and live under src/. They are
# reached as "mock/mock.hpp" and "evidence/reports/progress_reporter.hpp".
target_include_directories(ledgerase-cli PRIVATE
    ${CMAKE_SOURCE_DIR}/include
    ${CMAKE_SOURCE_DIR}/src
)
