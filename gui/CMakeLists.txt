# Qt6 application (BUILD_GUI=ON). Consumes ledgerase-core only.
#
# There is no GUI source yet. Until there is, BUILD_GUI=ON configures with a
# warning and builds no ledgerase-gui target. Adding .cpp files here makes the
# target appear.
file(GLOB_RECURSE GUI_SOURCES
    *.cpp
)

if(NOT GUI_SOURCES)
    message(WARNING "BUILD_GUI=ON but gui/ contains no source files yet; "
                    "ledgerase-gui is not built.")
    return()
endif()

file(GLOB_RECURSE GUI_HEADERS
    *.hpp
    *.h
)

qt_add_executable(ledgerase-gui
    ${GUI_SOURCES}
    ${GUI_HEADERS}
)

target_link_libraries(ledgerase-gui PRIVATE
    ledgerase-core
    Qt6::Core
    Qt6::Widgets
    Qt6::Charts
)
