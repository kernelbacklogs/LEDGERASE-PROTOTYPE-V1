file(GLOB_RECURSE CORE_SOURCES
    core/*.cpp
)

file(GLOB_RECURSE DEVICE_SOURCES
    device/*.cpp
)

file(GLOB_RECURSE CAPABILITY_SOURCES
    capability/*.cpp
)

file(GLOB_RECURSE SAFETY_SOURCES
    safety/*.cpp
)

file(GLOB_RECURSE POLICY_SOURCES
    policy/*.cpp
)

file(GLOB_RECURSE SANITIZATION_SOURCES
    sanitization/*.cpp
)

# Module 3: signature-based carving. Added alongside the others; the globs
# below pick it up without touching the module 1 source list.
file(GLOB_RECURSE CARVING_SOURCES
    carving/*.cpp
)

file(GLOB_RECURSE ERASURE_SOURCES
    erasure/*.cpp
)

file(GLOB_RECURSE VERIFICATION_SOURCES
    verification/*.cpp
)

file(GLOB_RECURSE REPORTING_SOURCES
    reporting/*.cpp
)

file(GLOB_RECURSE AUDIT_SOURCES
    audit/*.cpp
)

file(GLOB_RECURSE MOCK_SOURCES
    mock/*.cpp
)

file(GLOB_RECURSE PLATFORM_SOURCES
    platform/linux/*.cpp
)

file(GLOB_RECURSE FILESYSTEM_SOURCES
    filesystem/*.cpp
)

file(GLOB_RECURSE CLI_SOURCES
    cli/*.cpp
)

add_library(ledgerase-core STATIC
    ${CORE_SOURCES}
    ${DEVICE_SOURCES}
    ${CAPABILITY_SOURCES}
    ${SAFETY_SOURCES}
    ${POLICY_SOURCES}
    ${SANITIZATION_SOURCES}
    ${VERIFICATION_SOURCES}
    ${CARVING_SOURCES}
    ${FILESYSTEM_SOURCES}
    ${ERASURE_SOURCES}
    ${REPORTING_SOURCES}
    ${AUDIT_SOURCES}
    ${MOCK_SOURCES}
    ${PLATFORM_SOURCES}
)

target_include_directories(ledgerase-core PUBLIC
    ${CMAKE_SOURCE_DIR}/include
    ${LIBUDEV_INCLUDE_DIRS}
    ${LIBUUID_INCLUDE_DIRS}
    ${LIBBLKID_INCLUDE_DIRS}
    ${OPENSSL_INCLUDE_DIRS}
)

target_link_libraries(ledgerase-core PUBLIC
    Threads::Threads
    ${LIBUDEV_LIBRARIES}
    ${LIBUUID_LIBRARIES}
    ${LIBBLKID_LIBRARIES}
    ${OPENSSL_LIBRARIES}
    nlohmann_json::nlohmann_json
)

target_compile_options(ledgerase-core PRIVATE
    -fPIC
)

if(BUILD_CLI)
    add_executable(ledgerase-cli
        main.cpp
        ${CLI_SOURCES}
    )

    target_link_libraries(ledgerase-cli PRIVATE ledgerase-core)

    target_include_directories(ledgerase-cli PRIVATE
        ${CMAKE_SOURCE_DIR}/include
    )
endif()

if(BUILD_GUI)
    file(GLOB_RECURSE GUI_SOURCES
        gui/*.cpp
        gui/*.hpp
        gui/*.h
    )

    qt_add_executable(ledgerase-gui
        main_gui.cpp
        ${GUI_SOURCES}
    )

    target_link_libraries(ledgerase-gui PRIVATE
        ledgerase-core
        Qt6::Core
        Qt6::Widgets
        Qt6::Charts
    )
endif()