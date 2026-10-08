file(GLOB_RECURSE COMMON_SOURCES
    common/*.cpp
)

file(GLOB_RECURSE DEVICE_SOURCES
    device/*.cpp
)

# Module 3: signature-based carving. Added alongside the others; the globs
# below pick it up without touching the module 1 source list.
file(GLOB_RECURSE CARVER_SOURCES
    carver/*.cpp
)

file(GLOB_RECURSE ERASURE_SOURCES
    erasure/*.cpp
)

# evidence/audit (the evidence record) and evidence/reports (renderings of it).
file(GLOB_RECURSE EVIDENCE_SOURCES
    evidence/*.cpp
)

file(GLOB_RECURSE MOCK_SOURCES
    mock/*.cpp
)

file(GLOB_RECURSE PLATFORM_SOURCES
    platform/linux/*.cpp
)

add_library(ledgerase-core STATIC
    ${COMMON_SOURCES}
    ${DEVICE_SOURCES}
    ${ERASURE_SOURCES}
    ${CARVER_SOURCES}
    ${EVIDENCE_SOURCES}
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

# src/ is private to the library: the Linux platform header, the mock backend,
# the progress reporter and the internal evidence-document header are included
# as "platform/linux/linux.hpp", "mock/mock.hpp" and so on, and are not part of
# the installed include/ tree.
target_include_directories(ledgerase-core PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}
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
