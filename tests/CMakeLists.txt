# Tests CMakeLists.txt

# Several tests exercise internals directly (the Linux platform layer, the mock
# backend, the progress reporter), so src/ is on their include path. Those
# headers are not part of the public include/ tree.
include_directories(${CMAKE_SOURCE_DIR}/src)

# Execution status semantics: a failed sanitization must never be reported as
# a success, and simulation must not reach the real device methods.
add_executable(test_execution_status test_execution_status.cpp)
target_link_libraries(test_execution_status PRIVATE ledgerase-core)
target_include_directories(test_execution_status PRIVATE
    ${CMAKE_SOURCE_DIR}/include
)
add_test(NAME test_execution_status COMMAND test_execution_status)

# Evidence layer: hash chain, tamper/truncation detection, Ed25519 signing,
# and the honesty gates on the recorded outcome.
add_executable(test_evidence test_evidence.cpp)
target_link_libraries(test_evidence PRIVATE ledgerase-core)
target_include_directories(test_evidence PRIVATE
    ${CMAKE_SOURCE_DIR}/include
)
add_test(NAME test_evidence COMMAND test_evidence)

# Example:
# add_executable(test_device test_device.cpp)
# target_link_libraries(test_device PRIVATE ledgerase-core)
# add_test(NAME test_device COMMAND test_device)

# Device identification: USB transport, media-type derivation, and host
# techniques on an unidentified bus.
add_executable(test_device_identification test_device_identification.cpp)
target_link_libraries(test_device_identification PRIVATE ledgerase-core)
target_include_directories(test_device_identification PRIVATE
    ${CMAKE_SOURCE_DIR}/include
)
add_test(NAME test_device_identification COMMAND test_device_identification)

# Raw hardware command encodings: NVMe Sanitize opcode and cdw10/cdw11 field
# layout, the ATA Security Feature Set fail-closed path, and the NVMe identity
# struct offsets. Asserts against the specification without opening any device.
add_executable(test_hardware_commands test_hardware_commands.cpp)
target_link_libraries(test_hardware_commands PRIVATE ledgerase-core)
target_include_directories(test_hardware_commands PRIVATE
    ${CMAKE_SOURCE_DIR}/include
)
add_test(NAME test_hardware_commands COMMAND test_hardware_commands)

# Device containment: both kernel partition-naming conventions, and the
# neighbouring-disk cases that must not be mistaken for a partition. Backs
# isMounted / isSystemDisk / isBootDisk / the swap check.
add_executable(test_device_containment test_device_containment.cpp)
target_link_libraries(test_device_containment PRIVATE ledgerase-core)
target_include_directories(test_device_containment PRIVATE
    ${CMAKE_SOURCE_DIR}/include
)
add_test(NAME test_device_containment COMMAND test_device_containment)

# USB mass storage: bridge passthrough vs. a bridge that accepts commands and
# erases nothing, the refusal-not-downgrade rule for PURGE, and the real
# read-back verifier against a temporary image.
add_executable(test_usb_support test_usb_support.cpp)
target_link_libraries(test_usb_support PRIVATE ledgerase-core)
target_include_directories(test_usb_support PRIVATE
    ${CMAKE_SOURCE_DIR}/include
)
add_test(NAME test_usb_support COMMAND test_usb_support)

# Safety properties that are easy to lose silently: the serial confirmation must
# fail closed, a host overwrite must not under-wipe and report success, an
# unknown NVMe namespace must not be targeted, an unestablished capability must
# not read as supported, and --method must be honoured or refused.
add_executable(test_safety_properties test_safety_properties.cpp)
target_link_libraries(test_safety_properties PRIVATE ledgerase-core)
target_include_directories(test_safety_properties PRIVATE
    ${CMAKE_SOURCE_DIR}/include
)
add_test(NAME test_safety_properties COMMAND test_safety_properties)

# Output quality: the limitation registry (unique IDs, grouped, no banned
# phrasing) and the progress formatter (fields, pac-man position, ASCII
# fallback, narrow terminals, TTY-off). No device is touched.
add_executable(test_output_quality test_output_quality.cpp)
target_link_libraries(test_output_quality PRIVATE ledgerase-core)
target_compile_definitions(test_output_quality PRIVATE
    LEDGERASE_SOURCE_DIR="${CMAKE_SOURCE_DIR}"
)
target_include_directories(test_output_quality PRIVATE
    ${CMAKE_SOURCE_DIR}/include
)
add_test(NAME test_output_quality COMMAND test_output_quality)

# Carving: signature-based recovery from a controlled dataset. Recovery is
# asserted by content hash against a known original, never by filename. The
# source is opened read-only and must be unchanged afterwards.
add_executable(test_carving test_carving.cpp)
target_link_libraries(test_carving PRIVATE ledgerase-core)
target_include_directories(test_carving PRIVATE
    ${CMAKE_SOURCE_DIR}/include
)
add_test(NAME test_carving COMMAND test_carving)

# Recovery accuracy: the three cases a controlled-dataset suite does not cover -
# a fragmented file, a quick-formatted medium, and a deleted file that was partly
# overwritten. Asserts that the carver *fails* on them and says why, because a
# carver that reports a wrong recovery is worse than one that reports nothing.
# Also covers the carve evidence record and the output-containment refusal.
add_executable(test_carve_accuracy test_carve_accuracy.cpp)
target_link_libraries(test_carve_accuracy PRIVATE ledgerase-core)
target_include_directories(test_carve_accuracy PRIVATE
    ${CMAKE_SOURCE_DIR}/include
)
add_test(NAME test_carve_accuracy COMMAND test_carve_accuracy)

# The filesystem capability matrix and the strict refusal policy. Asserts the
# table says what it must say, that delete-trace removal is never claimed, and
# that every refusal names an action the operator can take.
add_executable(test_filesystem_capability test_filesystem_capability.cpp)
target_link_libraries(test_filesystem_capability PRIVATE ledgerase-core)
target_compile_definitions(test_filesystem_capability PRIVATE
    LEDGERASE_SOURCE_DIR="${CMAKE_SOURCE_DIR}"
)
target_include_directories(test_filesystem_capability PRIVATE
    ${CMAKE_SOURCE_DIR}/include
)
add_test(NAME test_filesystem_capability COMMAND test_filesystem_capability)

# File and folder erasure: the overwrite and its read-back, the hard-link and
# symlink blocks, the folder's per-entry classification, and the format-blind
# residual search that replaces the carver as the check.
add_executable(test_file_erasure test_file_erasure.cpp)
target_link_libraries(test_file_erasure PRIVATE ledgerase-core)
target_include_directories(test_file_erasure PRIVATE
    ${CMAKE_SOURCE_DIR}/include
)
add_test(NAME test_file_erasure COMMAND test_file_erasure)

# Every setting that was declared, parsed or documented but not enforced, shown
# changing behaviour when it is changed. The cap, the search bound, the pass
# count, the category filter and --identity-confirmed all failed this in one form
# or another.
# Runs the real CLI binary, so it exists only when BUILD_CLI=ON.
if(TARGET ledgerase-cli)
    add_executable(test_config_enforcement test_config_enforcement.cpp)
    target_link_libraries(test_config_enforcement PRIVATE ledgerase-core)
    target_compile_definitions(test_config_enforcement PRIVATE
        LEDGERASE_CLI_PATH="$<TARGET_FILE:ledgerase-cli>"
    )
    add_dependencies(test_config_enforcement ledgerase-cli)
    target_include_directories(test_config_enforcement PRIVATE
        ${CMAKE_SOURCE_DIR}/include
    )
    add_test(NAME test_config_enforcement COMMAND test_config_enforcement)

    # Runtime layout of the evidence directory: bundles in audit/, rendered
    # reports in reports/, reports never read back as records.
    add_executable(test_evidence_layout test_evidence_layout.cpp)
    target_compile_definitions(test_evidence_layout PRIVATE
        LEDGERASE_CLI_PATH="$<TARGET_FILE:ledgerase-cli>"
    )
    add_dependencies(test_evidence_layout ledgerase-cli)
    add_test(NAME test_evidence_layout COMMAND test_evidence_layout)
endif()

# The local assurance policy: a judgement encoded as a function. What matters is
# not that it returns a level but that it is total, that it declines to decide on
# partial input, and that nothing it says is attributable to NIST SP 800-88
# Rev. 2 - the level names are the standard's, the choice between them is not.
add_executable(test_assurance_policy test_assurance_policy.cpp)
target_link_libraries(test_assurance_policy PRIVATE ledgerase-core)
target_include_directories(test_assurance_policy PRIVATE
    ${CMAKE_SOURCE_DIR}/include
)
add_test(NAME test_assurance_policy COMMAND test_assurance_policy)

# Folder handling: the traversal, glob filtering, the symlink rule and the
# file-scope refusals. These are the things that only become dangerous at folder
# scale, and the symlink rule in particular is the one the whole tool exists to
# get right, so it is tested against a real tree rather than a fixture.
add_executable(test_folder_handling test_folder_handling.cpp)
target_link_libraries(test_folder_handling PRIVATE ledgerase-core)
target_include_directories(test_folder_handling PRIVATE
    ${CMAKE_SOURCE_DIR}/include
)
add_test(NAME test_folder_handling COMMAND test_folder_handling)

# Device read-only determination and write-access checks.
#
# Regression: a safety check reported "Cannot open device to check read-only
# status" for a writable USB drive whose node the operator could not open, while
# blockdev --getro returned 0 and lsblk reported RO=0. Two defects, fixed
# together - the state was only ever established by BLKROGET on an open fd, and
# the permissions check tested the owner's write bit so it false-PASSed for every
# user. Driven through findSysfsPath()'s sysfsBase seam, so no real block device
# and no privilege are needed.
add_executable(test_device_readonly test_device_readonly.cpp)
target_link_libraries(test_device_readonly PRIVATE ledgerase-core)
target_include_directories(test_device_readonly PRIVATE
    ${CMAKE_SOURCE_DIR}/include
)
add_test(NAME test_device_readonly COMMAND test_device_readonly)
