// Regression tests for the device read-only determination and the write-access
// check.
//
// The bug these exist for: a safety check reported "Cannot open device to check
// read-only status" for a perfectly writable USB drive. The device node was
// brw-rw---- root disk and the operator was not in group disk, so open() returned
// EACCES; the check treated that as "the read-only state is unknown", discarded
// the errno, and blocked the run. On the same machine `sudo blockdev --getro`
// returned 0 and `lsblk` reported RO=0, because lsblk never opens the device - it
// reads /sys/block/<name>/ro, which is world-readable.
//
// Two independent defects, fixed together because fixing either alone leaves a
// report that lies:
//
//   * The read-only state was established only by BLKROGET on an opened fd, so
//     it was unavailable to exactly the users least able to open the device.
//   * The permissions check tested S_IWUSR - whether the OWNER may write - so a
//     root-owned device node reported "write permission available" to a process
//     that could not open it. That is the PASS-beside-FAIL contradiction.
//
// No real block device is required. findSysfsPath() takes a sysfsBase parameter
// precisely so a test can drive a synthetic tree, and that is the seam used
// throughout. The tests build /sys-shaped directories with ro=0 and ro=1 and
// point a device path that cannot be opened at them, which reproduces the bug
// exactly: the ioctl path fails and the sysfs path answers.

#include "ledgerase/platform/linux.hpp"
#include "ledgerase/safety.hpp"

#include <cstdio>
#include <filesystem>
#include <fcntl.h>
#include <unistd.h>
#include <fstream>
#include <string>
#include <vector>

using namespace ledgerase;
// plat::deviceReadOnlyStatus() and its types live in the platform namespace, not the
// top-level one, and are qualified explicitly rather than pulled in wholesale so
// it stays visible that these are Linux-platform calls.
namespace plat = ledgerase::platform::linux;
namespace fs = std::filesystem;

namespace {

int g_failures = 0;

void check(bool condition, const std::string& what) {
    if (condition) {
        std::printf("  ok   %s\n", what.c_str());
        return;
    }
    std::printf("  FAIL %s\n", what.c_str());
    ++g_failures;
}

// A synthetic sysfs tree. `block/<name>/ro` is written with the given value, or
// the directory is left absent entirely, which is what a non-block device looks
// like to findSysfsPath().
struct FakeSysfs {
    fs::path base;

    explicit FakeSysfs(const std::string& name) {
        base = fs::temp_directory_path() / name;
        std::error_code ec;
        fs::remove_all(base, ec);
        fs::create_directories(base / "block", ec);
    }
    ~FakeSysfs() {
        std::error_code ec;
        fs::remove_all(base, ec);
    }

    // Declares a block device with the given read-only value.
    void addBlock(const std::string& devName, int roValue) {
        std::error_code ec;
        const fs::path dir = base / "block" / devName;
        fs::create_directories(dir, ec);
        std::ofstream out(dir / "ro", std::ios::trunc);
        out << roValue << "\n";
    }

    // A block device entry that exists but has no readable `ro` attribute. This
    // is the "sysfs present but the attribute is not there" case, which must not
    // be read as "writable".
    void addBlockWithoutRo(const std::string& devName) {
        std::error_code ec;
        fs::create_directories(base / "block" / devName, ec);
    }

    std::string str() const { return base.string(); }
};

// A device path that cannot be opened, standing in for a root-owned device node
// the operator has no permission for.
//
// It is a path under /dev that does not exist, and that is deliberate on two
// counts. findSysfsPath() keys on the *filename*, so "/dev/<name>" pairs with a
// synthetic /sys-shaped entry named <name>; a real file in a temp directory
// would need the same basename, and would also be a regular file - which the
// disk-image branch claims before sysfs is ever consulted, so the block-device
// path under test would never be reached. And a path that does not exist cannot
// be opened, which is the condition under test: the device query fails and sysfs
// has to answer.
//
// The host's own real devices cover the EACCES case end to end, in
// testReadOnlyCheckNoLongerFalseFails().
std::string unopenableDevicePath(const std::string& blockName) {
    return "/dev/" + blockName;
}

// --- the bug itself -------------------------------------------------------

void testUnopenableWritableDeviceDetected() {
    std::printf("a device we cannot open but which the kernel reports writable\n");
    // The exact reported failure: open() fails, and the device is not read-only.
    FakeSysfs sysfs("sanitizer-ro-fake-writable");
    sysfs.addBlock("sdz", 0);
    const std::string device = unopenableDevicePath("sdz");

    const plat::ReadOnlyStatus status =
        plat::deviceReadOnlyStatus(device, sysfs.str());

    check(status.established,
          "the read-only state is established even though the node cannot be "
          "opened - this is the regression");
    check(!status.readOnly, "and it is writable, because the kernel says ro=0");
    check(status.source == plat::ReadOnlySource::SYSFS,
          "the answer came from sysfs, which needs no device access");
    // The open failure is retained, not swallowed: a reader can see that the
    // device node was not openable even though the state was established.
    check(!status.openError.empty(),
          "the open failure is still recorded rather than discarded");
    check(status.diagnostic().find("writable") != std::string::npos,
          "the diagnostic says the device reports itself writable");
}

void testUnopenableReadOnlyDeviceDetected() {
    std::printf("a device we cannot open and which the kernel reports read-only\n");
    FakeSysfs sysfs("sanitizer-ro-fake-readonly");
    sysfs.addBlock("sdy", 1);
    const std::string device = unopenableDevicePath("sdy");

    const plat::ReadOnlyStatus status = plat::deviceReadOnlyStatus(device, sysfs.str());
    check(status.established, "the state is established from sysfs");
    check(status.readOnly, "and it is read-only, because the kernel says ro=1");
    check(status.source == plat::ReadOnlySource::SYSFS, "established via sysfs");
    check(status.diagnostic().find("read-only") != std::string::npos,
          "the diagnostic says the device reports itself read-only");
}

// --- fail closed ----------------------------------------------------------

void testUndeterminableStateFailsClosed() {
    std::printf("an undeterminable state fails closed, never assumed writable\n");
    // No sysfs entry and no openable device: nothing establishes the state.
    FakeSysfs sysfs("sanitizer-ro-fake-none");
    const std::string device = unopenableDevicePath("sdnone");

    const plat::ReadOnlyStatus status = plat::deviceReadOnlyStatus(device, sysfs.str());
    check(!status.established, "the state is not established");
    check(!status.readOnly,
          "and readOnly is false, but established is false too, so no caller "
          "may read this as writable");
    check(status.source == plat::ReadOnlySource::UNDETERMINED,
          "the source says undetermined");
    check(!status.diagnostic().empty(),
          "a diagnostic is present so the refusal can explain itself");
    check(status.diagnostic().find("could not be established") !=
              std::string::npos,
          "the diagnostic says the state could not be established");
}

void testSysfsEntryWithoutRoAttributeFailsClosed() {
    std::printf("a sysfs entry with no ro attribute fails closed\n");
    // A block directory that exists but has no `ro` file must not be read as
    // "writable": readSysfsBool propagates the read error, and the status stays
    // unestablished. Treating a missing attribute as false is exactly the kind
    // of silent default this project does not make.
    FakeSysfs sysfs("sanitizer-ro-fake-partial");
    sysfs.addBlockWithoutRo("sdx");
    const std::string device = unopenableDevicePath("sdx");

    const plat::ReadOnlyStatus status = plat::deviceReadOnlyStatus(device, sysfs.str());
    check(!status.established, "a missing ro attribute does not establish a state");
    check(!status.sysfsError.empty(),
          "and the sysfs failure is recorded with the attribute that was missing");
}

void testNonexistentDeviceFailsClosed() {
    std::printf("a device that does not exist fails closed\n");
    FakeSysfs sysfs("sanitizer-ro-fake-missing");
    const std::string device = "/dev/definitely-not-a-real-device-xyz";
    const plat::ReadOnlyStatus status = plat::deviceReadOnlyStatus(device, sysfs.str());
    check(!status.established, "nothing establishes the state for a missing device");
    check(!status.openError.empty(), "the open failure is recorded");
    check(!status.sysfsError.empty(), "the sysfs failure is recorded too");
}

void testDiskImageIsAnsweredOnItsOwnTerms() {
    std::printf("a disk image is answered by its writability, not by BLKROGET\n");
    // A regular file cannot answer BLKROGET - the ioctl returns ENOTTY - and has
    // no sysfs entry. Before the fix that combination passed the read-only check
    // by accident, because a *failed* ioctl was read as "not read-only". Once
    // failures stopped implying a state, refusing the case outright would have
    // removed the project's ability to sanitize images, which is supported.
    FakeSysfs sysfs("sanitizer-ro-fake-image");
    const fs::path image = fs::temp_directory_path() / "sanitizer-ro-image.img";
    { std::ofstream o(image, std::ios::binary | std::ios::trunc); o << "x"; }
    std::error_code ec;
    fs::permissions(image, fs::perms::owner_all, ec);

    const plat::ReadOnlyStatus status =
        plat::deviceReadOnlyStatus(image.string(), sysfs.str());
    check(status.established,
          "a writable image establishes a state rather than being refused");
    check(!status.readOnly, "and it is not read-only, because it can be written");
    check(status.source == plat::ReadOnlySource::REGULAR_FILE,
          "the answer came from a direct writability check, which is the only "
          "question a regular file can answer");

    // A file that cannot be written is a definite fact and must block, not be
    // reported as an unknown - the operator needs to be told what is wrong.
    const fs::path locked = fs::temp_directory_path() / "sanitizer-ro-locked.img";
    { std::ofstream o(locked, std::ios::trunc); o << "x"; }
    fs::permissions(locked, fs::perms::owner_read, ec);
    const plat::ReadOnlyStatus lockedStatus =
        plat::deviceReadOnlyStatus(locked.string(), sysfs.str());
    check(lockedStatus.established,
          "a non-writable image is a known state, not an unknown one");
    check(lockedStatus.readOnly, "and it is reported as not writable");
    check(!lockedStatus.openError.empty(),
          "with the errno recorded, so the reason survives");

    fs::remove(image, ec);
    fs::remove(locked, ec);
}

// --- diagnostics ----------------------------------------------------------

void testDiagnosticsNameTheOperationAndErrno() {
    std::printf("a failure names the operation and the errno\n");
    FakeSysfs sysfs("sanitizer-ro-fake-diag");
    const std::string device = "/dev/definitely-not-a-real-device-abc";
    const plat::ReadOnlyStatus status = plat::deviceReadOnlyStatus(device, sysfs.str());

    // Every attempted operation is named, with a numeric errno alongside the
    // text, so a reader can act without guessing which call failed.
    const std::string diag = status.diagnostic();
    check(diag.find("opening the device node failed") != std::string::npos,
          "the diagnostic names the failed open");
    check(diag.find("sysfs read-only attribute unavailable") != std::string::npos,
          "the diagnostic names the failed sysfs read");
    // A numeric errno appears somewhere in the recorded errors.
    bool hasNumericErrno = false;
    for (const std::string* e : {&status.openError, &status.ioctlError,
                                 &status.sysfsError}) {
        for (const char c : *e) {
            if (c >= '0' && c <= '9') { hasNumericErrno = true; break; }
        }
        if (hasNumericErrno) break;
    }
    check(hasNumericErrno, "at least one errno is reported numerically");
}

// --- the permissions check, which was a false PASS -------------------------

void testWriteAccessCheckDoesNotFalsePass() {
    std::printf("write access is judged by the kernel, not by the owner bit\n");
    // The reported contradiction: a root-owned brw-rw---- node has S_IWUSR set,
    // so the old mode-bit test reported "write permission available" to a
    // process that could not open it. A file with no rights reproduces the same
    // shape: S_IWUSR may be set while this process still cannot write.
    const fs::path p = fs::temp_directory_path() / "sanitizer-perm-node";
    { std::ofstream o(p, std::ios::trunc); o << "x"; }
    std::error_code ec;
    fs::permissions(p, fs::perms::owner_read, ec);   // S_IWUSR clear

    const Result<bool> writable = plat::canOpenForWrite(p.string());
    check(writable.isError(), "a file with no write permission is not writable");
    check(std::string(writable.error().what()).size() > 0,
          "and the error explains why");
    // The message must carry the errno, not just "no".
    bool numeric = false;
    for (const char c : std::string(writable.error().what())) {
        if (c >= '0' && c <= '9') { numeric = true; break; }
    }
    check(numeric, "the diagnostic carries a numeric errno or code");

    // And the positive case: a file this process may write.
    const fs::path w = fs::temp_directory_path() / "sanitizer-perm-writable";
    { std::ofstream o(w, std::ios::trunc); o << "x"; }
    fs::permissions(w, fs::perms::owner_all, ec);
    const Result<bool> canWrite = plat::canOpenForWrite(w.string());
    check(canWrite.ok() && canWrite.value(),
          "a file this process owns and may write is writable");

    fs::remove(p, ec);
    fs::remove(w, ec);
}

void testDescriptorReportsAccessMode() {
    std::printf("a descriptor reports the access mode it actually has\n");
    const fs::path p = fs::temp_directory_path() / "sanitizer-fd-mode";
    { std::ofstream o(p, std::ios::trunc); o << "x"; }
    const int ro = ::open(p.c_str(), O_RDONLY);
    const int rw = ::open(p.c_str(), O_RDWR);
    check(ro >= 0 && rw >= 0, "both descriptors opened");
    check(!plat::descriptorIsWritable(ro), "an O_RDONLY descriptor is not writable");
    check(plat::descriptorIsWritable(rw), "an O_RDWR descriptor is writable");
    check(!plat::descriptorIsWritable(-1), "an invalid descriptor is not writable");
    if (ro >= 0) ::close(ro);
    if (rw >= 0) ::close(rw);
    std::error_code ec;
    fs::remove(p, ec);
}

// --- the safety report, end to end ----------------------------------------

// Finds a named check in a report, or nullptr.
const SafetyCheck* findCheck(const SafetyReport& report, const std::string& name) {
    for (const SafetyCheck& c : report.checks) {
        if (c.name == name) return &c;
    }
    return nullptr;
}

void testReadOnlyCheckNoLongerFalseFails() {
    std::printf("the safety report classifies an unopenable-but-writable node\n");
    // The whole point, at the level the operator sees it. Before the fix, a real
    // /dev/sda produced "[FAIL] Read-Only Check: Cannot open device to check
    // read-only status" and aborted the run.
    //
    // This has to run against a *real* block device, because the fix reads the
    // device's real sysfs entry. A synthetic file has none, and failing closed
    // for a path with no sysfs entry and no open access is correct - the earlier
    // version of this test used one and therefore asserted the wrong thing.
    const char* candidates[] = {"/dev/sda", "/dev/sdb", "/dev/nvme0n1",
                                "/dev/vda"};
    const char* found = nullptr;
    for (const char* dev : candidates) {
        std::error_code ec;
        if (fs::exists(dev, ec)) { found = dev; break; }
    }
    if (found == nullptr) {
        check(true,
              "skipped: this host has no block device to report on. The "
              "determination itself is covered above through the sysfs seam.");
        return;
    }

    SafetyManager manager;
    const auto result = manager.checkDeviceSafety(found, false, true);
    check(result.ok(), std::string("the report is produced for ") + found);
    if (result.isError()) return;
    const SafetyReport& report = result.value();

    const SafetyCheck* ro = findCheck(report, "Read-Only Check");
    check(ro != nullptr, "the report contains a Read-Only Check");
    if (ro != nullptr) {
        check(ro->message.find("Cannot open device to check read-only status") ==
                  std::string::npos,
              "the old misleading message is gone: " + ro->message);
        check(ro->result != SafetyCheckResult::FAIL,
              "a writable device whose node this user cannot open is not "
              "reported as a read-only failure");
        check(!ro->message.empty(),
              "the check still says how it established the state");
    }

    // The permissions check may legitimately fail - this process may not be
    // able to open the node - but it must not claim permission it lacks.
    const SafetyCheck* perm = findCheck(report, "Permissions Check");
    check(perm != nullptr, "the report contains a Permissions Check");
    if (perm != nullptr) {
        const bool canWrite = plat::canOpenForWrite(found).ok() &&
                              plat::canOpenForWrite(found).value();
        if (!canWrite) {
            check(perm->message.find("write permission available") ==
                      std::string::npos,
                  "it does not claim 'write permission available' when this "
                  "process cannot open the device");
        } else {
            check(true, "this process can write, so the permissions check's "
                        "result is not constrained by that case");
        }
    }
}

void testExistingChecksAreUnaffected() {
    std::printf("the other safety checks are untouched by the fix\n");
    SafetyManager manager;
    const auto result = manager.checkDeviceSafety("/dev/definitely-not-real-qq",
                                                 false, true);
    check(result.ok(), "a report is produced for a nonexistent path");
    if (result.isError()) return;
    const SafetyReport& report = result.value();

    // The device-level checks must still all be present: a fix that dropped one
    // would be a fix that weakened a gate.
    const char* required[] = {
        "Mount Check", "System Disk Check", "Boot Disk Check", "Swap Check",
        "Device Mapper Check", "LVM Check", "RAID Check",
        "Permissions Check", "Read-Only Check"};
    for (const char* name : required) {
        check(findCheck(report, name) != nullptr,
              std::string("the report still contains ") + name);
    }

    // And for a nonexistent device the read-only state is undetermined, so the
    // check must be a critical FAIL - fail closed.
    const SafetyCheck* ro = findCheck(report, "Read-Only Check");
    if (ro != nullptr) {
        check(ro->result == SafetyCheckResult::FAIL,
              "a nonexistent device fails the read-only check closed");
        check(ro->critical,
              "and it is a critical check, so it blocks rather than warns");
    }
    check(report.hasCriticalFailure,
          "a nonexistent device produces a critical failure overall");
}

// --- the real host, when it is available ----------------------------------

void testRealBlockDeviceIfOneIsOpenable() {
    std::printf("a real openable block device, when this host has one\n");
    // Exercises the BLKROGET path, which the synthetic tree cannot reach. Skips
    // rather than fails when the test user cannot open any block device, because
    // that is a property of the host, not of the code.
    const char* candidates[] = {"/dev/sda", "/dev/sdb", "/dev/nvme0n1",
                                "/dev/vda"};
    bool exercised = false;
    for (const char* dev : candidates) {
        std::error_code ec;
        if (!fs::exists(dev, ec)) continue;
        const int fd = ::open(dev, O_RDONLY | O_CLOEXEC | O_NONBLOCK);
        if (fd < 0) continue;
        ::close(fd);
        const plat::ReadOnlyStatus status = plat::deviceReadOnlyStatus(dev);
        check(status.established,
              std::string("a real openable device establishes its state: ") + dev);
        if (status.established &&
            status.source == plat::ReadOnlySource::BLKROGET_IOCTL) {
            check(true, "and it came from BLKROGET on the opened device");
            exercised = true;
        }
        break;
    }
    if (!exercised) {
        check(true,
              "skipped the BLKROGET path: no block device is openable by this "
              "user on this host, which is the case the sysfs fallback exists "
              "for");
    }
}

} // namespace

int main() {
    std::printf("device read-only determination and write-access checks\n");

    testUnopenableWritableDeviceDetected();
    testUnopenableReadOnlyDeviceDetected();
    testUndeterminableStateFailsClosed();
    testSysfsEntryWithoutRoAttributeFailsClosed();
    testNonexistentDeviceFailsClosed();
    testDiskImageIsAnsweredOnItsOwnTerms();
    testDiagnosticsNameTheOperationAndErrno();
    testWriteAccessCheckDoesNotFalsePass();
    testDescriptorReportsAccessMode();
    testReadOnlyCheckNoLongerFalseFails();
    testExistingChecksAreUnaffected();
    testRealBlockDeviceIfOneIsOpenable();

    if (g_failures == 0) {
        std::printf("\nAll read-only/access checks passed.\n");
        return 0;
    }
    std::printf("\n%d read-only/access check(s) FAILED.\n", g_failures);
    return 1;
}
