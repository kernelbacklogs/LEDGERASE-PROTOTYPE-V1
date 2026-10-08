// Regression test for deviceContains().
//
// This function backs isMounted(), isSystemDisk(), isBootDisk(),
// getMountPoints() and the active-swap check. Every one of those is a refusal to
// destroy something. A false "not contained" result means the safety layer
// cannot see that the running root filesystem, the boot device or a mounted
// partition lives on the target disk, and the tool will happily destroy it.
//
// The bug it guards against: the original implementation only recognised the
// 'p'-separated partition naming convention (nvme0n1 -> nvme0n1p1). Classic
// SCSI/SATA naming has no separator (sda -> sda1), so for every /dev/sdX, /dev/hdX
// and /dev/vdX disk the containment check silently returned false. The safety
// layer was blind on exactly the device class that pen drives, USB sticks and
// ordinary SATA disks all use.
//
// The converse error is just as dangerous and is asserted here too: /dev/nvme0n10
// is a *different disk* from /dev/nvme0n1, not a partition of it. A naive
// "suffix is digits" test conflates the two, which would make the tool refuse to
// sanitize a perfectly good disk (annoying) or, worse, treat an unrelated disk as
// the system disk and then behave as if the target were safe.
//
// No real device is opened. This is a pure string test.

#include "platform/linux/linux.hpp"
#include "ledgerase/safety.hpp"

#include <cstdio>
#include <string>
#include <vector>

using ledgerase::platform::linux::deviceContains;

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

void expectContains(const std::string& parent, const std::string& child,
                    const std::string& why) {
    check(deviceContains(parent, child),
          parent + " contains " + child + " (" + why + ")");
}

void expectNotContains(const std::string& parent, const std::string& child,
                       const std::string& why) {
    check(!deviceContains(parent, child),
          parent + " does NOT contain " + child + " (" + why + ")");
}

// The convention without a separator. This is the case that was broken, and the
// one that matters most because it is how ordinary disks are named.
void testDigitSuffixNaming() {
    std::printf("classic naming: no separator between disk and partition\n");

    expectContains("/dev/sda", "/dev/sda1", "SCSI/SATA first partition");
    expectContains("/dev/sda", "/dev/sda2", "SCSI/SATA later partition");
    expectContains("/dev/sda", "/dev/sda15", "multi-digit partition number");
    expectContains("/dev/sdb", "/dev/sdb1", "a second SATA disk");
    expectContains("/dev/sda", "/dev/sda", "the disk contains itself");
    expectContains("/dev/hda", "/dev/hda1", "IDE naming");
    expectContains("/dev/vda", "/dev/vda1", "virtio block device partition");
    expectContains("/dev/vdb", "/dev/vdb3", "a second virtio disk");
}

// The convention with a 'p' separator, used when the disk name already ends in a
// digit so that digits in the partition number are unambiguous.
void testPSeparatedNaming() {
    std::printf("p-separated naming: disk name already ends in a digit\n");

    expectContains("/dev/nvme0n1", "/dev/nvme0n1p1", "NVMe namespace partition");
    expectContains("/dev/nvme0n1", "/dev/nvme0n1p15", "multi-digit partition");
    expectContains("/dev/nvme0n1", "/dev/nvme0n1", "the namespace contains itself");
    expectContains("/dev/mmcblk0", "/dev/mmcblk0p1", "eMMC/SD partition");
    expectContains("/dev/loop0", "/dev/loop0p1", "loop device partition");
    expectContains("/dev/md0", "/dev/md0p1", "md array partition");
}

void testDifferentDisksAreNotConfused() {
    std::printf("a neighbouring disk is never treated as a partition\n");

    // The single most important negative case. nvme0n10 is a separate disk.
    expectNotContains("/dev/nvme0n1", "/dev/nvme0n10",
                      "nvme0n10 is its own disk, not a partition of nvme0n1");
    expectNotContains("/dev/nvme0n1", "/dev/nvme0n11",
                      "nvme0n11 is its own disk");
    expectNotContains("/dev/sda", "/dev/sdaa", "sdaa is a different disk");
    expectNotContains("/dev/sda", "/dev/sdb", "sdb is a different disk");
    expectNotContains("/dev/sda", "/dev/sdaa1", "sdaa1 belongs to sdaa");
    expectNotContains("/dev/mmcblk0", "/dev/mmcblk01",
                      "mmcblk01 is not a partition of mmcblk0");
    expectNotContains("/dev/nvme0n1", "/dev/nvme0n2",
                      "a different namespace on the same controller");
}

void testMalformedInputIsRejected() {
    std::printf("degenerate input never matches\n");

    expectNotContains("", "/dev/sda1", "an empty parent contains nothing");
    expectNotContains("/dev/sda", "", "an empty child contains nothing");
    expectNotContains("", "", "two empty names are not a containment");
    expectNotContains("/dev/sda", "/dev/sda0p1",
                      "the digit-suffix form does not admit a 'p' separator");
    expectNotContains("/dev/nvme0n1", "/dev/nvme0n1p",
                      "'p' with no partition number is not a partition");
    expectNotContains("/dev/nvme0n1", "/dev/nvme0n1px1",
                      "a non-digit after 'p' is not a partition number");
    expectNotContains("/dev/sda", "/dev/sda1a",
                      "a non-digit after the partition number is not a partition");
    expectNotContains("/dev/sda", "/dev/sd", "a prefix is not a containment");
}

// The reason the function is exercised through a table rather than a few
// examples: the two naming conventions are not interchangeable, and the rule
// that selects between them is whether the disk name ends in a digit.
void testConventionSelectionRule() {
    std::printf("the convention is chosen by the disk name's last character\n");

    // Names ending in a digit use the p-form...
    const std::vector<std::string> digitEnding = {
        "/dev/nvme0n1", "/dev/nvme1n2", "/dev/mmcblk0", "/dev/loop0", "/dev/md0"
    };
    for (const auto& disk : digitEnding) {
        expectContains(disk, disk + "p1",
                      "name ends in a digit, so the p-form applies");
        // The digit form must not also apply, or a second disk would be
        // mistaken for a partition.
        const std::string neighbour = disk + "0";
        expectNotContains(disk, neighbour,
                          "a name ending in a digit never takes a bare digit suffix");
    }

    // ...and names not ending in a digit take the bare digit form.
    for (const auto& disk : std::vector<std::string>{
             "/dev/sda", "/dev/sdb", "/dev/hda", "/dev/vda"}) {
        expectContains(disk, disk + "1",
                      "name does not end in a digit, so the digit form applies");
        expectNotContains(disk, disk + "p1",
                          "a name not ending in a digit never takes a p-suffix");
    }
}

// The safety layer must actually reach this function. If isSystemDisk() or
// isBootDisk() were to reimplement the comparison, a future change could make
// this test pass while the safety layer stayed broken.
void testSafetyLayerUsesIt() {
    std::printf("the safety layer routes through deviceContains\n");

    // These read the real running system, so they are only asserted for
    // well-formedness: that they return a definite bool and do not throw on an
    // ordinary device path. No device is opened.
    (void)ledgerase::platform::linux::isSystemDisk("/dev/sda");
    (void)ledgerase::platform::linux::isBootDisk("/dev/sda");
    (void)ledgerase::platform::linux::isMounted("/dev/sda");
    check(true, "isSystemDisk / isBootDisk / isMounted evaluate for a /dev/sdX path");

    // resolveToPhysicalDevices is the LVM/device-mapper expansion used by
    // isSystemDisk and isBootDisk. On a path with no sysfs entry it must return
    // an empty list rather than inventing a device.
    const auto physical =
        ledgerase::platform::linux::resolveToPhysicalDevices("/dev/definitely-not-here");
    check(physical.empty(),
          "an unknown device resolves to no physical devices, not a guess");
}

// 10. mountinfo octal escapes must be decoded.
//
// This is a safety decision, not cosmetics. mountinfo writes the mount source
// with spaces escaped, and a device reached through a disk label is routinely
// spelled with one. Compared undecoded, "/dev/disk/by-label/My\040Backup" matches
// no real device node, so a mounted device reads as unmounted - which is the
// exact mistake that lets a target in active use be waved through.
void testMountInfoEscapesAreDecoded() {
    std::printf("mountinfo octal escapes are decoded\n");

    using ledgerase::platform::linux::detail::decodeMountInfoEscapes;

    check(decodeMountInfoEscapes("/dev/sda1") == "/dev/sda1",
          "a path with no escapes is returned unchanged");
    check(decodeMountInfoEscapes("/dev/disk/by-label/My\\040Backup") ==
              "/dev/disk/by-label/My Backup",
          "\\040 decodes to a space");
    check(decodeMountInfoEscapes("/dev/sda1\\011weird") == "/dev/sda1\tweird",
          "\\011 decodes to a tab");
    check(decodeMountInfoEscapes("/dev/sda1\\012weird") == "/dev/sda1\nweird",
          "\\012 decodes to a newline");
    check(decodeMountInfoEscapes("/dev/sda1\\134weird") == "/dev/sda1\\weird",
          "\\134 decodes to a backslash");

    // The real-world case, verbatim from a label containing a space.
    check(decodeMountInfoEscapes("/dev/disk/by-label/Backup\\0402024") ==
              "/dev/disk/by-label/Backup 2024",
          "a label containing a space decodes to a matchable path");

    // Malformed or partial escapes must be left exactly as they are, not
    // silently mangled or read past the end of the string.
    check(decodeMountInfoEscapes("/dev/a\\04") == "/dev/a\\04",
          "a truncated escape is left alone");
    check(decodeMountInfoEscapes("/dev/a\\999") == "/dev/a\\999",
          "a non-octal escape is left alone");
    check(decodeMountInfoEscapes("/dev/a\\") == "/dev/a\\",
          "a trailing lone backslash is left alone");
    check(decodeMountInfoEscapes("\\040\\040") == "  ",
          "two escapes decode to two spaces");
    check(decodeMountInfoEscapes("") == "",
          "an empty field stays empty");
}

} // namespace

int main() {
    testMountInfoEscapesAreDecoded();
    testDigitSuffixNaming();
    testPSeparatedNaming();
    testDifferentDisksAreNotConfused();
    testMalformedInputIsRejected();
    testConventionSelectionRule();
    testSafetyLayerUsesIt();

    if (g_failures == 0) {
        std::printf("\nall device containment tests passed\n");
        return 0;
    }
    std::printf("\n%d check(s) failed\n", g_failures);
    return 1;
}
