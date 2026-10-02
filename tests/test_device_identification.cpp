// Tests for device identification and capability reporting, driven by a fake
// sysfs tree so they run on any machine without touching real hardware.
//
// The cases here correspond to real defects found on a USB pen drive:
//
//   1. A USB mass-storage device has no "transport" attribute and does not
//      match any of the bus path patterns, so it was classified as UNKNOWN.
//   2. A USB bridge reports queue/rotational = 1 regardless of the media, so
//      the pen drive was classified as an HDD.
//   3. Consequently the capability detector reported no usable technique at
//      all, because host techniques were only established for identified
//      transports.

#include "ledgerase/device.hpp"
#include "ledgerase/capability.hpp"
#include "ledgerase/types.hpp"
#include "ledgerase/error.hpp"
#include "ledgerase/policy.hpp"

#include <cstdio>
#include <filesystem>
#include <fstream>
#include <string>

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

void writeFile(const fs::path& path, const std::string& contents) {
    fs::create_directories(path.parent_path());
    std::ofstream out(path);
    out << contents;
}


// A fake sysfs tree that mirrors the real kernel layout.
//
// This matters: /sys/block/<name> is a symlink whose target is the resolved
// device directory, and the bus directories are ANCESTORS of that target, not
// children of it. A tree built the other way round would let a test pass for
// the wrong reason, which is worse than having no test.
//
//   <base>/usb1/1-2/1-2:1.0/host2/target2:0:0/2:0:0:0/block/sda   <- /sys/block/sda
//   <base>/usb1/1-2                                            <- USB device node
//
// sysBlockPath() returns the symlink that stands in for /sys/block/sda, because
// that is what the kernel hands the tool and what identifyTransport resolves.
struct FakeSysfs {
    fs::path base;
    fs::path blockLink;   // stands in for /sys/block/<name>

    explicit FakeSysfs(const std::string& name) {
        base = fs::temp_directory_path() / ("sanitizer-sysfs-" + name);
        std::error_code ec;
        fs::remove_all(base, ec);
        fs::create_directories(base);
        blockLink = base / "sys-block";
    }

    ~FakeSysfs() {
        std::error_code ec;
        fs::remove_all(base, ec);
    }

    const std::string sysBlockPath() const { return blockLink.string(); }

    // Whole-disk attributes the inspector reads from /sys/block/<name>.
    void baseDisk(uint64_t sectors, bool rotational, bool removable) {
        const fs::path dev = blockLink;
        writeFile(dev / "size", std::to_string(sectors));
        writeFile(dev / "queue" / "logical_block_size", "512");
        writeFile(dev / "queue" / "physical_block_size", "512");
        writeFile(dev / "queue" / "rotational", rotational ? "1" : "0");
        writeFile(dev / "removable", removable ? "1" : "0");
        writeFile(dev / "ro", "0");
    }

    // A pen drive: USB device node two levels above the SCSI target, no
    // "transport" attribute anywhere, and the bridge reporting rotational=1.
    void usbTopology(bool rotationalFlag, bool removableFlag) {
        const fs::path usbNode = base / "usb1" / "1-2";
        writeFile(usbNode / "idVendor", "0781");
        writeFile(usbNode / "idProduct", "5567");

        const fs::path scsiTarget =
            usbNode / "1-2:1.0" / "host2" / "target2:0:0" / "2:0:0:0";
        const fs::path blockDev = scsiTarget / "block" / "sda";
        fs::create_directories(blockDev);

        std::error_code ec;
        fs::create_directory_symlink(blockDev, blockLink, ec);
        // /sys/block/sda/device points at the SCSI target, as on a real system.
        fs::create_directory_symlink(scsiTarget, blockLink / "device", ec);

        baseDisk(15728640, rotationalFlag, removableFlag);
        writeFile(scsiTarget / "vendor", "Kingston");
        writeFile(scsiTarget / "model", "DataTraveler 2.0");
    }

    // NVMe: the bus directory is an ancestor of the resolved block path.
    void nvmeTopology() {
        const fs::path nvme = base / "nvme" / "nvme0" / "n1";
        fs::create_directories(nvme);

        std::error_code ec;
        fs::create_directory_symlink(nvme, blockLink, ec);
        fs::create_directory_symlink(nvme, blockLink / "device", ec);

        baseDisk(976773168, false, false);
        writeFile(nvme / "model", "WDC PC SN530");
        writeFile(nvme / "serial", "22166D800265");
    }

    // SATA behind libata, with an authoritative transport attribute.
    void sataTopology() {
        const fs::path sata = base / "ata1" / "host0" / "target0:0:0" / "0:0:0:0";
        fs::create_directories(sata);

        std::error_code ec;
        fs::create_directory_symlink(sata, blockLink, ec);
        fs::create_directory_symlink(sata, blockLink / "device", ec);

        baseDisk(1953525168, false, false);
        writeFile(sata / "transport", "sata");
        writeFile(sata / "model", "SOME SATA DISK");
    }
};

// Drives the inspector against the fake tree. inspectFromSysfs() is the entry
// point used here precisely because it does not require a real /dev node: what
// is under test is the transport and media-type derivation, not device-node
// validation.
ledgerase::DeviceInfo inspectFake(const FakeSysfs& fake) {
    ledgerase::DeviceManager manager;
    ledgerase::DeviceInspector inspector(manager);
    auto result = inspector.inspectFromSysfs(fake.sysBlockPath());
    return result.ok() ? result.value() : ledgerase::DeviceInfo();
}

void testUsbTransportDetection() {
    std::printf("USB mass storage is identified as USB\n");

    FakeSysfs usb("usb");
    usb.usbTopology(/*rotationalFlag=*/true, /*removableFlag=*/true);

    // Guard the premise: if a transport attribute existed, the test would pass
    // through the pre-existing SCSI path and prove nothing about this fix.
    check(!fs::exists(usb.sysBlockPath() + "/device/transport"),
          "premise: the USB device has no transport attribute");
    check(fs::exists(usb.base.string() + "/usb1/1-2/idVendor"),
          "premise: the USB device node is reachable above the SCSI target");

    const auto info = inspectFake(usb);
    check(info.transport == ledgerase::TransportType::USB,
          "a USB pen drive reports transport USB, not Unknown");
}

void testUsbIsNotReportedAsHdd() {
    std::printf("a USB bridge's rotational flag does not make it an HDD\n");

    FakeSysfs usb("usb-hdd");
    // The kernel claims rotational=1 and removable=1, as a real pen drive does.
    usb.usbTopology(/*rotationalFlag=*/true, /*removableFlag=*/true);

    const auto info = inspectFake(usb);
    check(info.mediaType != ledgerase::MediaType::HDD,
          "the pen drive is not classified as an HDD");
    check(info.mediaType == ledgerase::MediaType::REMOVABLE,
          "the pen drive is classified as removable media");

    // A non-removable USB device reporting rotational=1 is genuinely likely to
    // be a spinning disk, and is allowed to say so.
    FakeSysfs hdd("usb-hdd2");
    hdd.usbTopology(/*rotationalFlag=*/true, /*removableFlag=*/false);
    const auto spinner = inspectFake(hdd);
    check(spinner.mediaType == ledgerase::MediaType::HDD,
          "a non-removable rotational USB device is an HDD");
}

// The kernel's rotational flag is kept as read, and the disagreement with the
// derived media type is carried separately.
//
// This is the case that produced a confusing row: a flash pen drive reporting
// queue/rotational=1, so ROT said Yes while TYPE said Removable, with nothing to
// reconcile them. The flag is not corrected - an assessor wants what the kernel
// said - and what is added is a statement that it was contradicted.
void testRotationalFlagFlaggedNotCorrected() {
    std::printf("a contradicted rotational flag is flagged, not overwritten\n");

    // The reported case: a USB pen drive, removable, rotational flag = 1.
    FakeSysfs usb("rot-dispute-usb");
    usb.usbTopology(/*rotationalFlag=*/true, /*removableFlag=*/true);
    const auto pen = inspectFake(usb);

    check(pen.rotational,
          "the kernel's rotational flag is still reported as read, not "
          "silently corrected");
    check(pen.mediaType == ledgerase::MediaType::REMOVABLE,
          "and the derived media type still says removable");
    check(pen.rotationalDisputed,
          "the disagreement is carried on the identity, so every display and the "
          "evidence record see the same answer");

    // A genuine spinning disk behind USB: flag agrees with the derived type, so
    // nothing is flagged and the plain value stands.
    FakeSysfs hdd("rot-dispute-hdd");
    hdd.usbTopology(/*rotationalFlag=*/true, /*removableFlag=*/false);
    const auto spinner = inspectFake(hdd);
    check(spinner.mediaType == ledgerase::MediaType::HDD,
          "a non-removable rotational USB device is still an HDD");
    check(!spinner.rotationalDisputed,
          "and its rotational flag is not flagged, because nothing contradicts "
          "it");

    // The flag is only ever disputed when the kernel claims rotational; a
    // non-rotational flash device must never be flagged.
    FakeSysfs flash("rot-dispute-flash");
    flash.usbTopology(/*rotationalFlag=*/false, /*removableFlag=*/true);
    const auto stick = inspectFake(flash);
    check(!stick.rotationalDisputed,
          "a device the kernel calls non-rotational is never flagged");

    // And an NVMe SSD, which reports 0 and is classified independently.
    FakeSysfs nvme("rot-dispute-nvme");
    nvme.nvmeTopology();
    const auto ssd = inspectFake(nvme);
    check(ssd.mediaType == ledgerase::MediaType::SSD, "NVMe is an SSD");
    check(!ssd.rotationalDisputed, "and its rotational flag is not disputed");
}

void testNvmeUnaffected() {
    std::printf("NVMe identification is unchanged\n");

    FakeSysfs nvme("nvme");
    nvme.nvmeTopology();

    const auto info = inspectFake(nvme);
    check(info.transport == ledgerase::TransportType::NVME,
          "NVMe still reports transport NVMe");
    check(info.mediaType == ledgerase::MediaType::SSD,
          "NVMe is still classified as an SSD");
}

void testSataUnaffected() {
    std::printf("SATA identification is unchanged\n");

    FakeSysfs sata("sata");
    sata.sataTopology();

    const auto info = inspectFake(sata);
    check(info.transport == ledgerase::TransportType::SATA,
          "a transport attribute still wins for SATA");
    check(info.mediaType == ledgerase::MediaType::SSD,
          "a non-rotational SATA disk is an SSD");
}

void testHostTechniqueSurvivesUnknownBus() {
    std::printf("host techniques do not depend on identifying the bus\n");

    ledgerase::CapabilityDetector detector;
    ledgerase::DeviceInfo device;
    device.path = "/dev/fake0";
    device.transport = ledgerase::TransportType::UNKNOWN;

    const auto caps = detector.detectCapabilities(device);
    check(caps.ok(), "capability detection succeeds for an unidentified bus");

    if (caps.isError()) return;

    check(caps.value().overwriteHost == ledgerase::CapabilityStatus::SUPPORTED,
          "a host overwrite is still reported as available");
    check(caps.value().cryptoEraseHost == ledgerase::CapabilityStatus::UNSUPPORTED,
          "host crypto erase stays unsupported; it is not implemented");
    check(caps.value().nvmeCryptoErase == ledgerase::CapabilityStatus::UNKNOWN,
          "device-level NVMe capability stays UNKNOWN for an unidentified bus");
    check(caps.value().ataSecureErase == ledgerase::CapabilityStatus::UNKNOWN,
          "device-level ATA capability stays UNKNOWN for an unidentified bus");

    // The set is queried by ID. A capability that is UNKNOWN with no recorded
    // reason is indistinguishable from a bug, and the detail attached to the
    // entry is what names the transport.
    check(caps.value().limitations.contains(
              ledgerase::LimitationId::CAPABILITY_UNKNOWN),
          "the unknown bus is explained as a limitation");
    bool namesTransport = false;
    for (const std::string& limitation : caps.value().limitations.texts()) {
        if (limitation.find("transport:") != std::string::npos) {
            namesTransport = true;
        }
    }
    check(namesTransport, "the limitation detail names the unrecognised transport");
}

void testUnidentifiedBusStillPlansClear() {
    std::printf("a CLEAR plan is reachable even on an unidentified bus\n");

    ledgerase::SanitizationPolicyEngine engine(
        ledgerase::SanitizationPolicyEngine::createDefaultPolicy());
    ledgerase::DeviceInfo device;
    device.path = "/dev/fake0";
    device.model = "Unidentified Bus Device";
    device.capacityBytes = 8ULL * 1024 * 1024 * 1024;
    device.transport = ledgerase::TransportType::UNKNOWN;
    device.mediaType = ledgerase::MediaType::UNKNOWN;

    ledgerase::CapabilityInfo caps;
    caps.overwriteHost = ledgerase::CapabilityStatus::SUPPORTED;

    const auto plan = engine.createPlan(device, caps, ledgerase::SanitizationCategory::CLEAR, true);
    check(plan.ok(), "a CLEAR plan can be generated");
    if (plan.isError()) return;

    check(plan.value().selectedMethod == ledgerase::SanitizationMethod::OVERWRITE_HOST,
          "the plan selects a host overwrite rather than refusing outright");
    check(!plan.value().alternativesConsidered.empty(),
          "the plan records the alternatives it considered");

    // PURGE must still be refused: a host overwrite cannot deliver it.
    const auto purge = engine.createPlan(device, caps, ledgerase::SanitizationCategory::PURGE, true);
    check(purge.isError(), "PURGE is still refused rather than downgraded");
}

} // namespace

int main() {
    testUsbTransportDetection();
    testUsbIsNotReportedAsHdd();
    testRotationalFlagFlaggedNotCorrected();
    testNvmeUnaffected();
    testSataUnaffected();
    testHostTechniqueSurvivesUnknownBus();
    testUnidentifiedBusStillPlansClear();

    if (g_failures == 0) {
        std::printf("\nall device identification tests passed\n");
        return 0;
    }
    std::printf("\n%d check(s) failed\n", g_failures);
    return 1;
}
