#pragma once

#include "ledgerase/types.hpp"
#include "ledgerase/error.hpp"
#include <cstddef>
#include <string>
#include <vector>
#include <sys/types.h>
#include <linux/fs.h>
#include <linux/nvme_ioctl.h>

namespace ledgerase::platform::linux {

// ---------------------------------------------------------------------------
// NVMe admin opcodes
//
// These are defined by the NVMe Base Specification, not exported by
// <linux/nvme_ioctl.h>, which only provides the ioctl plumbing. They live in
// the header rather than in a .cpp file-local block so the tests can assert
// the values this build actually sends.
//
//   Identify     0x06  CNS 0x00/0x01
//   Get Log Page 0x02  the Sanitize Status log is LID 0x81
//   Sanitize     0x84  vendor specific range; 0x0C is Format NVM, not Sanitize
// ---------------------------------------------------------------------------
constexpr uint8_t NVME_ADMIN_IDENTIFY = 0x06;
constexpr uint8_t NVME_ADMIN_GET_LOG_PAGE = 0x02;
constexpr uint8_t NVME_ADMIN_SANITIZE = 0x84;

// Sanitize cdw10 field positions, per the NVMe Base Specification:
//   bits 2:0  SANACT  sanitize action
//   bit  3    AUSE    Allow Unrestricted Sanitize Exit
//   bits 7:4  OWPASS  overwrite pass count (4 bits, 1h..Fh)
// bits 31:8 are reserved.
constexpr uint32_t SANITIZE_SANACT_MASK = 0x07;
constexpr uint32_t SANITIZE_AUSE_BIT = 1u << 3;
constexpr uint32_t SANITIZE_OWPASS_MASK = 0x0F;
constexpr int SANITIZE_OWPASS_SHIFT = 4;
constexpr uint8_t SANITIZE_OWPASS_MIN = 1;
constexpr uint8_t SANITIZE_OWPASS_MAX = 15;

// Get Log Page cdw10/cdw11 field positions:
//   cdw10 bits 7:0   LID   log page identifier
//   cdw10 bits 31:16 NUMDL number of dwords lower (zero-based)
//   cdw11 bits 15:0  NUMDU number of dwords upper (zero-based)
//   cdw11 bits 31:16 Log Specific Identifier, unrelated to the LID
constexpr uint32_t GLPL_NUMDL_SHIFT = 16;
constexpr uint32_t GLPL_NUMDU_MASK = 0xFFFF;
constexpr uint32_t GLPL_LSI_SHIFT = 16;

// Sanitize action codes (Sanitize cdw10 bits 2:0).
constexpr uint8_t SANITIZE_BLOCK_ERASE = 0x01;
constexpr uint8_t SANITIZE_CRYPTO_ERASE = 0x02;
constexpr uint8_t SANITIZE_OVERWRITE = 0x03;

// Sanitize Status log page: LID 0x81, and the result codes in SSTATUS
// (bytes 2-3, little-endian).
constexpr uint16_t NVME_LID_SANITIZE_STATUS = 0x0081;
constexpr uint16_t SANITIZE_STATUS_NOT_STARTED = 0x0000;
constexpr uint16_t SANITIZE_STATUS_IN_PROGRESS = 0x0001;
constexpr uint16_t SANITIZE_STATUS_COMPLETED = 0x0002;
constexpr uint16_t SANITIZE_STATUS_FAILED = 0x000F;

// Sanitize Progress (SPPROG, bytes 0-1) sentinels. 0xFFFF means the controller
// does not report progress and must not be rendered as 0% or 100%.
constexpr uint16_t SANITIZE_PROGRESS_NONE = 0xFFFF;

// ---------------------------------------------------------------------------
// Identify Controller (CNS 0x01)
//
// The field offsets below are load-bearing. The previous hand-written layout in
// this header placed the string fields correctly but everything from
// CNTRLTYPE onwards at the wrong offsets, and two of the mis-placed fields are
// the ones the tool uses to decide whether a sanitize is even possible:
//
//   OACS    (byte 256)  bit 13 = Sanitize command supported
//   SANICAP (byte 328)  per-action sanitize capability bits
//
// The old layout read OACS from byte 128 and SANICAP from byte 220, so both
// answers were unrelated bytes of the controller's data: capability detection
// was deciding "does this drive support Sanitize" from noise.
//
// The layout mirrors the kernel's struct nvme_id_ctrl, and the static_asserts
// below pin every field this tool reads to its specification offset so the
// mapping cannot silently drift again. Those assertions are the reason it is
// safe to change this struct at all.
// ---------------------------------------------------------------------------
struct NvmeIdentifyController {
    uint16_t vid = 0;
    uint16_t ssvid = 0;
    char sn[20] = {0};         // offset 4
    char mn[40] = {0};         // offset 24
    char fr[8] = {0};          // offset 64
    uint8_t rab = 0;           // offset 72
    uint8_t ieee[3] = {0};     // offset 73
    uint8_t cmic = 0;          // offset 76
    uint8_t mdts = 0;          // offset 77
    uint16_t cntlid = 0;       // offset 78
    uint32_t ver = 0;          // offset 80
    uint32_t rtd3r = 0;        // offset 84
    uint32_t rtd3e = 0;        // offset 88
    uint32_t oaes = 0;         // offset 92
    uint32_t ctratt = 0;       // offset 96
    uint16_t rrls = 0;         // offset 100
    uint8_t rsvd102[9] = {0};  // offset 102
    uint8_t cntrltype = 0;     // offset 111
    uint8_t fguid[16] = {0};   // offset 112
    uint16_t crdt1 = 0;        // offset 128
    uint16_t crdt2 = 0;        // offset 130
    uint16_t crdt3 = 0;        // offset 132
    uint8_t rsvd134[122] = {0};// offset 134
    uint16_t oacs = 0;         // offset 256  <-- Sanitize support lives here
    uint8_t acl = 0;           // offset 258
    uint8_t aerl = 0;
    uint8_t frmw = 0;
    uint8_t lpa = 0;
    uint8_t elpe = 0;
    uint8_t npss = 0;
    uint8_t avscc = 0;
    uint8_t apsta = 0;
    uint16_t wctemp = 0;
    uint16_t cctemp = 0;
    uint16_t mtfa = 0;
    uint32_t hmpre = 0;
    uint32_t hmmin = 0;
    uint8_t tnvmcap[16] = {0};
    uint8_t unvmcap[16] = {0};
    uint32_t rpmbs = 0;
    uint16_t edstt = 0;
    uint8_t dsto = 0;
    uint8_t fwug = 0;
    uint16_t kas = 0;
    uint16_t hctma = 0;
    uint16_t mntmt = 0;
    uint16_t mxtmt = 0;
    uint32_t sanicap = 0;      // offset 328  <-- per-action capabilities
    uint32_t hmminds = 0;
    uint16_t hmmaxd = 0;
    uint16_t nvmsetidmax = 0;
    uint16_t endgidmax = 0;
    uint8_t anatt = 0;
    uint8_t anacap = 0;
    uint32_t anagrpmax = 0;
    uint32_t nanagrpid = 0;
    uint8_t rsvd352[160] = {0};
    uint8_t sqes = 0;
    uint8_t cqes = 0;
    uint16_t maxcmd = 0;
    uint32_t nn = 0;
    uint16_t oncs = 0;
    uint16_t fuses = 0;
    uint8_t fna = 0;
    uint8_t vwc = 0;
    uint16_t awun = 0;
    uint16_t awupf = 0;
    uint8_t nvscc = 0;
    uint8_t nwpc = 0;
    uint16_t acwu = 0;
    uint8_t rsvd534[2] = {0};
    uint32_t sgls = 0;
    uint32_t mnan = 0;
    uint8_t rsvd544[224] = {0};
    char subnqn[256] = {0};
};

// Every field the tool reads is pinned to its specification offset. If any of
// these fail to compile the struct no longer matches the wire format and every
// capability decision taken from it is unfounded.
static_assert(offsetof(NvmeIdentifyController, sn) == 4, "NVMe SN must be at byte 4");
static_assert(offsetof(NvmeIdentifyController, mn) == 24, "NVMe MN must be at byte 24");
static_assert(offsetof(NvmeIdentifyController, fr) == 64, "NVMe FR must be at byte 64");
static_assert(offsetof(NvmeIdentifyController, cntrltype) == 111, "NVMe CNTRLTYPE must be at byte 111");
static_assert(offsetof(NvmeIdentifyController, crdt1) == 128, "NVMe CRDT1 must be at byte 128");
static_assert(offsetof(NvmeIdentifyController, oacs) == 256, "NVMe OACS must be at byte 256");
static_assert(offsetof(NvmeIdentifyController, acl) == 258, "NVMe ACL must be at byte 258");
static_assert(offsetof(NvmeIdentifyController, wctemp) == 266, "NVMe WCTEMP must be at byte 266");
static_assert(offsetof(NvmeIdentifyController, sanicap) == 328, "NVMe SANICAP must be at byte 328");
static_assert(offsetof(NvmeIdentifyController, nvmsetidmax) == 338, "NVMe NVMSETIDMAX must be at byte 338");
static_assert(offsetof(NvmeIdentifyController, sqes) == 512, "NVMe SQES must be at byte 512");
static_assert(offsetof(NvmeIdentifyController, nn) == 516, "NVMe NN must be at byte 516");
static_assert(offsetof(NvmeIdentifyController, oncs) == 520, "NVMe ONCS must be at byte 520");
static_assert(offsetof(NvmeIdentifyController, sgls) == 536, "NVMe SGLS must be at byte 536");
static_assert(offsetof(NvmeIdentifyController, subnqn) == 768, "NVMe SUBNQN must be at byte 768");

// OACS bit 13 advertises the Sanitize admin command.
constexpr uint16_t NVME_OACS_SANITIZE = 1u << 13;
// SANICAP bits 2:0 advertise Block Erase, Crypto Erase and Overwrite (ACAP);
// bits 7:3 give the maximum number of sanitize actions the controller will
// accept in one command (AWS). Bits 31:8 are reserved.
//
// AWS is a 5-bit field at bits 7:3, so the mask is 0xF8 and the shift is 3.
// Masking with 0x1F and then shifting by 3 would decode bits 5:3 as the whole
// field and read roughly half the real value.
constexpr uint32_t NVME_SANICAP_BLOCK_ERASE = 1u << 0;
constexpr uint32_t NVME_SANICAP_CRYPTO_ERASE = 1u << 1;
constexpr uint32_t NVME_SANICAP_OVERWRITE = 1u << 2;
constexpr uint32_t NVME_SANICAP_MAX_ACTIONS_MASK = 0xF8;
constexpr int NVME_SANICAP_MAX_ACTIONS_SHIFT = 3;

// Identify Namespace (CNS 0x00). Mirrors the kernel's struct nvme_id_ns.
struct NvmeLbaFormat {
    uint16_t ms = 0;   // metadata size
    uint8_t ds = 0;    // LBA data size, as a power of two (0 = 2^0 = 512 B)
    uint8_t rp = 0;    // relative performance
};
static_assert(sizeof(NvmeLbaFormat) == 4, "nvme_lbaf is exactly 4 bytes");

struct NvmeIdentifyNamespace {
    uint64_t nsze = 0; // offset 0
    uint64_t ncap = 0; // offset 8
    uint64_t nuse = 0; // offset 16
    uint8_t nsfeat = 0;
    uint8_t nlbaf = 0; // offset 25: number of LBA formats, 0 means all 64
    uint8_t flbas = 0;
    uint8_t mc = 0;
    uint8_t dpc = 0;
    uint8_t dps = 0;
    uint8_t nmic = 0;
    uint8_t rescap = 0;
    uint8_t fpi = 0;
    uint8_t dlfeat = 0;
    uint16_t nawun = 0;
    uint16_t nawupf = 0;
    uint16_t nacwu = 0;
    uint16_t nabsn = 0;
    uint16_t nabo = 0;
    uint16_t nabspf = 0;
    uint16_t noiob = 0;
    uint8_t nvmcap[16] = {0};
    uint16_t npwg = 0;
    uint16_t npwa = 0;
    uint16_t npdg = 0;
    uint16_t npda = 0;
    uint16_t nows = 0;
    uint8_t rsvd74[18] = {0};
    uint32_t anagrpid = 0;
    uint8_t rsvd96[3] = {0};
    uint8_t nsattr = 0;
    uint16_t nvmsetid = 0;
    uint16_t endgid = 0;
    uint8_t nguid[16] = {0};   // offset 104
    uint8_t eui64[8] = {0};    // offset 120
    NvmeLbaFormat lbaf[64];    // offset 128
    uint8_t vs[3712] = {0};
};

static_assert(offsetof(NvmeIdentifyNamespace, nlbaf) == 25, "NVMe NLBAF must be at byte 25");
static_assert(offsetof(NvmeIdentifyNamespace, nguid) == 104, "NVMe NGUID must be at byte 104");
static_assert(offsetof(NvmeIdentifyNamespace, eui64) == 120, "NVMe EUI64 must be at byte 120");
static_assert(offsetof(NvmeIdentifyNamespace, lbaf) == 128, "NVMe LBAF must be at byte 128");

struct NvmeSanitizeCapabilities {
    bool supported = false;
    bool blockErase = false;
    bool cryptoErase = false;
    bool overwrite = false;
    uint32_t maxSanitizeActions = 0;
    std::vector<uint8_t> supportedActions;
};

// ---------------------------------------------------------------------------
// USB mass storage
// ---------------------------------------------------------------------------

// What this tool could establish about a USB mass-storage device's own
// sanitization mechanisms.
//
// This exists because a USB bridge chip is a command processor, not a
// transparent wire. The bridge sits between the host and the media and is free
// to accept a command, drop it, or reinterpret it. Many bridges pass ATA and
// NVMe through; many more answer the identity request and then quietly fail the
// security command, or accept a security command and never act on it. Neither
// failure is visible from the host without probing, and neither may be guessed
// at.
enum class UsbBridgeVerdict {
    // The bridge answered an identity request, so a device-level mechanism is at
    // least conceivable on this path.
    PASSTHROUGH_PRESENT,
    // The bridge accepted an ATA/NVMe identity request and it worked, so
    // device-level commands have a plausible route to the media.
    PASSTHROUGH_VERIFIED,
    // The bridge answered nothing, or answered in a way that could not be
    // interpreted. Device-level mechanisms are not reachable.
    PASSTHROUGH_ABSENT,
    // The bridge answered, but not consistently enough to rely on. This is the
    // case that matters: the device-level answer must be UNKNOWN, not
    // SUPPORTED and not UNSUPPORTED.
    PASSTHROUGH_UNRELIABLE
};

std::string usbBridgeVerdictToString(UsbBridgeVerdict verdict);

struct UsbBridgeProbe {
    UsbBridgeVerdict verdict = UsbBridgeVerdict::PASSTHROUGH_UNRELIABLE;
    // Human-readable statement of what was observed, recorded as a limitation so
    // a certificate states why the answer is what it is.
    std::string detail;
    // True when the probe observed the bridge consuming a command without
    // effect. That is the specific, dangerous case: the host is told the
    // command was sent, and nothing happened.
    bool commandsSilentlyDropped = false;
    // The USB device node the block device resolved through, e.g. ".../usb1/1-2".
    std::string usbDeviceNode;
    std::string vendorId;
    std::string productId;
    std::string productName;
};

// Walks up from a *resolved* /sys/block/<name> path, through its "device" link,
// until a node publishes idVendor and idProduct, and reports that node.
//
// A USB mass-storage device has no "transport" attribute and its SCSI target
// sits several levels below the USB device, so neither an attribute check nor a
// path substring identifies it reliably. The presence of idVendor and idProduct
// is authoritative because it is a property of the USB interface itself.
//
// Returns false when the block device is not behind a USB device. Takes the
// resolved sysfs path rather than a device node so callers that already hold it
// (and tests using a synthetic sysfs tree) do not have to re-resolve.
bool findUsbAncestor(const std::string& resolvedSysfsPath, std::string& usbNodeOut);

// True when the target is a partition rather than a whole disk.
//
// The name alone cannot settle this. "/dev/sda1" is syntactically both a
// partition of sda and a whole disk whose own partitions would be sda1p1; the
// kernel's naming rule depends on the *disk* name, so a name alone is ambiguous.
// sysfs can, and does:
//
//   1. a partition publishes a "partition" attribute; a whole disk does not
//   2. a partition's resolved sysfs path is .../block/<disk>/<partition>, while
//      a whole disk's is .../block/<disk>
//
// Only when sysfs cannot answer - the device is absent, or the path is a disk
// image - does this fall back to the p-form, which is the one case that *is*
// decidable from a name ("nvme0n1p1" cannot be a whole disk, because a
// partition is never a parent). A bare digit suffix falls back to "not a
// partition", because the alternative is guessing.
//
// Reported as a risk on every plan so that "sanitize /dev/sda1" cannot be
// mistaken at a glance for "sanitize the whole of /dev/sda". Sanitizing a
// partition is legitimate; erasing a quarter of a disk when the operator meant
// all of it is not.
bool looksLikePartition(const std::string& devicePath,
                        const std::string& sysfsBase = "/sys");

// The whole disk that contains this target, or an empty string when the target
// is itself a whole disk or the containing disk cannot be identified. Resolved
// through sysfs, so it works for every naming convention rather than by string
// manipulation.
std::string containingWholeDisk(const std::string& devicePath,
                                const std::string& sysfsBase = "/sys");

// As above, but starts from a device node such as "/dev/sda" and resolves
// /sys/block/<name> first.
bool findUsbDeviceNode(const std::string& devicePath, std::string& usbNodeOut);

// Probes a USB mass-storage device for a usable device-level command path.
//
// Non-destructive by construction: it issues only identity requests
// (HDIO_GET_IDENTITY, and NVMe Identify Controller for a bridge that presents
// namespaces), never a security or sanitize command. It cannot prove that a
// bridge will honour a security command, only that a route to the media exists
// and is answering. The uncertainty is reported rather than resolved.
Result<UsbBridgeProbe> probeUsbBridge(const std::string& devicePath);

// ---------------------------------------------------------------------------
// Sanitize Status log page (LID 0x81), per NVMe Base Specification.
enum class NvmeSanitizeState : uint16_t {
    NOT_STARTED   = 0x0,
    IN_PROGRESS   = 0x1,
    COMPLETED     = 0x2,
    FAILED        = 0xF,
    UNKNOWN       = 0xFFFF
};

struct NvmeSanitizeStatus {
    NvmeSanitizeState state = NvmeSanitizeState::UNKNOWN;
    // 0xFFFF means the device does not report sanitize progress.
    bool progressValid = false;
    uint16_t progressPercent = 0;
};

Result<int> openDevice(const std::string& path, bool readOnly = true);
void closeDevice(int fd);

Result<uint64_t> getBlockDeviceSize(int fd);
Result<uint32_t> getLogicalBlockSize(int fd);
Result<uint32_t> getPhysicalBlockSize(int fd);
Result<bool> isRotational(int fd);
Result<bool> isReadOnly(int fd);

// How a device's read-only state was established, and what went wrong when it
// could not be. Recorded rather than collapsed into a bool so a check that
// fails says whether the device is read-only, the device could not be reached,
// or the kernel refused the query - three different problems with three
// different fixes, and a report that says "cannot open" for all of them sends
// the operator to the wrong place.
enum class ReadOnlySource {
    // Named BLKROGET_IOCTL, not BLKROGET: <linux/fs.h> defines BLKROGET as the
    // ioctl request number, so an enumerator of that name is a macro expansion
    // and will not compile.
    BLKROGET_IOCTL,  // ioctl on an opened descriptor; what `blockdev --getro` does
    SYSFS,         // /sys/block/<name>/ro; what `lsblk` reads, needs no device access
    // A disk image: a regular file, not a block device. BLKROGET is meaningless
    // for it - the ioctl returns ENOTTY - and it has no sysfs entry either, so
    // neither block-device source can speak for it. The question that *is*
    // meaningful is whether the file can be written, and that is asked directly.
    //
    // This case previously passed the read-only check by accident rather than by
    // decision: the old code treated a *failed* ioctl as "not read-only", so a
    // disk image satisfied a check that had actually learned nothing. Removing
    // that accident exposed the case, and refusing it outright would have taken
    // away the project's ability to sanitize images, which is a supported
    // operation. So it is answered on its own terms and labelled as such.
    REGULAR_FILE,
    UNDETERMINED,  // no source could establish it
};

struct ReadOnlyStatus {
    bool established = false;   // false means: do not assume anything
    bool readOnly = false;      // only meaningful when established
    ReadOnlySource source = ReadOnlySource::UNDETERMINED;

    // Populated when established is false. Each names the operation and the
    // errno, so the reason survives into the safety report and the evidence.
    std::string openError;      // opening the device node failed
    std::string ioctlError;     // BLKROGET failed
    std::string sysfsError;     // /sys/block/<name>/ro was absent or unreadable

    // One sentence combining the above, for the check's detail line.
    std::string diagnostic() const;
};

// Establishes whether a block device is read-only.
//
// Two independent sources, tried in order of authority:
//
//   1. BLKROGET on an opened descriptor. This is exactly what
//      `blockdev --getro` does, and it is the authoritative answer because it
//      asks the device the kernel is about to write to.
//
//   2. /sys/block/<name>/ro. This is what `lsblk` reads, and it is mode 0444 -
//      world-readable - so it works for a user who cannot open the device node
//      at all, which is the common case: a root-owned `brw-rw---- root disk`
//      node is unreadable by an unprivileged operator, and that has nothing
//      whatever to do with whether the medium is write-protected.
//
// The fallback exists because those two failures are independent, and conflating
// them produced a real false negative. A safety check reported "Cannot open
// device to check read-only status" for a perfectly writable USB drive whose
// node the process could not open, while lsblk on the same machine said RO=0.
// The check had the answer available and did not look.
//
// If neither source establishes the state, `established` is false and the
// caller must fail closed. This function never guesses.
ReadOnlyStatus deviceReadOnlyStatus(const std::string& devicePath,
                                    const std::string& sysfsBase = "/sys");

// Whether this process can open `path` for writing, tested against the real
// access check rather than by inspecting the mode bits.
//
// The mode bits answer a different question: S_IWUSR says whether the *owner*
// may write. For a root-owned device node that is true for every user, so a
// check built on it reports "write permission available" to a process that
// cannot open the device - which is how a safety report came to show
// "Permissions: PASS" next to "Read-Only: cannot open device" on the same
// device, which is a contradiction no operator can act on.
//
// Returns an error carrying the errno rather than a bare bool, because a bool
// would leave the safety report with no errno to show and the check would go
// back to saying "no permission" with nothing to back it up.
Result<bool> canOpenForWrite(const std::string& path);

// True when `fd` is a descriptor this process may write to, established by
// actually asking the kernel rather than by reading the mode.
bool descriptorIsWritable(int fd);


// Trims a fixed-width device string field: copies up to the first NUL and then
// removes trailing spaces. The kernel space-pads and does not NUL-terminate the
// IDENTIFY and Identify Controller string fields, so this is required before any
// of them can be compared, displayed or hashed.
std::string trimDeviceString(const char* raw, std::size_t length);

// Model, serial and firmware revision as the device itself reports them.
struct DeviceIdentity {
    std::string model;
    std::string serial;
    std::string firmware;
    // Which interface the values came from, so an operator reading a
    // certificate can tell a device-reported value from an inferred one.
    std::string source;
};

// Reads the identity of an open device, dispatching on the transport the device
// actually reported rather than assuming ATA.
//
// HDIO_GET_IDENTITY is an ATA interface and does not work on NVMe, so an
// ATA-only reader could never produce a serial for an NVMe drive. That matters:
// the destructive-path confirmation asks the operator to type the last
// characters of the serial, so a missing serial removes the check that proves
// the right disk was selected.
//
//   NVME            Identify Controller (MN, SN, FR)
//   SATA/SCSI/MMC   ATA IDENTIFY DEVICE via HDIO_GET_IDENTITY
//   USB             ATA, then NVMe; a bridge may implement either or neither
//   anything else   ATA, then NVMe
Result<DeviceIdentity> readDeviceIdentity(int fd,
                                          TransportType transport = TransportType::UNKNOWN);

Result<std::string> getDeviceModel(int fd,
                                   TransportType transport = TransportType::UNKNOWN);
Result<std::string> getDeviceSerial(int fd,
                                    TransportType transport = TransportType::UNKNOWN);
Result<std::string> getDeviceFirmware(int fd,
                                      TransportType transport = TransportType::UNKNOWN);

Result<NvmeIdentifyController> nvmeIdentifyController(int fd);
Result<NvmeIdentifyNamespace> nvmeIdentifyNamespace(int fd, uint32_t nsid);

// The namespace id of an open NVMe namespace device node, read from
// /sys/block/<name>/device/nsid.
//
// This is not a convenience. NVME_IOCTL_ADMIN_CMD carries an explicit nsid, and
// the previous code hardcoded 1, so a sanitize issued against namespace 3 of a
// multi-namespace controller would have been addressed to namespace 1. The
// Sanitize command applies to the namespace in the nsid field, so that is the
// difference between erasing the target and erasing something else.
//
// Fails when the attribute is absent, which is the honest answer for a device
// this tool cannot place.
Result<uint32_t> nvmeIdentifyNamespaceForDevice(int fd);

Result<NvmeSanitizeCapabilities> nvmeGetSanitizeCapabilities(int fd);
Result<std::vector<uint8_t>> nvmeGetSupportedSanitizeActions(int fd);
Result<void> nvmeSanitize(int fd, uint32_t nsid, uint8_t action, uint8_t overwritePassCount = 0);
Result<NvmeSanitizeStatus> nvmeSanitizeStatus(int fd, uint32_t nsid);

Result<bool> ataSecurityEnabled(int fd);
Result<bool> ataSecurityFrozen(int fd);
Result<bool> ataSecuritySupported(int fd);
Result<bool> ataEnhancedEraseSupported(int fd);

// Whether this build can actually issue the ATA Security Feature Set erase
// commands. Succeeds only when the transport exists; the error explains why it
// does not, so capability detection can report the mechanism as unavailable
// rather than selecting a method that will always fail at execution time.
Result<bool> ataSecurityEraseSupportedInThisBuild();

// Both fail closed in this build. HDIO_DRIVE_CMD carries only a 4-byte taskfile
// header, which cannot express the security identifier that SECURITY ERASE
// PREPARE (0xF3) and SECURITY ERASE UNIT (0xF4) pass in the taskfile registers.
// They require SG_IO ATA PASS-THROUGH(16). See ataSecurityEraseSupportedInThisBuild().
Result<void> ataSecurityErasePrepare(int fd, const std::string& password);
Result<void> ataSecurityEraseUnit(int fd, const std::string& password, bool enhanced);
Result<void> ataSanitize(int fd, uint8_t action, uint16_t overwritePassCount = 0);
Result<uint16_t> ataSanitizeStatus(int fd);

// True when `child` names the same device as `parent`, or is a partition of it.
//
// The direction matters: the root filesystem is usually a *partition* of the
// target whole disk (target=/dev/nvme0n1, root=/dev/nvme0n1p2), so the
// containment test must ask whether the system device sits inside the target,
// not the other way round.
//
// Both kernel partition-naming conventions are handled:
//   /dev/nvme0n1  ->  /dev/nvme0n1p1   (name already ends in a digit, so a
//                                        'p' separator is inserted)
//   /dev/sda      ->  /dev/sda1        (no separator)
// and /dev/nvme0n10 is correctly *not* treated as a partition of /dev/nvme0n1.
//
// Exposed because the safety layer, the swap check and the LVM/RAID checks all
// depend on it, and it must not be reimplemented by each caller.
bool deviceContains(const std::string& parent, const std::string& child);

std::vector<std::string> getMountPoints(const std::string& devicePath);

// The filesystem a path lives on, from /proc/self/mountinfo. Empty when the
// kernel reported nothing, which is UNKNOWN rather than a default: a file on a
// filesystem this tool cannot name must not be treated as being on a familiar
// one.
std::string filesystemTypeOf(const std::string& path);
bool isMounted(const std::string& devicePath);
bool isSystemDisk(const std::string& devicePath);
bool isBootDisk(const std::string& devicePath);

// Expands a device node to the physical devices actually behind it, walking
// /sys/block/<name>/slaves/ through any device-mapper, LVM or md layers.
//
// Needed because a root filesystem in an LVM volume is reported by
// /proc/self/mountinfo as /dev/mapper/<vg>-<lv>, and the disk that must be
// protected is the one underneath it. Returns a single-element list for a
// device with no layering, and an empty list for anything not present in sysfs.
std::vector<std::string> resolveToPhysicalDevices(const std::string& devicePath);

std::string getRootDevice();
std::string getBootDevice();
std::vector<std::string> getActiveSwapDevices();
bool isDeviceMapperInUse(const std::string& devicePath);
bool isLvmInUse(const std::string& devicePath);
bool isRaidInUse(const std::string& devicePath);

// ---------------------------------------------------------------------------
// File-scope safety
//
// These answer questions about a single file that the device-level checks above
// cannot: not "is this disk the system disk" but "is this file open, is it
// writable, is its filesystem read-only, is it a running program".
//
// The open-file question is answered by walking /proc, not by a lock attempt.
// flock() would be the obvious tool and it is wrong here: an advisory lock says
// what cooperating programs have agreed to, and an overwrite issued through a
// descriptor the kernel did not consult ignores every lock on the file. The
// honest question is "who holds this inode open", and /proc is where the kernel
// publishes that.
// ---------------------------------------------------------------------------

// A process holding the file open, or a running program mapped to it.
struct FileUse {
    bool openByAnyProcess = false;
    // The pid and command of one holder. There can be many; one is enough to
    // tell the operator, and the list is scanned for all of them at the call
    // site if it needs to.
    uint32_t pid = 0;
    std::string command;
    // True when the file is mapped into a process as an executable, a library
    // or a data segment, i.e. it is part of something that is running now.
    bool mappedAsExecutable = false;
    std::string mappedByCommand;
    // The inode the scan matched, so a caller can tell "no holder" from "the
    // scan could not read /proc and therefore found nothing".
    uint64_t inode = 0;
    // False when /proc could not be read at all. Distinct from "nothing is
    // open": an unreadable /proc must not be reported as a clean result.
    bool scanCompleted = false;
};

// Scans /proc for any process holding the given inode open, and for a process
// with the given path mapped into its address space.
//
// The inode is matched by (device, inode) from an fstat, not by path, so a
// hard link or a bind mount cannot hide a holder and a renamed file cannot
// produce a false one.
FileUse findFileUse(uint64_t deviceNumber, uint64_t inodeNumber,
                    const std::string& pathForMappingCheck);

// True when the filesystem holding `path` is mounted read-only. A file on one
// cannot be overwritten at all, and the failure would otherwise surface as a
// write error partway through a multi-file run.
bool isOnReadOnlyMount(const std::string& path);

Result<std::vector<PartitionInfo>> readPartitions(const std::string& devicePath);
Result<std::vector<FilesystemInfo>> readFilesystems(const std::string& devicePath);

Result<std::string> readSysfsAttribute(const std::string& sysfsPath, const std::string& attribute);
Result<uint64_t> readSysfsUint64(const std::string& sysfsPath, const std::string& attribute);
Result<uint32_t> readSysfsUint32(const std::string& sysfsPath, const std::string& attribute);
Result<bool> readSysfsBool(const std::string& sysfsPath, const std::string& attribute);
// Resolves a device node to its /sys/block entry. sysfsBase is a parameter so
// the partition-containment tests can drive a synthetic tree.
std::string findSysfsPath(const std::string& devicePath,
                          const std::string& sysfsBase = "/sys");

// Nothing here shells out. A device path is operator input and a shell
// interprets any metacharacter in it, so no std::string is ever handed to
// /bin/sh.
//
// Everything this tool needs from the system is read from sysfs or obtained
// through libblkid, both of which take the path as opaque data.

// Exposed for testing only.
//
// Decodes the octal escapes the kernel writes into /proc/self/mountinfo fields
// (\040 space, \011 tab, \012 newline, \134 backslash). It sits in the
// mounted-detection path, and a mountinfo source reached through a disk label
// routinely contains a space, so leaving the escapes in place can make a
// genuinely mounted device look unmounted.
namespace detail {
std::string decodeMountInfoEscapes(const std::string& field);
} // namespace detail

} // namespace ledgerase::platform::linux