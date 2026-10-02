# Filesystem capability matrix

What this tool can actually do to a filesystem, and what it refuses.

This table is generated from `include/sanitizer/filesystem_capability.hpp` and
`src/filesystem/filesystem_capability.cpp`, and a test asserts that the
documentation and the code cover the same rows. The measurements behind several
of the cells are in [RESIDUE.md](RESIDUE.md).

## The three values, and why there are three

| value | meaning |
|---|---|
| **supported** | performed, and the result is checked afterwards |
| **partial** | partly performed, and the remainder is recorded as a limitation |
| **unsupported** | not performed. Refused rather than silently skipped. |
| **unknown** | the filesystem was not identified, so nothing is claimed |

"Partial" exists because "supported" would be a lie. Overwriting a file's own
blocks on ext4 is exactly what was asked and no more: the file's name is removed,
its content is overwritten, its inode's extent map and size are still on the
medium, and every block freed by an earlier delete of some other file is still
there. Calling that "supported" is how a tool ends up implying an assurance it
did not deliver.

**The refusal rule is strict:** a file-level erase proceeds only when the
filesystem's *overwrite content* cell is **supported**. *Partial* is refused, and
the refusal names the layer that got in the way, because "partially erased" is
not a state an operator can act on.

## The matrix

| filesystem | detect | overwrite content | remove delete traces | handle journal | overwrite free space |
|---|---|---|---|---|---|
| **ext2/ext3/ext4** | supported | **supported** | unsupported | partial | unsupported |
| **xfs** | supported | **supported** | unsupported | partial | unsupported |
| **btrfs** | supported | partial | unsupported | partial | unsupported |
| **f2fs** | supported | partial | unsupported | partial | unsupported |
| **tmpfs** | supported | **supported** | partial | supported | supported |
| **vfat** | supported | partial | partial | unsupported | unsupported |
| **ntfs** | supported | partial | unsupported | partial | unsupported |
| **apfs** | unsupported | unsupported | unsupported | unsupported | unsupported |
| **overlayfs** | partial | unsupported | unsupported | partial | unsupported |
| **zfs** | supported | partial | unsupported | partial | unsupported |
| **swap** | unsupported | unsupported | unsupported | unsupported | unsupported |
| **other / unidentified** | partial | unsupported | unsupported | unsupported | unsupported |

Bold marks the cells that permit a file-level erase: ext2/ext3/ext4, xfs and tmpfs.

## Why each cell says what it says

### ext2/ext3/ext4 — the only filesystem with a measured row

* **overwrite content: supported.** The file's own blocks are overwritten
  through its open descriptor and read back. Nothing else on the filesystem is
  touched. This is the whole of what the operation means, and it is why the cell
  is supported rather than partial: the *content* really is gone from the
  *blocks that held it*.
* **remove delete traces: unsupported, and this one is measured.** After an
  ordinary `unlink`, the file's name is gone from the directory and from the
  inode, but the inode is still readable by number and its extent tree still
  points at the data blocks. See [RESIDUE.md §3](RESIDUE.md). An eraser working
  on one open file cannot reach the inode table for other files, the free-block
  bitmap, or blocks freed before the run started.
* **handle journal: partial.** `fsync`/`syncfs` is called after wiping, which
  commits pending transactions and bounds the window in which a copy of the data
  can sit in the journal. Already-committed journal blocks are not zeroed, and
  this tool does not reach into the journal's own space. The unmeasured question
  is in [RESIDUE.md §5](RESIDUE.md): whether the file's data is ever written to
  the journal at all under each `data=` mode.
* **overwrite free space: unsupported.** Freeing a file's blocks and overwriting
  the free list means writing blocks nobody asked this tool to write. Not
  attempted.

### xfs

The same structure as ext4 — inode, extent map, log — and the same rule. The
delete-trace cell is `unsupported` on the same reasoning; the one difference is
that nothing about xfs has been *measured* here, and the reason field says so
rather than borrowing ext4's evidence.

### btrfs

`overwrite content: partial`. A file's blocks can be written, but btrfs is
copy-on-write: the previous version of the block lives in the same extent tree
until it is overwritten by a new allocation, and the file may be in a snapshot.
Writing into a btrfs block on the top-level tree can itself be snapshotted, so
the write is not guaranteed to reach the physical medium even immediately.

`remove delete traces: unsupported`, and it is a stronger refusal than on ext4 —
this tool does not enumerate snapshots, so it cannot even say whether a
pre-erase version exists.

### f2fs

`partial` for the same family of reason, inverted: f2fs is log-structured, so the
superseded version of the data sits in the node area until a checkpoint, and
nothing in a file-level erase reaches it.

### tmpfs

The one filesystem where several cells are genuinely better, and the reasons say
why:

* `overwrite content: supported` — a tmpfs file's content is held only in that
  file's pages, so overwriting them does remove the file's content from the
  filesystem, which is the question this cell answers. The pages may also be
  mapped by something else; that is a limit on what the *memory* holds rather
  than on what the *filesystem* holds, and it is recorded as a limitation on
  every file erased on tmpfs. The distinction is the same one a device-level
  erase records as "host-visible address space only".
* `remove delete traces: partial` — the directory entry does go, and there is no
  on-disk inode or free-block map to clear, which is genuinely all there is to
  clear.
* `handle journal: supported` — there is no journal. Recorded explicitly so the
  cell is not read as an oversight.
* `overwrite free space: supported` — there is no persistent free space.

### vfat

`overwrite content: partial`, and this is the cell most often got wrong: vfat
has no per-file slack. It has the gap between the end of one file and the start
of the next, and that gap belongs to no single file, so a file-level erase cannot
reach it.

`remove delete traces: partial` — the unlink clears the directory entry's first
character to `0xE5`, which is the format's own convention, but the rest of the
32-byte entry is left alone by this tool.

`handle journal: unsupported` — vfat has no journal. Recorded so the cell is not
mistaken for a gap in the work.

### ntfs

`partial`. A small file's data is *resident*, inside its `$MFT` record, and this
tool does not edit the `$MFT`; only a non-resident file's data runs are reachable
through the file's descriptor. The `$LogFile` and the free-space record clusters
are likewise out of reach.

### apfs

Every cell `unsupported`, and the reason is the same in each: APFS is not a Linux
filesystem and there is no Linux path to it. The cells exist so the row is a
refusal with an explanation rather than an absence.

### overlayfs

`overwrite content: unsupported`, and refused deliberately. An overlay's write
goes to the *upper* layer. A file that lives in a lower layer cannot be erased
in place — a write to it is a copy-up, and unlinking it produces a whiteout
rather than a deletion. Doing either would be acting on the wrong filesystem, so
the operation is refused instead.

### zfs

`partial`, copy-on-write and snapshot-preserving for the same reason as btrfs,
and this tool does not enumerate or destroy snapshots.

### swap

Refused throughout. A page that is currently in memory may have been swapped in
from any filesystem, and overwriting a copy does not erase the original.

### other / unidentified

Refused. Overwriting content on a filesystem whose copy-on-write, snapshot and
log semantics have not been established would mean writing to storage without
knowing what a write does there. The refusal names `sanitize <device>` as the
alternative.

## The three questions the table cannot answer

* **What the filesystem was doing at the time.** The rows describe a filesystem's
  design, not a run's configuration. A btrfs subvolume with snapshots disabled
  behaves differently from one with them, and this tool does not read the mount
  options.
* **What the flash translation layer did.** Every row above is about the
  logical view. On an SSD, a file's blocks are not a contiguous region of the
  medium, and none of this reaches the NAND. See [LIMITATIONS.md](LIMITATIONS.md).
* **What the controller's own encryption did.** Where the medium is
  self-encrypting, the content is already ciphertext, so "byte for byte intact"
  is both true and useless. Not detected, not claimed.

## Which filesystems permit an erase today

**ext2/ext3/ext4**, **xfs** and **tmpfs**, and only for the file's own blocks.
For
everything else the tool refuses and points at `ledgerase-cli sanitize
<device>`, which reaches the copies a file-level erase cannot. That is the
design, not a limitation to be worked around: an eraser that reported success on
a btrfs snapshot or a FAT inter-file gap would be claiming something it had not
done.
