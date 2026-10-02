# What survives a normal delete on ext4?

Measured, not quoted. Every statement below is the output of
`tools/residue/ext4-residue.py` on the machine named in the run record, on an
image that script built and then examined. Where a claim could not be
reproduced in this environment it is marked **UNPROVEN** and the reason is
given. Nothing here is a general claim about ext4: the answer depends on the
`data=` mode, the journal, the block size and the filesystem version, all of
which vary.

Reproduce with:

```sh
python3 tools/residue/ext4-residue.py /tmp/residue
```

---

## 1. The method, and the one thing it cannot do

The image is built with `mkfs.ext4` and populated with `debugfs`, so no root
and no real filesystem is touched. `debugfs` edits the filesystem's own
structures; it does **not** go through the kernel. That is the method's
limitation and it decides two of the four questions below:

* A `unlink(2)` on a running system journals the metadata changes and, under
  `data=journal`, journals the file's data blocks before writing them home.
  `debugfs` writes none of that. **So anything about the journal is unproven
  here**, and the script says so rather than reporting "nothing survived".
* `debugfs` zeroes the whole block it writes, slack included. ext4 does not.
  So **block-slack retention is unproven here** for the same reason.

Everything the method *can* establish, it establishes exactly: what the
filesystem's structures look like after an ordinary unlink.

Run record:

| | |
|---|---|
| Host filesystem | tmpfs on `/tmp`, x86_64, Linux (the image is a file, not a device) |
| mke2fs | 1.47.4 (6-Mar-2025), EXT2FS library 1.47.4 |
| Filesystem features | `has_journal ext_attr resize_inode dir_index orphan_file filetype extent 64bit flex_bg metadata_csum_seed sparse_super large_file huge_file dir_nlink extra_isize metadata_csum` |
| Block size | 1024 bytes |
| Image size | 64 MiB |
| Journal | inode 8, blocks 16385–20480. **Empty in this image**: the journal superblock (magic `0xC03B3998`) is not present, because no kernel-side write ever happened. |
| Files examined | three: an 10 928-byte PNG, a 43 398-byte PNG, a 9 000-byte text file |

---

## 2. Data blocks — everything survives

**MEASURED. A normal delete left all three files' full contents in the image,
byte for byte, and every one of their data blocks intact.**

| file | size | blocks | whole file found after delete | every data block intact |
|---|---|---|---|---|
| `exact.png` | 10 928 | 11 | 1 occurrence | yes |
| `blocky.png` | 43 398 | 43 | 1 occurrence | yes |
| `mixed.txt` | 9 000 | 9 | 1 occurrence | yes |

The control matters: the same searches were run against a second image where the
files had **not** been deleted, and each returned the same counts. A "not found"
result is only informative if the search is known to find the thing when it is
there.

`mixed.txt` returns 230 occurrences of a 64-byte probe rather than 1, because
it is built from a six-word vocabulary and the probe is not unique. Its
*whole-file* digest still matches exactly once. This is stated because it is the
kind of number that looks like a false-positive rate and is not one.

**What this means for an eraser:** overwriting the file's own blocks is
necessary and is not sufficient on its own — see §3 and §4.

## 3. The inode — still addressable, still holding the extent map

**MEASURED. After the unlink the file's name is gone, but the inode is still
readable by number and its extent tree still points at the very blocks the data
sits in.**

| file | inode | name in directory | name in inode | inode still addressable | extents recorded after delete |
|---|---|---|---|---|---|
| `exact.png` | 13 | no | no | yes | `(0-10):4417-4427` |
| `blocky.png` | 15 | no | no | yes | `(0-42):4437-4479` |
| `mixed.txt` | 14 | no | no | yes | `(0-8):4428-4436` |

So the file is anonymous but its size and its block list are still recorded. An
investigator with the inode number recovers both without touching a single data
block.

**What this means for an eraser:** a file eraser that only overwrites content
leaves a complete map of the file behind. Phase B's residue check searches for
content chunks, so it would not notice this; the honest capability entry for
"delete-trace removal" on ext4 is therefore *unsupported* for this tool, and
that is what the Phase C matrix says.

## 4. Block slack — UNPROVEN

**UNPROVEN, and the reason is the method, not the filesystem.**

The case was built: a 1 500-byte file was written, deleted, and a 5-byte file
was written into the block its data had occupied. The short file did land in
that block (4417, confirmed from the inode's extents), so the situation arose.
The block was then **entirely zero**, including the 1 019 bytes past the short
file's 5.

`debugfs` zeroes the whole block it writes. ext4 does not: the kernel's
`write()` path writes the file's bytes and leaves the rest of the block as it
found it, which is why block-slack residue is a real and well-documented
phenomenon. But this experiment cannot see it, because the tool used to create
the situation destroys the evidence.

To settle it, one of:

* a kernel-side `write()` of the short file into the freed block, on a mounted
  ext4 image — needs `CAP_SYS_ADMIN` and a loop mount, unavailable here;
* `fuse2fs`, which mounts ext4 unprivileged — not installed here;
* a real block device, which this project will not use for a throwaway
  experiment.

Until then, any statement about ext4 slack from this project is an assumption
imported from elsewhere, and Phase B treats slack as **assumed to retain data**
on the conservative side: it overwrites the file's blocks in full, which covers
slack whether or not it survives, and it records the assumption as a limitation.

## 5. The journal — UNPROVEN

**UNPROVEN. The journal in this image is empty, because nothing wrote through
the kernel.**

The journal is inode 8, 4 096 blocks, at blocks 16385–20480. Its superblock —
magic `0xC03B3998` at offset 56 — is not present anywhere in the image, which is
what an unused, never-written journal looks like. There was nothing to search,
so the script reports "not located, so this was not searched" and not "nothing
survived".

The claim worth testing is the important one: on a running system with
`data=journal`, or even with `data=ordered`, the file's data blocks are
transiently in the journal, and a journal commit wipes the transaction. A file
eraser that overwrites the file's blocks but never commits the journal can
therefore leave the original content sitting in the journal's free space.

Phase B takes that as an **assumption to be safe against**, and says so: the
eraser calls `syncfs()`/`fsync()` on the containing filesystem after wiping, and
records in its evidence that a journal this tool cannot reach may still hold
pre-erasure content. `syncfs()` writes and commits the journal; it does not
zero already-committed journal blocks, so this is a mitigation and not a
guarantee, and the evidence says that.

---

## 6. What this changes for the eraser

| residue location | survives a normal delete? | can this tool wipe it? | matrix entry |
|---|---|---|---|
| file's data blocks | **yes, byte for byte** (measured) | yes — overwrite through the open fd | supported |
| block slack | not established here; assumed yes (see §4) | yes, incidentally — the whole block is rewritten | supported (with the assumption recorded) |
| inode: extent map, size | **yes** (measured) | no | **unsupported** |
| inode: the name | no (measured) | n/a | not applicable |
| directory entry | no (measured) | n/a | not applicable |
| journal | not established here; assumed possibly (see §5) | no | **unsupported** |
| freed blocks not yet reused | **yes** (measured — this is the data-block case) | only if the eraser knows which blocks they are | **unsupported** |

The last row is the one that decides the tool's honesty. An eraser opened on one
file can wipe that file's blocks. It cannot wipe the blocks of files that were
already deleted, cannot wipe the journal, and cannot wipe inode tables it did
not allocate. A file eraser that reports success for any of those is claiming
something it cannot deliver.

## 7. What would change these answers

* `data=writeback` journalling of data: less in the journal, more risk on a
  crash. Untested here.
* `bigalloc`: one allocation unit spans many blocks, so "the file's blocks" is a
  much larger region and the slack question changes shape. Untested here.
* Encrypted directories (`fscrypt`/`ecryptfs`): the content on the medium is
  already ciphertext, so "byte for byte intact" would be true and useless.
  Untested here.
* An SSD behind any interface: none of this applies. The flash translation
  layer decides where these blocks physically are, and the file's blocks are not
  a contiguous region of the medium. See [LIMITATIONS.md](../LIMITATIONS.md).
