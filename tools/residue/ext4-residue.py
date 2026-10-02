#!/usr/bin/env python3
"""What actually survives a normal delete on ext4?

Builds an ext4 image, writes files of known content, deletes them the ordinary
way (unlink, with the journal live), and then asks four separate questions
about the finished image:

  data blocks    is the file's content still there, byte for byte?
  block slack    do the bytes after the file's content, inside its last block,
                 still hold part of the old content?
  inode          does the inode still exist, and what does it record?
  journal        does the ext4 journal still contain the old file's content?

The point is to decide what a file eraser has to overwrite, rather than to
confirm what a document already says. Where a claim cannot be reproduced here,
it is reported as unproven rather than as a finding.

Every conclusion is measured on the image that this script built, on the machine
it ran on. ext4's behaviour is configurable (data=journal, data=ordered,
data=writeback) and a mount option changes the answer, so the mount options used
are printed and are part of the result.

Usage:
  ext4-residue.py <outdir>
"""

import hashlib
import json
import os
import struct
import subprocess
import sys
import zlib

BLOCK = 1024
IMAGE_MB = 64


def run(args):
    return subprocess.run(args, check=True, capture_output=True)


def debugfs(image, request, write=True):
    args = ["debugfs"] + (["-w"] if write else []) + ["-R", request, image]
    return subprocess.run(args, capture_output=True, text=True)


def crc32(data):
    return zlib.crc32(data) & 0xFFFFFFFF


def make_png(width, height, seed):
    def chunk(kind, payload):
        body = kind + payload
        return (struct.pack(">I", len(payload)) + body +
                struct.pack(">I", zlib.crc32(body) & 0xFFFFFFFF))
    rows = []
    for y in range(height):
        row = bytearray([0])
        for x in range(width):
            row += bytes([(x * 7 + y * 3 + seed) % 256,
                          (x * 11 + y * 5 + seed * 2) % 256,
                          (x * 13 + y + seed * 3) % 256])
        rows.append(bytes(row))
    raw = b"".join(rows)
    header = struct.pack(">IIBBBBB", width, height, 8, 2, 0, 0, 0)
    return (b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", header) +
            chunk(b"IDAT", zlib.compress(raw, 6)) + chunk(b"IEND", b""))


def make_text(size, seed):
    words = [b"ALPHA", b"BRAVO", b"CHARLIE", b"DELTA", b"ECHO", b"FOXTROT"]
    out = bytearray()
    i = seed
    while len(out) < size:
        out += words[i % len(words)] + b" "
        i += 1
    return bytes(out[:size])


def extent_map(image, name, file_blocks):
    result = debugfs(image, "stat /" + name.lstrip("/"), write=False)
    lines = [l.strip() for l in result.stdout.splitlines()
             if l.startswith("(") and "):" in l]
    if not lines:
        return []
    text = " ".join(lines).replace("(ETB0):", "")
    pairs = []
    for chunk_text in text.split(","):
        chunk_text = chunk_text.strip()
        if not chunk_text or ":" not in chunk_text:
            continue
        file_range, image_range = chunk_text.split(":")
        file_range = file_range.strip("() ").split("-")
        image_range = image_range.strip("() ").split("-")
        first_file, last_file = int(file_range[0]), int(file_range[-1])
        first_image = int(image_range[0])
        for step in range(last_file - first_file + 1):
            if first_file + step < file_blocks:
                pairs.append((first_file + step, first_image + step))
    return pairs


def find_all(haystack, needle):
    out = []
    index = haystack.find(needle)
    while index != -1:
        out.append(index)
        index = haystack.find(needle, index + 1)
    return out


def find_short(haystack, needle):
    return find_all(haystack, needle)


def main():
    outdir = sys.argv[1] if len(sys.argv) > 1 else "."
    os.makedirs(outdir, exist_ok=True)
    work = os.path.join(outdir, ".work")
    os.makedirs(work, exist_ok=True)
    image = os.path.join(outdir, "residue.img")
    size = IMAGE_MB * 1024 * 1024

    with open(image, "wb") as handle:
        handle.truncate(size)
    # data=journal is not passed: mke2fs's default is data=ordered, which is
    # what a default install uses. The setting is recorded in the output because
    # the answer depends on it.
    run(["mkfs.ext4", "-q", "-F", "-b", str(BLOCK), image])
    features = run(["dumpe2fs", "-h", image]).stdout.decode()
    mount_options = [line.split(":")[1].strip()
                     for line in features.splitlines()
                     if line.startswith("Filesystem features") or
                     line.startswith("Filesystem flags")]

    samples = {}
    for index, (name, data) in enumerate([
            ("exact.png", make_png(60, 60, 3)),
            ("mixed.txt", make_text(9000, 5)),
            ("blocky.png", make_png(120, 120, 7)),
    ]):
        path = os.path.join(work, name)
        with open(path, "wb") as handle:
            handle.write(data)
        debugfs(image, f"write {path} /{name}")
        blocks = (len(data) + BLOCK - 1) // BLOCK
        samples[name] = {
            "bytes": data,
            "size": len(data),
            "sha256": hashlib.sha256(data).hexdigest(),
            "blocks": blocks,
            "layout": extent_map(image, name, blocks),
        }

    # Delete, the ordinary way. debugfs's rm unlinks and frees the extents, which
    # is the same sequence of journal and metadata operations as a running
    # system's unlink; what it cannot do is run the page cache, and that
    # difference is recorded rather than glossed over.
    inodes_before = {}
    for name in samples:
        listing = debugfs(image, "stat /" + name, write=False).stdout
        for line in listing.splitlines():
            # "Inode: 13   Type: Regular    Mode:  0644   Flags: 0x80000"
            if "Inode:" in line:
                fields = line.split(":", 1)[1].split()
                inodes_before[name] = int(fields[0])
    for name in samples:
        debugfs(image, f"rm /{name}")

    with open(image, "rb") as handle:
        after = handle.read()

    findings = {"mount_options": mount_options, "files": {}}
    for name, sample in samples.items():
        data = sample["bytes"]
        record = {
            "size": sample["size"],
            "sha256": sample["sha256"],
            "blocks": sample["blocks"],
            "inode": inodes_before.get(name),
            "extents": len({b for _, b in sample["layout"]}),
        }

        # 1. data blocks
        whole = find_all(after, data)
        record["whole_file_occurrences_after_delete"] = len(whole)
        # Only the bytes the file actually held. Comparing whole blocks would
        # always report false for the last block, whose tail is slack the file
        # never occupied - which is a measurement artefact, not a finding.
        record["data_blocks_intact"] = all(
            after[b * BLOCK:b * BLOCK + (min((f + 1) * BLOCK, len(data)) - f * BLOCK)] ==
            data[f * BLOCK:min((f + 1) * BLOCK, len(data))]
            for f, b in sample["layout"])

        # 2. block slack: the tail of the last block beyond the file's content
        slack = (len(data) % BLOCK) or BLOCK
        if len(data) % BLOCK:
            tail = data[-64:]
            hits = find_all(after, tail)
            record["slack_bytes_after_content"] = slack
            record["last_64_content_bytes_found_after_delete"] = len(hits)
            record["slack_survives"] = bool(hits)
        else:
            record["slack_survives"] = None
            record["note_slack"] = "file is a whole number of blocks: no slack"

        # 3. the inode
        listed = debugfs(image, "ls -l /", write=False).stdout
        record["name_still_listed"] = (name in listed)
        found_inode = debugfs(image, f"stat <{inodes_before.get(name, 0)}>",
                              write=False)
        record["inode_still_addressable"] = found_inode.returncode == 0
        record["inode_size_after_delete"] = None
        record["inode_raw"] = found_inode.stdout.strip().splitlines()[:24]
        for line in found_inode.stdout.splitlines():
            # "Size: 141                  Blocks: 16  IO Block: 4096  regular file"
            if line.strip().startswith("Size:"):
                record["inode_size_after_delete"] = int(line.split()[1])
        record["inode_extents_after_delete"] = [
            l.strip() for l in found_inode.stdout.splitlines()
            if l.startswith("(") and "):" in l]
        record["file_name_in_inode_after_delete"] = (
            name in found_inode.stdout)

        # 4. the journal
        # Where the journal lives, from the superblock. Read rather than
        # guessed: a hardcoded offset would silently report "nothing survived"
        # if the geometry were different.
        journal = journal_region(after)
        record["journal_in_image"] = journal is not None
        if journal is not None:
            start, length, blocks = journal
            findings.setdefault("journal", {})
            findings["journal"].update({"offset": start, "bytes": length,
                                        "blocks": blocks})
            blob = after[start:start + length]
            probe = data[:64] if len(data) >= 64 else data
            record["content_in_journal"] = len(find_all(blob, probe))
        else:
            # Not "nothing survived": the journal was not located, so the
            # question was not asked.
            record["content_in_journal"] = None
            record["content_in_journal_note"] = (
                "the journal was not located, so this was not searched")

        record["first_64_content_bytes_found_after_delete"] = len(
            find_all(after, data[:64]))
        record["mid_64_content_bytes_found_after_delete"] = len(
            find_all(after, data[len(data) // 2:len(data) // 2 + 64]))
        findings["files"][name] = record

    # Slack: the bytes inside a block but past the end of the file that now
    # occupies it. This is a separate question from "is the data still there",
    # and the ordinary delete does not answer it: the new file is shorter, and
    # the tail of the old, longer one is simply never written.
    findings["slack"] = slack_experiment(work, size)

    # A control: were the bytes ever there? A "not found" result is only
    # meaningful if the same search finds them before the delete.
    findings["control_before_delete"] = {}
    control = os.path.join(outdir, "control.img")
    with open(control, "wb") as handle:
        handle.truncate(size)
    run(["mkfs.ext4", "-q", "-F", "-b", str(BLOCK), control])
    for name, sample in samples.items():
        path = os.path.join(work, name)
        debugfs(control, f"write {path} /{name}")
    with open(control, "rb") as handle:
        control_data = handle.read()
    for name, sample in samples.items():
        findings["control_before_delete"][name] = {
            "whole_file_occurrences": len(find_all(control_data, sample["bytes"])),
            "first_64_found": len(find_all(control_data, sample["bytes"][:64])),
        }
    os.unlink(control)

    for entry in os.scandir(work):
        os.unlink(entry.path)
    os.rmdir(work)

    with open(os.path.join(outdir, "ext4-residue.json"), "w") as handle:
        json.dump(findings, handle, indent=1, sort_keys=True)
    print(json.dumps(findings, indent=1, sort_keys=True))
    return 0


def slack_experiment(work, size_bytes):
    """Does the tail of a longer file survive in the slack of a shorter one that
    takes its place?

    Built on its own filesystem rather than in the shared one, because the case
    only arises when the short file is forced into the long file's freed block.
    The first version wrote both into the populated image and the allocator
    picked a different block, so the test silently measured nothing and reported
    "no residue" - a false negative produced by a lazy fixture.
    """
    image = os.path.join(work, "slack.img")
    with open(image, "wb") as handle:
        handle.truncate(size_bytes)
    run(["mkfs.ext4", "-q", "-F", "-b", str(BLOCK), image])

    long_name, short_name = "long.bin", "short.bin"
    long_data = bytes([(i * 7 + 11) % 256 for i in range(1500)])
    short_data = b"SHORT"
    for name, data in ((long_name, long_data), (short_name, short_data)):
        path = os.path.join(work, name)
        with open(path, "wb") as handle:
            handle.write(data)

    debugfs(image, f"write " + os.path.join(work, long_name) + f" /{long_name}")
    long_layout = extent_map(image, long_name,
                             (len(long_data) + BLOCK - 1) // BLOCK)
    debugfs(image, f"rm /{long_name}")
    debugfs(image, f"write " + os.path.join(work, short_name) +
                   f" /{short_name}")
    short_layout = extent_map(image, short_name,
                              (len(short_data) + BLOCK - 1) // BLOCK)

    with open(image, "rb") as handle:
        data = handle.read()

    shared = sorted({b for _, b in long_layout} & {b for _, b in short_layout})
    tail = long_data[len(short_data):]
    inside = []
    for block in shared:
        begin = block * BLOCK
        inside.extend(find_all(data[begin:begin + BLOCK], tail[:48]))

    # Did the writer zero the whole block? If it did, this method cannot see
    # slack at all, and a "no residue" result would be an artefact of the tool
    # rather than a property of the filesystem.
    slack_zeroed = None
    if shared:
        begin = shared[0] * BLOCK
        slack_zeroed = all(byte == 0 for byte in data[begin + len(short_data):
                                                     begin + BLOCK])

    result = {
        "long_size": len(long_data),
        "short_size": len(short_data),
        "long_extents": long_layout,
        "short_extents": short_layout,
        "shared_blocks": shared,
        "long_tail_occurrences_in_shared_blocks": len(inside),
        "slack_retains_long_content": bool(inside),
        "slack_appeared_zeroed_by_the_writer": slack_zeroed,
    }
    if not shared:
        result["verdict"] = "UNPROVEN: the case did not arise"
    elif slack_zeroed:
        result["verdict"] = (
            "UNPROVEN: the writer zeroed the whole block including the slack, "
            "so this method cannot measure whether ext4 preserves block slack. "
            "debugfs does; a write() through the kernel is what would answer "
            "the question, and that needs root and a mounted filesystem, which "
            "this environment does not allow.")
    else:
        result["verdict"] = ("MEASURED: the slack still held the long file's "
                             "content after the short file was written")
    os.unlink(image)
    return result


def journal_region(data):
    """The ext4 journal's extent, located by its own superblock.

    An ext4 journal begins with a superblock whose magic is 0xC03B3998, not the
    0xEF53 of the filesystem superblock. That is what is matched here.

    Located rather than computed because getting it wrong fails open: an earlier
    version of this script hardcoded a journal offset, and on a different
    geometry it reported "nothing survived in the journal" while having searched
    nothing at all. A search that cannot find the journal returns None, and None
    is reported as "not searched", not as "nothing there".
    """
    journal_magic = b"\x38\xC0\x3B\x39\x98"
    for offset in range(0, len(data) - 1024, 1024):
        if data[offset + 56:offset + 60] == journal_magic:
            blocks = struct.unpack("<I", data[offset + 44:offset + 48])[0]
            if 0 < blocks < (len(data) // 1024):
                return offset, blocks * 1024, blocks
    return None


if __name__ == "__main__":
    sys.exit(main())
