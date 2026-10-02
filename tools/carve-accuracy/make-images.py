#!/usr/bin/env python3
"""Build the medium images used by the recovery-accuracy experiment.

Scenarios, each producing one image plus a manifest of what was really on it:

  contiguous  files written and deleted, their blocks never reused   (case A)
  fragmented  a file whose extents the allocator scattered            (case B)
  quickfmt    a populated filesystem re-created over itself          (case C)
  overwritten files deleted, then part of each one's region replaced (case D)

Two things this script is careful about, both of which produced wrong numbers
in an earlier version:

* **Blocks are not reused before the measurement.** A file deleted while the
  script is still creating files has its blocks handed back to the allocator
  and the next file is written on top of it. That looks exactly like a carver
  failure and is not one.

* **The manifest is measured, not intended.** After the image is built, every
  file's bytes are searched for *in the finished image*. A file the scenario
  believed it had left behind but that the format's own metadata overwrote is
  recorded as absent, and the scorer does not count it as a miss. Without this
  the quick-format case produced six "misses" for files that were simply gone.

The images are built with debugfs rather than by mounting, so this needs no
root and touches no real filesystem. That is a limitation worth stating: the
allocator behaviour of a mounted ext4 may differ, and the fragmentation case
depends on the allocator entirely.
"""

import argparse
import hashlib
import json
import os
import struct
import subprocess
import sys
import zlib

BLOCK = 1024
IMAGE_MB = 64


# --------------------------------------------------------------------------
# Deterministic file generators
# --------------------------------------------------------------------------

def make_png(width, height, seed):
    """A real PNG: valid CRCs, a real zlib stream, an IEND chunk."""
    def chunk(kind, payload):
        body = kind + payload
        return (struct.pack(">I", len(payload)) + body +
                struct.pack(">I", zlib.crc32(body) & 0xFFFFFFFF))

    rows = []
    for y in range(height):
        row = bytearray([0])          # filter type 0
        for x in range(width):
            row += bytes([(x * 7 + y * 3 + seed) % 256,
                          (x * 11 + y * 5 + seed * 2) % 256,
                          (x * 13 + y + seed * 3) % 256])
        rows.append(bytes(row))
    raw = b"".join(rows)
    header = struct.pack(">IIBBBBB", width, height, 8, 2, 0, 0, 0)
    return (b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", header) +
            chunk(b"IDAT", zlib.compress(raw, 6)) + chunk(b"IEND", b""))


def make_pdf(pages, seed):
    body = b"%PDF-1.4\n"
    for i in range(pages):
        payload = bytes([(i * 31 + seed * 17 + j) % 256 for j in range(600)])
        body += (b"%d 0 obj\n<< /Type /Page /Contents %d 0 R >>\nstream\n"
                 % (i + 1, i + 1))
        body += payload + b"\nendstream\nendobj\n"
    body += b"trailer\n<< /Root 1 0 R >>\n%%EOF\n"
    return body


def make_gzip(payload_size, seed):
    raw = bytes([(i * 3 + seed) % 256 for i in range(payload_size)])
    return (b"\x1f\x8b\x08\x00" + struct.pack("<I", 0) + b"\x00\x03" +
            zlib.compress(raw, 6)[2:-4] +
            struct.pack("<II", zlib.crc32(raw) & 0xFFFFFFFF, len(raw)))


def make_text(size, seed):
    words = [b"alpha", b"bravo", b"charlie", b"delta", b"echo", b"foxtrot"]
    out = bytearray()
    i = seed
    while len(out) < size:
        out += words[i % len(words)] + b" "
        i += 1
    return bytes(out[:size])


def make_binary(size, seed):
    # No magic number anywhere: the case signature carving cannot reach.
    state = (seed * 2654435761 + 1) & 0xFFFFFFFF
    out = bytearray()
    while len(out) < size:
        state = (state * 1103515245 + 12345) & 0xFFFFFFFF
        out.append((state >> 16) & 0xFF)
    return bytes(out[:size])


GENERATORS = {
    "png": lambda seed: make_png(60, 60, seed),
    "png_big": lambda seed: make_png(200, 200, seed),
    "pdf": lambda seed: make_pdf(12 + seed, seed),
    "gz": lambda seed: make_gzip(20000, seed),
    "txt": lambda seed: make_text(12000, seed),
    "bin": lambda seed: make_binary(30000, seed),
}


# --------------------------------------------------------------------------
# ext4 helpers
# --------------------------------------------------------------------------

def run(args, **kwargs):
    return subprocess.run(args, check=True, capture_output=True, **kwargs)


def mkfs(path, size_bytes):
    with open(path, "wb") as handle:
        handle.truncate(size_bytes)
    run(["mkfs.ext4", "-q", "-F", "-b", str(BLOCK), path])


def quick_format_over(image_path, size_bytes, workdir):
    """Writes a fresh filesystem's structures over a populated image, leaving
    the data blocks alone. This is what a "quick format" of a partition does.

    It cannot be done with `mkfs.ext4 <image>`: measured on this host,
    mke2fs 1.47.4 *zeroes* a regular file it is given, with and without
    `-E assume_storage_prezeroed=1`. A partition is not zeroed, which is the
    whole reason a quick format is not a sanitization. So the set of blocks a
    fresh mkfs writes is computed here - by formatting an empty image of the
    same geometry and diffing it against zeroes - and exactly those blocks are
    copied over the populated one.

    Stated plainly: this is a *construction* of a quick-formatted medium, not a
    measurement of mke2fs. It is the closest a file-backed experiment gets, and
    the construction is reproducible.
    """
    fresh = os.path.join(workdir, "fresh.img")
    mkfs(fresh, size_bytes)

    with open(fresh, "rb") as handle:
        formatted = handle.read()

    # A block counts as "written by mkfs" when the freshly formatted image has
    # something in it. Blocks that are all zero there are ones mke2fs left
    # alone, so they must be left alone here too.
    touched = [i for i in range(0, len(formatted), BLOCK)
               if any(formatted[i:i + BLOCK])]

    with open(image_path, "r+b") as handle:
        for index in touched:
            handle.seek(index)
            handle.write(formatted[index:index + BLOCK])

    os.unlink(fresh)
    return len(touched)


def debugfs(image, request, write=True):
    args = ["debugfs"] + (["-w"] if write else []) + ["-R", request, image]
    return subprocess.run(args, capture_output=True, text=True)


def write_file(image, name, data, workdir):
    tmp = os.path.join(workdir, name.replace("/", "_"))
    with open(tmp, "wb") as handle:
        handle.write(data)
    result = debugfs(image, f"write {tmp} /{name}")
    if result.returncode != 0:
        raise RuntimeError(f"debugfs write {name} failed: {result.stderr}")


def remove_file(image, name):
    debugfs(image, f"rm /{name}")


def extent_map(image, name, file_blocks):
    """How many separate runs of blocks the file occupies, and where each of its
    blocks lives.

    Recorded rather than assumed. An earlier version of this script labelled a
    file 'contiguous' on the strength of having written it sequentially, and the
    allocator disagreed; the label would have been a claim about the filesystem
    that was never checked.

    debugfs prints extents in the form
        (0-29):4417-4446, (30-59):4507-4536
    where the first pair is the file's own block numbering and the second is
    where those blocks are on the medium.
    """
    result = debugfs(image, "stat /" + name.lstrip("/"), write=False)
    lines = [l.strip() for l in result.stdout.splitlines()
             if l.startswith("(") and "):" in l]
    if not lines:
        return 0, []

    text = " ".join(lines)
    # Drop the (ETB0) metadata extent, which is the extent tree itself.
    text = text.replace("(ETB0):", "")
    pairs = []
    runs = 0
    for chunk in text.split(","):
        chunk = chunk.strip()
        if not chunk or ":" not in chunk:
            continue
        runs += 1
        file_range, image_range = chunk.split(":")
        file_range = file_range.strip("() ").split("-")
        image_range = image_range.strip("() ").split("-")
        first_file = int(file_range[0])
        last_file = int(file_range[-1])
        first_image = int(image_range[0])
        for step in range(last_file - first_file + 1):
            if first_file + step < file_blocks:
                pairs.append((first_file + step, first_image + step))
    return runs, pairs


# --------------------------------------------------------------------------
# Presence measurement
# --------------------------------------------------------------------------

def probe_of(data):
    """A 64-byte window from the middle: distinctive, and short enough to search
    for without pulling the whole file into memory on every offset."""
    if len(data) <= 64:
        return data
    start = (len(data) - 64) // 2
    return data[start:start + 64]


def find_bytes(haystack, needle):
    out = []
    index = haystack.find(needle)
    while index != -1:
        out.append(index)
        index = haystack.find(needle, index + 1)
    return out


def measure(image, manifest, payloads):
    """Replaces each entry's `on_medium_at_carve_time` with what the finished
    image actually contains.

    A whole-file byte search answers the wrong question for a fragmented file:
    a file whose extents are scattered is *intact* and a linear search will not
    find it, so it would be scored as a carver failure when nothing was lost.
    So the block-level layout recorded at write time is used to check each
    file's blocks individually, and only then is a verdict assigned.
    """
    with open(image, "rb") as handle:
        data = handle.read()

    for name, entry in manifest.items():
        data_bytes = payloads[name]
        layout = entry.get("_blocks")   # [(file_block_index, image_block), ...]

        if layout:
            intact = 0
            for file_block, image_block in layout:
                begin = file_block * BLOCK
                end = min(begin + BLOCK, len(data_bytes))
                if begin >= len(data_bytes):
                    continue     # an extent block the file never reached
                want = data_bytes[begin:end]
                have = data[image_block * BLOCK:image_block * BLOCK + len(want)]
                if want == have:
                    intact += 1
            entry["blocks_total"] = len(layout)
            entry["blocks_intact"] = intact
            entry["fraction_intact"] = intact / len(layout) if layout else None
        else:
            entry["blocks_total"] = 0
            entry["blocks_intact"] = 0
            entry["fraction_intact"] = None

        offsets = find_bytes(data, data_bytes)
        probe_offsets = find_bytes(data, probe_of(data_bytes))

        entry["whole_file_present"] = bool(offsets)
        entry["on_medium_at_carve_time"] = bool(offsets)
        entry["content_probe_offsets"] = probe_offsets[:8]

        if offsets:
            entry["verdict"] = "whole file present, byte for byte"
        elif entry["blocks_total"] and entry["blocks_intact"] == entry["blocks_total"]:
            entry["verdict"] = ("all of the file's blocks are intact but the "
                                "file is not contiguous: fragmentation, not loss")
        elif entry["blocks_intact"]:
            entry["verdict"] = (f"{entry['blocks_intact']} of "
                                f"{entry['blocks_total']} blocks intact: partly "
                                "overwritten")
        else:
            entry["verdict"] = "gone: none of the file's blocks survived"


# --------------------------------------------------------------------------
# Scenarios
# --------------------------------------------------------------------------

def scenario_contiguous(image, workdir, manifest, payloads):
    """Files written contiguously, then deleted. The baseline case.

    The first file is written straight after mkfs into an empty filesystem,
    which is the condition under which ext4 gives a file one unbroken run of
    blocks. The extent count is read back from the inode.
    """
    mkfs(image, IMAGE_MB * 1024 * 1024)

    entries = []

    def add(name, data, note):
        blocks = (len(data) + BLOCK - 1) // BLOCK
        runs, layout = extent_map(image, name, blocks)
        entries.append((name, data))
        payloads[name] = data
        manifest[name] = {
            "sha256": hashlib.sha256(data).hexdigest(),
            "size": len(data),
            "kind": name.rsplit(".", 1)[-1],
            "note": note,
            "extents": runs,
            "_blocks": layout,
            "on_medium_at_carve_time": True,
        }

    first = GENERATORS["png_big"](3)
    write_file(image, "/contiguous.png", first, workdir)
    add("contiguous.png", first,
        "written into an empty filesystem, then deleted")

    for index, kind in enumerate(["png", "pdf", "gz", "png", "pdf", "gz",
                                  "png", "pdf"]):
        data = GENERATORS[kind](index + 1)
        name = f"doc{index:02d}.{kind}"
        write_file(image, name, data, workdir)
        add(name, data, "written, deleted, extent not reused")

    for name, _ in entries:
        remove_file(image, name)


def scenario_fragmented(image, workdir, manifest, payloads):
    """Files whose extents the allocator scattered.

    The targets are PNGs, so they are files a signature carver *would* find if
    they were contiguous. What happens to them says something about
    fragmentation rather than about magic numbers.
    """
    mkfs(image, IMAGE_MB * 1024 * 1024)

    # Fill, delete every third, then write: the new files have to use the holes
    # and their extents end up scattered.
    fillers = []
    for index in range(220):
        data = GENERATORS["bin"](index + 1)
        name = f"fill{index:03d}.bin"
        write_file(image, name, data, workdir)
        fillers.append((index, name))
    for index, name in fillers:
        if index % 3 == 0:
            remove_file(image, name)

    for name, seed, note in [
            ("target.png", 7, "written into the fragmented free space"),
            ("scattered.png", 9, "written into the fragmented free space, "
                                  "then deleted")]:
        data = GENERATORS["png_big"](seed)
        write_file(image, "/" + name, data, workdir)
        blocks = (len(data) + BLOCK - 1) // BLOCK
        runs, layout = extent_map(image, "/" + name, blocks)
        payloads[name] = data
        manifest[name] = {
            "sha256": hashlib.sha256(data).hexdigest(),
            "size": len(data),
            "kind": "png",
            "note": note,
            "extents": runs,
            "_blocks": layout,
            "on_medium_at_carve_time": True,
        }
    # Deleted last, so nothing is written on top of them.
    for name, _, _ in [("target.png", 7, ""), ("scattered.png", 9, "")]:
        remove_file(image, "/" + name)


def scenario_quickfmt(image, workdir, manifest, payloads):
    """A populated filesystem re-created over itself.

    This is the quick-format case: mkfs writes a fresh set of metadata over the
    old one and does not erase the data blocks. Which files survive depends
    entirely on where the format put its own structures, so the outcome is
    measured afterwards rather than assumed either way.
    """
    mkfs(image, IMAGE_MB * 1024 * 1024)

    entries = []
    for index, kind in enumerate(["png", "pdf", "gz", "txt", "png", "pdf"]):
        data = GENERATORS[kind](index + 20)
        name = f"old{index:02d}.{kind}"
        write_file(image, name, data, workdir)
        blocks = (len(data) + BLOCK - 1) // BLOCK
        runs, layout = extent_map(image, name, blocks)
        payloads[name] = data
        manifest[name] = {
            "sha256": hashlib.sha256(data).hexdigest(),
            "size": len(data),
            "kind": kind,
            "note": "written, then a fresh filesystem was written over it",
            "extents": runs,
            "_blocks": layout,
            "on_medium_at_carve_time": True,
        }
        entries.append(name)
    for name in entries:
        remove_file(image, name)

    # The quick format: a fresh filesystem's structures written over the old
    # ones, data blocks untouched.
    touched = quick_format_over(image, IMAGE_MB * 1024 * 1024, workdir)
    for entry in manifest.values():
        entry["note"] = (f"written, then a fresh filesystem's {touched} written "
                         "blocks were copied over it")


def scenario_overwritten(image, workdir, manifest, payloads):
    """Files deleted, then part of each one's region overwritten.

    The overwrite is what the allocator does when a new file lands on freed
    space, which is the ordinary case. How much of the old file survives is
    measured afterwards: "partly there" and "gone" are different verdicts and
    only one of them is a carver failure.
    """
    mkfs(image, IMAGE_MB * 1024 * 1024)

    entries = []
    for index, kind in enumerate(["png", "pdf", "gz", "png"]):
        data = GENERATORS[kind](index + 40)
        name = f"half{index:02d}.{kind}"
        write_file(image, name, data, workdir)
        blocks = (len(data) + BLOCK - 1) // BLOCK
        runs, layout = extent_map(image, name, blocks)
        payloads[name] = data
        manifest[name] = {
            "sha256": hashlib.sha256(data).hexdigest(),
            "size": len(data),
            "kind": kind,
            "note": "deleted, then new files were written over its freed blocks",
            "extents": runs,
            "_blocks": layout,
            "on_medium_at_carve_time": True,
        }
        entries.append(name)
    # Deleted only once everything is written, so the fills below are what
    # reuses the space, not the script's own writes.
    for name in entries:
        remove_file(image, name)

    # Fillers small enough that they take part of the freed extents and leave
    # the rest. Fillers as large as the originals wiped them completely, which
    # is a different case with a different answer and no information about the
    # "partly overwritten" one.
    for index in range(3):
        data = GENERATORS["bin"](index + 90)[:6000]
        write_file(image, f"filler{index}.bin", data, workdir)


SCENARIOS = {
    "contiguous": scenario_contiguous,
    "fragmented": scenario_fragmented,
    "quickfmt": scenario_quickfmt,
    "overwritten": scenario_overwritten,
}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("scenario", choices=sorted(SCENARIOS))
    parser.add_argument("outdir")
    args = parser.parse_args()

    os.makedirs(args.outdir, exist_ok=True)
    workdir = os.path.join(args.outdir, ".work")
    os.makedirs(workdir, exist_ok=True)
    image = os.path.join(args.outdir, f"{args.scenario}.img")
    manifest = {}
    payloads = {}

    SCENARIOS[args.scenario](image, workdir, manifest, payloads)
    measure(image, manifest, payloads)

    manifest_path = os.path.join(args.outdir, f"{args.scenario}.manifest.json")
    with open(manifest_path, "w") as handle:
        json.dump(manifest, handle, indent=1, sort_keys=True)
    for handle in os.scandir(workdir):
        os.unlink(handle.path)
    os.rmdir(workdir)

    for entry in manifest.values():
        entry.pop("_blocks", None)

    whole = sum(1 for v in manifest.values() if v["whole_file_present"])
    print(f"{args.scenario}: {image} ({os.path.getsize(image)} bytes)")
    print(f"  {whole} of {len(manifest)} known file(s) present whole")
    for name, entry in sorted(manifest.items()):
        blocks = ""
        if entry["blocks_total"]:
            blocks = (f" [blocks {entry['blocks_intact']}/{entry['blocks_total']}"
                      f", extents={entry['extents']}]")
        print(f"    {name:20s} {entry['verdict']}{blocks}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
