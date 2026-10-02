# Reference images to supply

The recovery-accuracy experiment in `tools/carve-accuracy/` builds its own
images. That is enough to measure the carver against *known* ground truth, and it
is what the published results use. It is not enough to show the carver behaves
like every other carver on the images the forensic community actually publishes.

Those images could not be fetched from this machine. Network egress here allows
request headers and blocks response bodies: `raw.githubusercontent.com` returns
HTTP 200 with `size_download=0` for every request, and `cfreds.nist.gov` returns
525 behind its CDN. `github.com` HTML and `api.github.com` respond, which is how
the file listing below was obtained - but the image bytes do not come through.

## What to supply, and why each one

Drop the files in a directory and pass it to the scorer. Nothing about the
experiment changes: `score.py` compares a manifest of SHA-256 digests against
what a carver reports, so a reference image needs only a manifest, not an
interpretation.

### 1. DFRWS 2006 Forensic Challenge - the `dd1` FAT disk image

| | |
|---|---|
| Where | `https://www.dfrws.org/2006/DFRWS2006/DiskImages/` (also mirrored at `https://cfreds.nist.gov/dfrws/DFRWS2006/DiskImages/`) |
| Files | `dd1.r01`, `dd1.r02`, `dd1.r03`, `dd1.r04` - a split raw image, reassemble with `cat dd1.r0* > dd1.raw` |
| Size | ~250 MB reassembled |
| Why | FAT32, with deleted and partially-deleted files including a fragment inside a Word document. It is the reference for "what does a fragmented file look like", which is the case this carver is worst at. |

### 2. DFRWS 2009 Challenge - `nssal-thumb-fs.dd`

| | |
|---|---|
| Where | `https://github.com/dfrws/dfrws2009-challenge` → `materials/nssal-thumb-fs.dd.bz2` |
| Files | one, 4 MB compressed |
| Size | ~64 MB uncompressed |
| Why | a real filesystem image with a known file layout, small enough to scan in a test. The one image on this list whose host *is* reachable - only the body download is blocked. |

### 3. NIST CFReDS - `dfrws-2006-dd1` and one FAT/NTFS image

| | |
|---|---|
| Where | `https://cfreds.nist.gov/all/NIST/CFReDS/` |
| Files | `dfrws-2006-dd1.zip` plus any NTFS image from the Digital Forensics Reference Data Set |
| Why | an independent implementation of the same ground truth, so the digests can be cross-checked against someone else's answer rather than only this project's. |

### 4. Optional but valuable: a modern image with a filesystem this project has
not measured

Any recent ext4 or XFS image containing a mix of deleted, truncated and
partially-overwritten files. The matrix in
[FILESYSTEMS.md](FILESYSTEMS.md) has rows for ext2/ext3/ext4 and xfs that are
asserted from the format's design rather than from a measurement on those exact
filesystems - `docs/RESIDUE.md` §3 measured ext4 only, and only through
`debugfs`.

## How to use them

```sh
# 1. Assemble and decompress, if needed.
cat dd1.r0* > dd1.raw
bunzip2 nssal-thumb-fs.dd.bz2

# 2. Write a manifest: {"filename": {"sha256": "...", "size": N}, ...}
#    The experiment does not need the original files, only their digests,
#    so a manifest is enough and the images need not be re-derivable from it.

# 3. Carve, into a directory on a different filesystem. The tool refuses to
#    write recovered files onto the source, on purpose.
ledgerase-cli carve /path/to/dd1.raw --output-dir /path/to/recovered \
    --evidence /path/to/records/carve-dd1.json

# 4. Score. The same scorer, the same counts, the same precision/recall split.
python3 tools/carve-accuracy/score.py /path/to/manifests /path/to/dd1.carve.json \
    --scenario dd1
```

## What will be reported, and what will not

* Precision and recall separately, with the counts behind each, and
  high-confidence-only figures alongside.
* A file that is present but fragmented counted separately from one that is
  gone, because a signature carver cannot reach either but only one of them
  would be a loss.
* Anything this carver cannot see stated as a limit: no-magic-number files,
  unterminated formats whose length is inferred, and the 16 MiB cap on an
  inferred length.

Nothing will be reported as a "recovery rate" in the sense of a security
percentage. These are measurements of one technique on one medium under a
described procedure, and a different tool on the same medium will produce a
different number - which is why photorec is run alongside and reported next to
them.
