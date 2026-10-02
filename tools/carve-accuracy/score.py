#!/usr/bin/env python3
"""Score a carving run against a known manifest.

Reports precision and recall separately, with the counts that produced them,
per scenario. The two answer different questions and conflating them is how a
carver ends up looking good:

  recall    of the files this experiment knows were on the medium, how many came
            back byte-exact (SHA-256 equal to what was written)?
  precision of the files the carver reported, how many were real? A carver that
            reports 10 000 candidates and gets 8 files right has 100% recall and
            0.8% precision, which is a useless tool and a good one respectively
            only if you are told which is which.

A carved file whose digest is not in the manifest counts as a false positive.
That is a strict definition: a carver that finds a JPEG this script never wrote
is still right about the JPEG and still counted here. The caveat is stated in
the output rather than hidden in the arithmetic.

Usage:
  score.py <scenario-dir> <carve.json> [--label <name>]
"""

import argparse
import json
import os
import sys


def load_manifest(directory, scenario):
    path = os.path.join(directory, f"{scenario}.manifest.json")
    with open(path) as handle:
        return json.load(handle)


def score(manifest, carved, only_confidence=None):
    """Returns the counts. carved is a list of dicts with sha256/confidence.

    Ground truth is `whole_file_present`, measured by searching the finished
    image for the file's exact bytes - not "what the scenario intended to
    leave behind". A file the format's own metadata overwrote is therefore not
    counted as a miss.

    A file that is present but fragmented is counted separately. Its bytes are
    all still there, so calling it a miss would measure the carver's technique
    against the wrong question; but a signature carver genuinely cannot
    reassemble it, so counting it as recoverable would flatter the technique.
    """
    known = {}
    fragmented = {}
    for name, entry in manifest.items():
        if entry.get("whole_file_present"):
            known[entry["sha256"]] = (name, entry["size"])
        elif entry.get("blocks_intact") and entry.get("blocks_total") and \
                entry["blocks_intact"] == entry["blocks_total"]:
            fragmented[name] = entry

    considered = carved
    if only_confidence:
        considered = [c for c in carved
                      if c.get("confidence") == only_confidence]

    true_positives = []      # (known name, carved entry)
    false_positives = []
    for entry in considered:
        digest = entry.get("sha256")
        if digest in known:
            true_positives.append((known[digest][0], entry))
        else:
            false_positives.append(entry)

    found = {name for name, _ in true_positives}
    missed = sorted(set(n for n, _ in known.values()) - found)

    # A file found more than once is still one recovery; the duplicates are
    # counted so the report can say so rather than quietly dropping them.
    duplicates = len(true_positives) - len(found)

    return {
        "ground_truth_whole_files": len(known),
        "known_but_fragmented": sorted(fragmented),
        "reported": len(considered),
        "true_positives": len(found),
        "false_positives": len(false_positives),
        "missed": missed,
        "duplicate_hits": duplicates,
        "recall": (len(found) / len(known)) if known else None,
        "precision": ((len(found) / len(considered)) if considered else None),
        # .get throughout: a photorec result has no offset or signature, and
        # the scorer has to accept one from either tool.
        "matched": [{"file": name, "offset": e.get("offset"),
                     "length": e.get("length"),
                     "confidence": e.get("confidence"),
                     "signature": e.get("signature") or e.get("name")}
                    for name, e in true_positives],
        "unmatched_sample": [{"offset": e.get("offset"), "length": e.get("length"),
                              "signature": e.get("signature") or e.get("name"),
                              "confidence": e.get("confidence")}
                             for e in false_positives[:12]],
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("directory")
    parser.add_argument("carve_json")
    parser.add_argument("--scenario")
    parser.add_argument("--label", default="sanitizer")
    args = parser.parse_args()

    with open(args.carve_json) as handle:
        document = json.load(handle)

    # A carve record from this tool and a photorec-bench.py result have
    # different keys for the same facts; both are accepted so the two are
    # scored by exactly the same code.
    if "files" not in document and "files" in document.get("result", {}):
        document = document["result"]

    source = document.get("source") or document.get("image", "")
    scenario = args.scenario
    if scenario is None:
        stem = os.path.basename(source).rsplit(".", 1)[0]
        scenario = stem

    manifest = load_manifest(args.directory, scenario)
    carved = document.get("files", [])

    overall = score(manifest, carved)
    high = score(manifest, carved, only_confidence="high")

    report = {
        "tool": args.label,
        "scenario": scenario,
        "source": source,
        "source_unchanged": document.get("source_unchanged"),
        "candidates_examined": document.get("candidates_examined"),
        "all_reported": overall,
        "high_confidence_only": high,
        "known_files": {
            name: {"sha256": entry["sha256"], "size": entry["size"],
                   "kind": entry["kind"], "extents": entry.get("extents"),
                   "blocks_intact": entry.get("blocks_intact"),
                   "blocks_total": entry.get("blocks_total"),
                   "verdict": entry.get("verdict"),
                   "note": entry.get("note")}
            for name, entry in sorted(manifest.items())
        },
    }

    print(json.dumps(report, indent=1))
    return 0


if __name__ == "__main__":
    sys.exit(main())
