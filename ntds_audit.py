#!/usr/bin/env python3

###############################################################################
#
# NTDS Audit v1.0
#
# Author: Charalampos Spanias (mollysec)
#
###############################################################################

import argparse
from pathlib import Path

VERSION = "1.0"

LM_EMPTY = "aad3b435b51404eeaad3b435b51404ee"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def info(msg):
    print(f"[*] {msg}")


def ok(msg):
    print(f"[+] {msg}")


def warn(msg):
    print(f"[!] {msg}")


def write_lines(path, lines):

    with open(path, "w") as f:

        for line in lines:
            f.write(f"{line}\n")


# ---------------------------------------------------------------------------
# NTDS Parsing
# ---------------------------------------------------------------------------

def parse_ntds_line(line):

    line = line.strip()

    if not line:
        return None

    enabled = "(status=Enabled)" in line

    record = line.split()[0]

    fields = record.split(":")

    if len(fields) < 4:
        return None

    username = fields[0]
    rid = fields[1]
    lm_hash = fields[2]
    nt_hash = fields[3]

    return {
        "raw": record,
        "username": username,
        "rid": rid,
        "lm": lm_hash,
        "ntlm": nt_hash,
        "enabled": enabled,
        "machine": username.endswith("$")
    }


def parse_ntds_file(path):

    entries = []

    with open(path, encoding="utf-8", errors="ignore") as f:

        for line in f:

            entry = parse_ntds_line(line)

            if entry:
                entries.append(entry)

    return entries


# ---------------------------------------------------------------------------
# Filters
# ---------------------------------------------------------------------------

def get_enabled(entries):

    return [e for e in entries if e["enabled"]]


def get_disabled(entries):

    return [e for e in entries if not e["enabled"]]


def get_machines(entries):

    return [e for e in entries if e["machine"]]


def get_users(entries):

    return [e for e in entries if not e["machine"]]


def apply_filter(entries, pattern):

    if not pattern:
        return entries, []

    kept = []
    removed = []

    for entry in entries:

        if pattern.lower() in entry["username"].lower():
            removed.append(entry)

        else:
            kept.append(entry)

    return kept, removed


# ---------------------------------------------------------------------------
# Hash Extraction
# ---------------------------------------------------------------------------

def extract_ntlm_hashes(entries):

    return sorted({
        e["ntlm"]
        for e in entries
    })


def extract_lm(entries):

    lm_users = [
        e for e in entries
        if e["lm"] != LM_EMPTY
    ]

    lm_hashes = sorted({
        e["lm"]
        for e in lm_users
    })

    return lm_users, lm_hashes


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():

    parser = argparse.ArgumentParser(
        description="NTDS Audit"
    )

    parser.add_argument(
        "-n",
        "--ntds",
        required=True,
        help="NTDS dump file"
    )

    parser.add_argument(
        "-o",
        "--output",
        default="ntds-audit",
        help="Output directory"
    )

    parser.add_argument(
        "-f",
        "--filter",
        help="Testing account filter (e.g. mollysec)"
    )

    args = parser.parse_args()

    output_dir = Path(args.output)
    output_dir.mkdir(parents=True, exist_ok=True)

    info(f"NTDS Audit v{VERSION}")

    entries = parse_ntds_file(args.ntds)

    enabled = get_enabled(entries)
    disabled = get_disabled(entries)

    machines = get_machines(enabled)
    users = get_users(enabled)

    users, filtered = apply_filter(
        users,
        args.filter
    )

    ntlm_hashes = extract_ntlm_hashes(users)

    lm_users, lm_hashes = extract_lm(users)

    # -----------------------------------------------------------------------
    # Output Files
    # -----------------------------------------------------------------------

    write_lines(
        output_dir / "ntds-enabled.txt",
        [e["raw"] for e in enabled]
    )

    write_lines(
        output_dir / "ntds-disabled.txt",
        [e["raw"] for e in disabled]
    )

    write_lines(
        output_dir / "ntds-machines.txt",
        [e["raw"] for e in machines]
    )

    write_lines(
        output_dir / "ntds-users-clean.txt",
        [e["raw"] for e in users]
    )

    write_lines(
        output_dir / "ntlm-hashes.txt",
        ntlm_hashes
    )

    write_lines(
        output_dir / "lm-users.txt",
        [e["raw"] for e in lm_users]
    )

    write_lines(
        output_dir / "lm-hashes.txt",
        lm_hashes
    )

    if filtered:

        write_lines(
            output_dir / "testing-accounts.txt",
            [e["raw"] for e in filtered]
        )

    # -----------------------------------------------------------------------
    # Summary
    # -----------------------------------------------------------------------

    print()

    ok(f"Enabled Accounts  : {len(enabled)}")
    ok(f"Disabled Accounts : {len(disabled)}")
    ok(f"User Accounts     : {len(users)}")
    ok(f"Machine Accounts  : {len(machines)}")
    ok(f"NTLM Hashes       : {len(ntlm_hashes)}")
    ok(f"LM Hashes         : {len(lm_hashes)}")

    if filtered:
        ok(f"Filtered Accounts : {len(filtered)}")

    print()
    ok(f"Output Directory  : {output_dir}")


if __name__ == "__main__":
    main()