#!/usr/bin/env python3

###############################################################################
# NTDS Audit v1.0
# Author: Charalampos Spanias (mollysec)
# Date: 22 May 2026
###############################################################################

import argparse
import json
import os
import sys

VERSION = "1.0"
LM_EMPTY = "aad3b435b51404eeaad3b435b51404ee"

# --- COLOURS ---
BLUE = "\033[1;34m"
GREEN = "\033[1;32m"
YELLOW = "\033[1;33m"
RED = "\033[1;31m"
NC = "\033[0m"

# ------------------------------------------------------------
# Logging
# ------------------------------------------------------------

def info(msg): print(f"{BLUE}[*] {msg}{NC}")
def ok(msg): print(f"{GREEN}[+] {msg}{NC}")
def warn(msg): print(f"{YELLOW}[!] {msg}{NC}")
def fail(msg):
    print(f"{RED}[!] {msg}{NC}")
    sys.exit(1)

# ------------------------------------------------------------
# Helpers
# ------------------------------------------------------------

def write_lines(path, lines):
    with open(path, "w") as f:
        for l in lines:
            f.write(l + "\n")

def load_json(path):
    with open(path) as f:
        return json.load(f)["data"]

def matches_filter(value, pattern):
    return pattern and pattern.lower() in value.lower()

# ------------------------------------------------------------
# Data model
# ------------------------------------------------------------

def parse_ntds_line(line):
    parts = line.strip().split()
    base = parts[0]

    fields = base.split(":")
    return {
        "username": fields[0],
        "lm": fields[2],
        "ntlm": fields[3],
        "enabled": "(status=Enabled)" in line,
        "disabled": "(status=Disabled)" in line,
    }

# ------------------------------------------------------------
# Processing
# ------------------------------------------------------------

def parse_ntds_file(path):
    enabled, disabled, machines, users = [], [], [], []

    with open(path) as f:
        for line in f:
            entry = parse_ntds_line(line)

            if entry["enabled"]:
                enabled.append(entry)
                if entry["username"].endswith("$"):
                    machines.append(entry)
                else:
                    users.append(entry)

            elif entry["disabled"]:
                disabled.append(entry)

    return enabled, disabled, machines, users


def apply_filter(users, pattern):
    if not pattern:
        return users, []

    warn(f"Applying filter: {pattern}")

    kept, filtered = [], []

    for u in users:
        if matches_filter(u["username"], pattern):
            filtered.append(u)
        else:
            kept.append(u)

    return kept, filtered


def extract_ntlm_hashes(users):
    return sorted({u["ntlm"] for u in users})


def extract_lm(users):
    lm_users = [u for u in users if u["lm"] != LM_EMPTY]
    lm_hashes = sorted({u["lm"] for u in lm_users})
    return lm_users, lm_hashes


def extract_admins(bh_users, pattern):
    admins = [
        u["Properties"]["samaccountname"]
        for u in bh_users
        if u["Properties"].get("admincount") and u["Properties"]["enabled"]
    ]

    if pattern:
        admins = [a for a in admins if not matches_filter(a, pattern)]

    return admins


def extract_domain_admins(bh_users, bh_groups, pattern):
    da_group = next(
        (g for g in bh_groups if g["ObjectIdentifier"].endswith("-512")),
        None
    )

    if not da_group:
        fail("Domain Admin group not found")

    da_sids = {m["ObjectIdentifier"] for m in da_group.get("Members", [])}

    da_users = [
        u["Properties"]["samaccountname"]
        for u in bh_users
        if u["ObjectIdentifier"] in da_sids
    ]

    if pattern:
        da_users = [u for u in da_users if not matches_filter(u, pattern)]

    return da_users


def normalize_username(username):
    return username.split("\\")[-1].lower()

def map_hashes(users, target_users):
    targets = {u.lower() for u in target_users}

    return [
        f"{u['username']}:{u['lm']}:{u['ntlm']}"
        for u in users
        if normalize_username(u["username"]) in targets
    ]


def map_potfile(users, potfile):
    pot = {}

    with open(potfile) as f:
        for line in f:
            if ":" in line:
                h, p = line.strip().split(":", 1)
                pot[h] = p

    return [
        f"{u['username']}:{pot[u['ntlm']]}"
        for u in users
        if u["ntlm"] in pot
    ]


def to_ntds_format(entries):
    return [f"{e['username']}:{e['lm']}:{e['ntlm']}" for e in entries]

# ------------------------------------------------------------
# Main
# ------------------------------------------------------------

def main():

    parser = argparse.ArgumentParser(
        description=f"NTDS Audit v{VERSION}",
        usage="python3 ntds-audit.py -n <ntds_file> [options]"
    )

    parser.add_argument("-n", "--ntds", metavar="NTDS_FILE")
    parser.add_argument("-u", "--users", metavar="USERS_JSON")
    parser.add_argument("-g", "--groups", metavar="GROUPS_JSON")
    parser.add_argument("-o", "--output", default="ntds-audit")
    parser.add_argument("-f", "--filter", metavar="PATTERN")
    parser.add_argument("-p", "--potfile", metavar="HASHCAT_POTFILE")

    # ✅ Prevent argparse from printing error twice
    if len(sys.argv) == 1:
        parser.print_help()
        sys.exit(0)

    args = parser.parse_args()

    # --- Required validation manually ---
    if not args.ntds:
        parser.print_help()
        print("\n[!] Missing required argument: --ntds\n")
        sys.exit(1)

    if not os.path.isfile(args.ntds):
        fail(f"NTDS file not found: {args.ntds}")

    # Optional validations
    if args.users and not os.path.isfile(args.users):
        fail("users.json not found")

    if args.groups and not os.path.isfile(args.groups):
        fail("groups.json not found")

    if args.potfile and not os.path.isfile(args.potfile):
        fail("Potfile not found")

    os.makedirs(args.output, exist_ok=True)
    out = lambda x: f"{args.output}/{x}"

    info(f"NTDS Audit v{VERSION} starting...")

    # ------------------------------------------------------------
    # STEP 1: Parsing
    # ------------------------------------------------------------
    info("Parsing NTDS...")
    total_records = sum(1 for _ in open(args.ntds))

    enabled, disabled, machines, users = parse_ntds_file(args.ntds)

    ok(f"Total records: {total_records}")
    ok(f"Enabled: {len(enabled)} | Disabled: {len(disabled)}")
    ok(f"Users: {len(users)} | Machines: {len(machines)}")

    # ------------------------------------------------------------
    # STEP 2: Filtering
    # ------------------------------------------------------------
    users, filtered_users = apply_filter(users, args.filter)

    write_lines(out("ntds-enabled.txt"), to_ntds_format(enabled))
    write_lines(out("ntds-disabled.txt"), to_ntds_format(disabled))
    write_lines(out("ntds-machine.txt"), to_ntds_format(machines))
    write_lines(out("ntds-users-clean.txt"), to_ntds_format(users))

    if filtered_users:
        write_lines(out("testing-accounts.txt"), to_ntds_format(filtered_users))
        warn(f"Filtered accounts: {len(filtered_users)}")

    # ------------------------------------------------------------
    # STEP 3: NTLM
    # ------------------------------------------------------------
    ntlm_hashes = extract_ntlm_hashes(users)
    write_lines(out("ntlm-hashes.txt"), ntlm_hashes)

    ok(f"Unique NTLM hashes: {len(ntlm_hashes)}")

    # ------------------------------------------------------------
    # STEP 4: LM
    # ------------------------------------------------------------
    lm_users, lm_hashes = extract_lm(users)

    if lm_hashes:
        warn(f"LM hashes detected: {len(lm_hashes)}")
        write_lines(out("lm-hashes.txt"), lm_hashes)
        write_lines(out("lm-users.txt"), to_ntds_format(lm_users))
    else:
        ok("No LM hashes detected")

    # ------------------------------------------------------------
    # STEP 5: Privileged (optional)
    # ------------------------------------------------------------
    if args.users:
        bh_users = load_json(args.users)

        admins = extract_admins(bh_users, args.filter)
        write_lines(out("admin-users.txt"), admins)

        admin_hashes = map_hashes(users, admins)
        write_lines(out("admin-hashes.txt"), admin_hashes)

        ok(f"Privileged accounts: {len(admins)}")

    # ------------------------------------------------------------
    # STEP 6: Domain Admins (optional)
    # ------------------------------------------------------------
    if args.users and args.groups:
        bh_users = load_json(args.users)
        bh_groups = load_json(args.groups)

        da_users = extract_domain_admins(bh_users, bh_groups, args.filter)
        write_lines(out("domain-admins.txt"), da_users)

        da_hashes = map_hashes(users, da_users)
        write_lines(out("domain-admin-hashes.txt"), da_hashes)

        ok(f"Domain Admins: {len(da_users)}")

    # ------------------------------------------------------------
    # STEP 7: Potfile (optional)
    # ------------------------------------------------------------
    if args.potfile:
        info("Mapping cracked hashes...")
        mapped = map_potfile(users, args.potfile)
        write_lines(out("mapped-passwords.txt"), mapped)
        ok(f"Cracked credentials: {len(mapped)}")

    ok("Done")
    ok(f"Output: {args.output}")

# ------------------------------------------------------------

if __name__ == "__main__":
    main()