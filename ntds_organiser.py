#!/usr/bin/env python3

###############################################################################
# NTDS Organiser v1.0
#
# Author: Charalampos Spanias (mollysec)
#
# Date: 22 July 2026
#
# Description:
#
# NTDS post-processing tool for Active Directory password audits.
#
# Focused on organising secretsdump output into datasets that are
# easier to review, crack, and report on.
###############################################################################

import argparse
import zipfile
import json
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

def apply_username_filter(usernames, patterns):

    if not patterns:
        return usernames

    filters = [
        p.strip().lower()
        for p in patterns.split(",")
        if p.strip()
    ]

    return [
        username
        for username in usernames
        if not any(
            f in username.lower()
            for f in filters
        )
    ]

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


def apply_filter(entries, patterns):

    if not patterns:
        return entries, []

    kept = []
    removed = []

    filters = [
        p.strip().lower()
        for p in patterns.split(",")
        if p.strip()
    ]

    for entry in entries:
        username = entry["username"].lower()

        if any(f in username for f in filters):
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
# BloodHound Data
# ---------------------------------------------------------------------------

def load_bloodhound_zip(zip_path):

    users = None
    groups = None
    domains = None

    with zipfile.ZipFile(zip_path) as z:

        for name in z.namelist():
            lower = name.lower()

            if lower.endswith("users.json"):
                users = json.loads(z.read(name).decode("utf-8"))

            elif lower.endswith("groups.json"):
                groups = json.loads(z.read(name).decode("utf-8"))

            elif lower.endswith("domains.json"):
                domains = json.loads(z.read(name).decode("utf-8"))

    return users, groups, domains

def extract_domain_admins(users_data, groups_data):

    if not users_data or not groups_data:
        return []

    users_lookup = {}

    for user in users_data["data"]:
        users_lookup[user["ObjectIdentifier"]] = user

    domain_admins = []

    for group in groups_data["data"]:

        if not group["ObjectIdentifier"].endswith("-512"):
            continue

        for member in group.get("Members", []):

            sid = member["ObjectIdentifier"]

            if sid not in users_lookup:
                continue

            user = users_lookup[sid]
            username = user["Properties"].get("samaccountname")

            if username:
                domain_admins.append(username)

    return sorted(set(domain_admins))

def extract_domain_policy(domains_data):

    if not domains_data:
        return {}

    domain = domains_data["data"][0]

    props = domain["Properties"]

    return {
        "domain": props.get("domain"),
        "minpwdlength": props.get("minpwdlength"),
        "pwdhistorylength": props.get("pwdhistorylength"),
        "lockoutthreshold": props.get("lockoutthreshold"),
        "minpwdage": props.get("minpwdage"),
        "maxpwdage": props.get("maxpwdage")
    }

# ---------------------------------------------------------------------------
# Potfile Parser and Username Mapping
# ---------------------------------------------------------------------------

def load_potfile(path):

    mapping = {}

    with open(path, encoding="utf-8", errors="ignore") as f:

        for line in f:
            line = line.rstrip()

            if ":" not in line:
                continue

            hash_value, password = (line.split(":", 1))
            mapping[hash_value.lower()] = password

    return mapping

def map_passwords(users, potfile):

    hash_lookup = load_potfile(potfile)
    mapped = []

    for user in users:
        nt_hash = user["ntlm"].lower()

        if nt_hash not in hash_lookup:
            continue

        mapped.append(f"{user['username']}:{hash_lookup[nt_hash]}")

    return mapped


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():

    parser = argparse.ArgumentParser(description="NTDS Audit")

    parser.add_argument("-n", "--ntds", required=True, help="NTDS dump file")
    parser.add_argument("-o", "--output", default="ntds-organiser", help="Output directory")
    parser.add_argument("-f", "--filter", help="Testing account filter (e.g. mollysec)")
    parser.add_argument("-b", "--bloodhound", help="BloodHound zip file")
    parser.add_argument("-p", "--potfile", help="Hashcat potfile")

    args = parser.parse_args()

    output_dir = Path(args.output)
    output_dir.mkdir(parents=True, exist_ok=True)

    info(f"NTDS Audit v{VERSION}")

    entries = parse_ntds_file(args.ntds)
    enabled = get_enabled(entries)
    disabled = get_disabled(entries)
    machines = get_machines(enabled)
    users = get_users(enabled)
    users, filtered = apply_filter(users, args.filter)

    if filtered:
        warn(f"Filtered Accounts ({len(filtered)})")

        for account in filtered:
            print(f" - {account['username']}")

    ntlm_hashes = extract_ntlm_hashes(users)

    lm_users, lm_hashes = extract_lm(users)

    domain_admins = []

    if args.bloodhound:
        users_json, groups_json, domains_json = (load_bloodhound_zip(args.bloodhound))

        if users_json is None:
            warn("users.json not found")

        if groups_json is None:
            warn("groups.json not found")

        if domains_json is None:
            warn("domains.json not found")

        domain_admins = extract_domain_admins(users_json, groups_json)
        domain_admins = apply_username_filter(domain_admins, args.filter)

        policy = extract_domain_policy(domains_json)
        
        if policy:
            write_lines(
                output_dir / "domain-policy.txt",
                [
                    f"Domain: {policy['domain']}",
                    "",
                    f"Minimum Password Length : {policy['minpwdlength']}",
                    f"Password History Length : {policy['pwdhistorylength']}",
                    f"Lockout Threshold       : {policy['lockoutthreshold']}",
                    f"Minimum Password Age    : {policy['minpwdage']}",
                    f"Maximum Password Age    : {policy['maxpwdage']}",
                ]
            )

    mapped_passwords = []

    if args.potfile:
        mapped_passwords = map_passwords(users, args.potfile)

    if mapped_passwords:
        write_lines(output_dir / "mapped-passwords.txt", mapped_passwords)


    # -----------------------------------------------------------------------
    # Output Files
    # -----------------------------------------------------------------------

    write_lines(
        output_dir / "enabled-users.txt",
        sorted(
            e["username"]
            for e in users
        )
    )

    write_lines(
        output_dir / ".ntds-enabled.txt",
        [e["raw"] for e in enabled]
    )

    write_lines(
        output_dir / ".ntds-disabled.txt",
        [e["raw"] for e in disabled]
    )

    write_lines(
        output_dir / ".ntds-machines.txt",
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

    if lm_users:

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
            output_dir / ".testing-accounts.txt",
            [e["raw"] for e in filtered]
        )

    if domain_admins:

        write_lines(
            output_dir / "domain-admins.txt",
            domain_admins
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

    if domain_admins:
        ok(f"Domain Admins    : {len(domain_admins)}")

    if mapped_passwords:
        ok(f"Mapped Passwords : {len(mapped_passwords)}")

    print()
    ok(f"Output Directory  : {output_dir}")


if __name__ == "__main__":
    main()