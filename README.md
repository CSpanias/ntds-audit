# ntds-organiser

A Python-based tool designed to make Active Directory password audits more efficient.

Developed as a Proof of Concept to accompany [Password Audits Part 2: Hash Organisation](https://mollysec.com/posts/password-audits-part-2/).

It automates the post-processing of `secretsdump.py` output and combines NTDS data with BloodHound and Hashcat artefacts and produces clean datasets that are easier to review, crack, and report on.

## Installation

Recommended (uv):

```bash
# Install UV
curl -LsSf https://astral.sh/uv/install.sh | sh

# Install ntds-organiser via UV
uv tool install git+https://github.com/CSpanias/ntds-organiser

# Verify installation
ntds-organiser -h

# Update
uv tool upgrade ntds-organiser
```

Clone locally:

> Note: Python 3 must be installed and available in your PATH.

```bash
# Clone the repository
git clone https://github.com/CSpanias/ntds-organiser /opt/ntds-organiser

# Make the script executable
chmod +x /opt/ntds-organiser/ntds_audit.py

# Create a symbolic link
sudo ln -s /opt/ntds-organiser/ntds_audit.py /usr/local/bin/ntds-organiser

# Verify installation
ntds-organiser -h
```

## Features

The tool follows the same workflow typically used during an Active Directory password audit.

### NTDS Processing

* Parse `secretsdump.py` NTDS output
* Separate enabled and disabled accounts
* Identify machine accounts
* Filter testing accounts
* Extract NTLM hashes
* Detect and extract LM hashes
  
### BloodHound Integration

* Parse BloodHound ZIP exports directly
* Automatically extract Domain Admins
* Automatically extract domain password policy
* Remove testing accounts from generated datasets

### Password Mapping

* Parse Hashcat potfiles
* Map recovered passwords back to users
* Generate clean `username:password` datasets

## Usage

```bash
# Organise NTDS
ntds-organiser -n mollysec.com.ntds

# Filter Testing Accounts
ntds-organiser -n mollysec.com.ntds -f testing-acc-1,testing-acc-2

# Include BloodHound Data
ntds-organiser -n mollysec.com.ntds -b bloodhound.zip

# Map Recovered Passwords
ntds-organiser -n mollysec.com.ntds -p hashcat.potfile

# Full Workflow
ntds-organiser -n mollysec.com.ntds -b bloodhound.zip -p hashcat.potfile -f testing-acc-1,testing-acc-2
```

## Example Output

```bash
ntds-organiser -n mollysec.com.ntds -b bloodhound.zip -p company.potfile -f testing-acc-1,testing-acc-2

[*] NTDS Organiser v1.0

[!] Filtered Accounts (2)
    - MOLLYSEC\testing-acc-1
    - MOLLYSEC\testing-acc-2

[+] Enabled Accounts  : 422
[+] Disabled Accounts : 39
[+] User Accounts     : 314
[+] Machine Accounts  : 108
[+] NTLM Hashes       : 297
[+] LM Hashes         : 2
[+] Domain Admins     : 7
[+] Mapped Passwords  : 126

[+] Output Directory  : ntds-organiser
```

## Generated Files

### Core Outputs

* `enabled-users.txt`
* `domain-admins.txt`
* `domain-policy.txt`
* `ntds-users-clean.txt`
* `ntlm-hashes.txt`
* `mapped-passwords.txt`

### Conditional Outputs

> Generated only when applicable.

* `lm-users.txt`
* `lm-hashes.txt`

### Audit Artefacts

> Generated to assist troubleshooting and validation.

* `.ntds-disabled.txt`
* `.ntds-machines.txt`
* `.testing-accounts.txt`

### Example Domain Policy

```bash
Domain: MOLLYSEC.COM

Minimum Password Length : 14
Password History Length : 24
Lockout Threshold       : 5
Minimum Password Age    : 1 day
Maximum Password Age    : 90 days
```

## Requirements

* Python 3 (Core)
* BloodHound ZIP exports (optional)
* Hashcat potfiles (optional)

## Limitations

* The tool organises and maps password audit data but does not perform password cracking itself.
* Statistics and reporting are intentionally outside the scope of this tool.

## Roadmap
* ???
