# Prior-year source review — partial

User-supplied source: https://github.com/msu-cnm/mwccdc2026_invitational.git

The existing gitlink pins `2920a85a355b7a3758b2b2ec1a179891c284daee`. On 2026-11-13 the browser tool successfully retrieved README.md and BulkADPasswordChange.ps1 at that revision. Root AGENTS.md and CLAUDE.md returned 404 at both the pinned revision and main; none exists in the local checkout. Nested instructions remain unchecked because directory browsing failed.

## Reviewed script

[BulkADPasswordChange.ps1, pinned source](https://github.com/msu-cnm/mwccdc2026_invitational/blob/2920a85a355b7a3758b2b2ec1a179891c284daee/BulkADPasswordChange.ps1) — **requires adaptation; do not run unchanged**.

Windows/AD: requires elevation, AD cmdlets and ADUC. It creates a temporary group, recursively selects its users, generates or accepts passwords, prompts, resets selected accounts, optionally requires password change at logon, then removes the group. It prints passwords and exports plaintext CSV beside the script. A shared password can be supplied through a string parameter. Failures can leave partial resets and the temporary group; no transaction rollback, dependency coordination or PCR synchronization exists. See GeneratePassword, PasswordChangeUsers, Results and the final reset/cleanup block.

For 2022 AD, first inventory selected identities and application dependencies; coordinate each credential change and PCR update, protect secret handling, and verify dependent logins. Password rollback cannot be inferred from this script. The new Windows guard deliberately performs no password resets. No prior-year code was copied.

## Other inspected references

The [pinned README](https://github.com/msu-cnm/mwccdc2026_invitational/blob/2920a85a355b7a3758b2b2ec1a179891c284daee/README.md) describes a competition toolkit and warns that scripts require adaptation. Its advertised directory structure is not a verified file inventory.

[THIRD_PARTY.md on main](https://github.com/msu-cnm/mwccdc2026_invitational/blob/main/THIRD_PARTY.md) attributes a Sysmon configuration to SwiftOnSecurity and recommends tailoring it. The configuration itself was not retrieved or reviewed; this is not approval to deploy it. This reference is from main, not verified against the pin.

## Restoration and remaining review

The local prior-year directory remains empty. Explicit-URL `git ls-remote` and HTTPS archive/raw downloads were rejected by the environment proxy with CONNECT 403; direct access could not resolve GitHub. Browser access to GitHub directory trees and the recursive API tree also failed. The supplied URL is valid; another URL is not the missing input. A complete source archive or network access permitting Git/archive downloads is needed to restore the checkout and inventory remaining scripts. Browser excerpts are not a substitute for original source files.

The gitlink, Git configuration and existing guard scripts were preserved. No commit, merge or push was performed. After restoration, verify HEAD equals the pin, read any nested instructions, and inventory script paths, behavior, service assumptions, privileges and recovery. Review account deletion, blanket service shutdown, SSH authentication changes, firewall flush/default-deny, scoring-only source filters, forwarding/rp_filter changes, log clearing, upgrades and reboots against the current environment matrix before reuse. Full prior-year review and the populated-checkout acceptance requirement remain incomplete.
