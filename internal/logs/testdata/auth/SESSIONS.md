Session fixture provenance
==========================

The existing debian-12.auth.log, ubuntu-24.04.auth.log and rocky-9.secure
captures contain Accepted and pam_unix(sshd:session) opened/closed messages
with matching PIDs (4400, 3942 and 287 respectively). Rocky's installed
OpenSSH logs under sshd-session. These were captured for the original auth
parser tests on 2026-10-31.

ubuntu-22.04.sessions.log and alpine-3.22.sessions.log were captured on
2026-11-09 in disposable Docker containers from ubuntu:22.04 and alpine:3.22.
Ubuntu used openssh-server, rsyslog and sudo; Alpine used openssh-server-pam,
linux-pam, BusyBox syslogd and sudo. Both ran a real public-key SSH login with
a PTY, sudo /usr/bin/id and logout, with UsePAM yes. Lines are unchanged.
Alpine logs under sshd-session.pam; its default non-PAM OpenSSH package does
not emit PAM session lines. The older alpine-3.20.messages fixture covers
that absence.

../journal/debian-12.sessions.jsonl was captured on 2026-11-09 in a disposable
jrei/systemd-debian:12 container with systemd-logind, openssh-server and sudo,
using the same SSH sequence. Only the journal cursor, timestamp, identifier,
message, trusted sender fields, MESSAGE_ID, SESSION_ID, LEADER and _BOOT_ID
used by the parser were retained; the structured fields were restored from
the original raw capture during review. The Accepted/open/close PID is 824. The trusted logind New session entry has
SESSION_ID=54 and LEADER=824, directly linking it to the SSH open event;
no logind line emits an event of its own. The logind ID is 54, and reading
/proc/self/sessionid inside that SSH session returned 54. That equality was
verified on this container only, not on all supported distributions.

../journal/rocky-9.sessions.jsonl was captured on 2026-11-12 in a disposable
rockylinux/rockylinux:9 container (systemd 252-67.el9_8.6, openssh-server
9.9p1-13.el9_8, authselect sssd profile) with the same SSH sequence and the
same retained fields. The password-auth stack runs pam_systemd before
pam_unix, so logind's New session 4 (LEADER=75) is logged 28 ms before
pam_unix(sshd:session) session opened from PID 75: the reverse of Debian.
The pam_sss.so warnings come from the missing sssd package and are unchanged.

Existing *.sudo.* fixtures contain real sudo I/O log TSIDs (01 or 000001).
They are sudo log identifiers, not SSH PIDs or logind IDs. No fixture asserts
that sudo has an SSH session key: the agent preserves TTY/TSID for the server's
correlation fallback without inventing a parent PID.

The systemd documentation says XDG_SESSION_ID is opaque and is often the
audit session ID, rather than guaranteeing equality:
https://www.freedesktop.org/software/systemd/man/252/pam_systemd.html
Alpine's PAM server is a separate package:
https://pkgs.alpinelinux.org/package/v3.22/main/x86/openssh-server-pam

The suggested quoted New session message format in the review is absent from
the systemd v256 and v257 source; both still emit New session %s of user %s.
Enrichment uses MESSAGE_ID, SESSION_ID and LEADER, independent of message text:
https://github.com/systemd/systemd/blob/v256/src/login/logind-session.c
https://github.com/systemd/systemd/blob/v257/src/login/logind-session.c

The exported session key deliberately remains the raw sshd PID required by
issue #21 and the stacked command capture work. PID reuse within or across
boots is a known correlation limit; adding a new key format needs a coordinated
consumer contract change. Internally, logind enrichment checks the boot and
nearby timestamps so unrelated or stale metadata is not attached.
