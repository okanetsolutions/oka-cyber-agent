Audit fixture provenance
========================

These are unchanged upstream audit records, not captures from a live host in
this workspace. Only selected whole lines were retained for the small files.

- `linux-audit-exec.log`: linux-audit/audit-userspace, auparse/test/test4.log,
  real multi-record exec events submitted for the auparse tests, including
  AArch64 toolchain invocations and long EXECVE records.
  https://github.com/linux-audit/audit-userspace/blob/master/auparse/test/test4.log
- `rhel7-hex.log`: EXECVE lines from elastic/go-libaudit,
  auparse/testdata/audit-rhel7.log, including a hex-encoded JSON argument.
  https://github.com/elastic/go-libaudit/blob/main/auparse/testdata/audit-rhel7.log
- `ubuntu16-login.log`: elastic/go-libaudit,
  auparse/testdata/audit-ubuntu16.log, successful and failed SSH audit logins.
  https://github.com/elastic/go-libaudit/blob/main/auparse/testdata/audit-ubuntu16.log

- `centos7-session.log`: the SSH PAM USER_START line from elastic/beats,
  auditbeat/module/auditd/testdata/centos7.log (Apache-2.0), retaining the
  authenticated user name before USER_LOGIN repeats only its numeric ID.
  https://github.com/elastic/beats/blob/main/auditbeat/module/auditd/testdata/centos7.log
- `apparmor-subj.log`: AppArmor confined records whose subject label is logged
  raw with its mode after a blank (`subj=/usr/sbin/cupsd (enforce)`), as on
  kernels up to 5.x. The USER_AUTH, ANOM_ABEND (stacked `//&` label) and ntpd
  SYSCALL lines are from hillu/linux-audit-parser-rs, src/testdata
  (`line-user-auth.txt`, `line-anom-abend-2.txt`, `line-broken-subj2.txt`,
  LGPL-3.0), cut before the `\x1d` that starts auditd's enrichment, which
  journald does not carry.
  https://github.com/hillu/linux-audit-parser-rs/tree/master/src/testdata
  The exec event (SYSCALL, EXECVE, CWD with `subj=docker-default (enforce)`)
  is from Reversenant/open-xp-rules-test (Apache-2.0),
  packages/system/normalization_formulas/UNIX_like/auditd/syslog_structured/syscall_process_start/tests/raw_24.txt,
  which stores the records as JSON: they are written back as `type=` lines with
  the event's own timestamp and ID, and the enrichment after `key=` is removed.
  https://github.com/Reversenant/open-xp-rules-test

The Elastic go-libaudit samples are distributed under Apache-2.0.
The linux-audit auparse tests are distributed under LGPL-2.1-or-later.
The original fixture's metadata is preserved, including its unrelated audit
key and UID below 1000; the fixture test checks metadata parsing, not that
these unrelated processes would pass the production scope filter.

End-to-end parser and spool tests construct explicit, synthetic SSH sessions
and command records separately, covering root and regular logins, the Oka
rule key or an earlier host rule key, split and hex arguments, interleaved records and rejected sources.
Journal JSON framing in tests follows systemd's journald-audit.c: `_TRANSPORT`,
`_BOOT_ID` and `_AUDIT_ID` identify kernel audit records and MESSAGE starts
with the record type; `_SOURCE_REALTIME_TIMESTAMP` is the audit event time.
https://github.com/systemd/systemd/blob/v252/src/journal/journald-audit.c
