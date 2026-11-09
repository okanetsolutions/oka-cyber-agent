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

The Elastic go-libaudit samples are distributed under Apache-2.0.
The linux-audit auparse tests are distributed under LGPL-2.1-or-later.
The original fixture's metadata is preserved, including its unrelated audit
key and UID below 1000; the fixture test checks metadata parsing, not that
these unrelated processes would pass the production scope filter.

End-to-end parser and spool tests construct explicit, synthetic SSH sessions
and command records separately, covering root and regular logins, the Oka
rule key, split and hex arguments, interleaved records and rejected sources.
Journal JSON framing in tests follows systemd's journald-audit.c: `_TRANSPORT`,
`_BOOT_ID` and `_AUDIT_ID` identify kernel audit records and MESSAGE starts
with the record type; `_SOURCE_REALTIME_TIMESTAMP` is the audit event time.
https://github.com/systemd/systemd/blob/v252/src/journal/journald-audit.c
