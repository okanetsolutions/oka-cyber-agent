# Security Policy

Oka Cyber Agent runs on our customers' servers, so we treat every vulnerability report as a priority.

## Reporting a vulnerability

Please do not open a public issue for a security problem.

Report it privately through GitHub: open the [Security tab](https://github.com/okanetsolutions/oka-cyber-agent/security) of this repository and choose **Report a vulnerability**. Include:

- the affected version (`oka-cyber-agent version`) and Linux distribution,
- what an attacker can do and what they need (local user, network access, a malicious server response),
- steps or a proof of concept to reproduce it.

We acknowledge reports within 3 business days and keep you updated until the fix ships. We credit reporters in the release notes unless you prefer otherwise.

## Supported versions

Only the latest release receives security fixes. The installer always installs the latest release, and updating is a rerun of the install command.

## Scope

In scope: the agent binary, the install script, the systemd unit and the release artifacts (signatures, checksums, packages).

Of particular interest: anything that lets the agent read or send data beyond what the README promises, lets the dashboard or a network attacker make the agent act on the server, leaks the agent token, or bypasses redaction of log events.

The Oka Cyber dashboard and API are part of Oka Core and are handled through the same channel.
