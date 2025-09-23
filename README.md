# Nmap Network Scan Report

**Date:** 2025-09-22
**Author:** Prudhvi Konakalla

---

## Overview

This repository contains the professional Nmap scan report and analysis for the 10.80.121.0/24 subnet. The original scans were run from a Kali Linux environment and used service/version detection, host discovery bypass (`-Pn`), specified port ranges, SYN stealth scans, and select Nmap Scripting Engine (NSE) scripts to gather additional host and service information.

The purpose of this README is to consolidate the full analysis and recommendations so it can be reviewed or shared via GitHub.

---

## Table of Contents

* [Scan Summary](#scan-summary)
* [Detailed Host Results](#detailed-host-results)

  * [10.80.121.223 — ETERNALTRUTH](#1080121223---eternaltruth)
  * [10.80.121.241 — DNS host (dnsmasq)](#1080121241---dns-host-dnsmasq)
  * [10.80.121.19 — No open ports reported](#108012119---no-open-ports-reported)
* [Commands Used](#commands-used)
* [Key Observations & Analysis](#key-observations--analysis)
* [Security Recommendations](#security-recommendations)
* [Attachments / Screenshots](#attachments--screenshots)
* [Next Steps Checklist](#next-steps-checklist)

---

## Scan Summary

* Target subnet: **10.80.121.0/24**
* Principal hosts of interest discovered: **10.80.121.223** and **10.80.121.241**.
* Scans indicated multiple exposed Windows RPC/SMB services on 10.80.121.223 and a minimal DNS service (dnsmasq 2.51) on 10.80.121.241.

---

## Detailed Host Results

### 10.80.121.223 — ETERNALTRUTH

**Identifying information**

* NetBIOS name: `ETERNALTRUTH`
* MAC: `38:D5:7A:36:77:AB` (Cloud Network Technology Singapore PTE.)
* OS: Windows (CPE: `cpe:/o:microsoft:windows`)

**Open / notable ports & services**

* `135/tcp` — Microsoft Windows RPC
* `139/tcp` — Microsoft Windows netbios-ssn (NetBIOS name: `ETERNALTRUTH`)
* `445/tcp` — Microsoft Windows microsoft-ds (SMB)
* `902/tcp`, `912/tcp` — VMware Authentication Daemon

**Scripted/NSE results (high level)**

* SMB signing: enabled but **not required** (security concern)
* SMB returned server time: `2025-09-22T06:11:10`
* Clock skew: `-3s` (minor, likely virtualization or sync differences)

**Analysis**

* Multiple RPC/SMB services are exposed to the scanned network. These services are high-value for attackers because they can be used for enumeration (shares, users, local accounts), lateral movement, and exploitation of known RPC/SMB vulnerabilities if the host is unpatched.
* VMware ports (902/912) suggest virtualization components which may provide additional attack surface if management interfaces are exposed.

### 10.80.121.241 — DNS host (dnsmasq)

**Identifying information**

* Port: `53/tcp` — Open
* Service: `dnsmasq 2.51`
* MAC: `0E:85:E1:13:2D:3E` (unknown vendor)

**Analysis**

* Host appears to be a DNS forwarder/caching resolver running `dnsmasq 2.51` and is minimally exposed (only port 53 visible). Running an outdated dnsmasq version may carry CVE risks depending on the exact release and local configuration (e.g., recursion allowed, DNSSEC configuration, response to large queries).
* Since only port 53 is open, focused DNS monitoring and hardening will significantly reduce risk.

### 10.80.121.19 — No open ports reported

* Host responded as up, but Nmap reported all ports in ignored/closed states. This indicates limited or no exposure at the time of scanning.

---

## Commands Used

Key Nmap commands used during assessment (as executed on Kali Linux):

```bash
# Single-port, DNS service check
nmap -sV -Pn -sA -p 53 -sC 10.80.121.241

# Multi-host, version detection across the /24 subnet
nmap -sV -Pn 10.80.121.19/24

# SYN stealth single-host full TCP port scan (no ping), with decoys
nmap -sV -Pn -sS -p- -D RND:10 10.80.121.223

# Focused SMB/NetBIOS/RPC script scans
nmap -sV -Pn -sC -sS -p 139 10.80.121.223
nmap -sV -Pn -sC -sS -p 135 10.80.121.223

# Full port scan of host 10.80.121.241
nmap -sV -Pn 10.80.121.241 -sS -p-
```

> Note: `-Pn` was used to bypass host discovery in these runs; NSE scripts (`-sC`) were used for basic scripted checks.

---

## Key Observations & Analysis

1. **High-risk services exposed on 10.80.121.223** — The presence of RPC and SMB (ports 135, 139, 445) increases attack surface for enumeration and exploitation. SMB signing being optional is a specific weakness that can enable man-in-the-middle tampering in certain network configurations.

2. **Virtualization management ports** — Ports 902 and 912 indicate VMware services; management interfaces should be restricted and patched.

3. **dnsmasq on 10.80.121.241** — A single open DNS port simplifies hardening, but dnsmasq versions should be checked against known CVEs and configured to limit recursion and abusive queries.

4. **MAC address vendor mapping** — MAC addresses suggest at least one host (10.80.121.223) runs on cloud infrastructure (Cloud Network Technology SGP), which may affect patching and management models.

5. **Temporal artifacts** — Clock skew is minor (–3s) and likely not indicative of deliberate tampering; still note for correlation across logs.

---

## Security Recommendations

These recommendations are prioritized for quick risk reduction.

### Immediate (high priority)

* **Limit SMB/RPC exposure**: Restrict ports 135, 139, 445 at the perimeter and internal firewalls to only necessary hosts/networks.
* **Enforce SMB signing**: Configure Group Policy or local policies to require SMB signing where supported.
* **Patch Windows hosts**: Ensure latest security updates are applied—especially for components that interact with RPC/SMB.
* **Harden dnsmasq**: Verify the installed dnsmasq version and apply updates. Limit recursion to internal clients and enable response rate limiting if available.

### Short-to-Medium term

* **Restrict VMware management**: Block/limit access to 902/912 to trusted management networks and use secure management workflows.
* **Enable logging & monitoring**: Monitor DNS queries and SMB authentication events; enable alerting for anomalous behaviors.
* **Regular scanning cadence**: Schedule periodic authenticated and unauthenticated scans to detect configuration drift.

### Long term

* **Penetration test**: Conduct an in-depth pentest on 10.80.121.223 focusing on SMB/RPC and any privileged services discovered.
* **Asset inventory & segmentation**: Map VMs and hosts, enforce least-privilege network segmentation, and adopt a zero-trust approach where practicable.

---

## Attachments / Screenshots

The original report referenced several screenshots (named in the report as `1.jpg`, `2.jpg`, `3.jpg`, `4.jpg`, `5.jpg`, `6.jpg`). Add these files to the repository under a directory such as `assets/` or `scans/` so the report renders correctly on GitHub.

Suggested structure:

```
/README.md
/scans/
  ├─ 1.jpg
  ├─ 2.jpg
  ├─ 3.jpg
  ├─ 4.jpg
  ├─ 5.jpg
  └─ 6.jpg
```



## Conclusion

This consolidated README captures the Nmap results and prioritized security recommendations. The most critical exposure is the Windows host `ETERNALTRUTH (10.80.121.223)` due to RPC/SMB services; immediate mitigation should focus on restricting exposure, patching, and enforcing SMB signing. The dnsmasq host presents a smaller but important surface for DNS hardening.

*Report prepared by Prudhvi Konakalla — 2025-09-22*
