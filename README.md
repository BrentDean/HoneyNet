# Honeynet / T-Pot Log Analysis Report

## 1. Executive Summary

This report summarizes an initial offline analysis of logs collected from a T-Pot honeynet deployed on a public VPS. The honeynet captured broad Internet scanning, SSH brute-force activity, protocol fingerprinting, and service-specific probes against exposed honeypot services.

The strongest finding so far is a repeated SSH credential attack pattern targeting Solana/crypto-related infrastructure terms. One source IP, `2.57.122.177`, repeatedly attempted usernames and passwords such as `solana`, `sol`, `raydium`, `firedancer`, `helius`, and related variants. After fake successful Cowrie logins, the actor immediately executed a system fingerprinting command:

```bash
/bin/./uname -s -v -n -r -m
```

This suggests automated reconnaissance for weakly secured Linux systems associated with Solana or cryptocurrency infrastructure.

## 2. Environment Overview

- Platform: T-Pot honeynet
- Hostname: `honeynet2`
- Public VPS IP: `168.119.178.95`
- Primary log archive: `tpot-logs-20260508-044029.tar.gz`
- Original uncompressed T-Pot data size: approximately `4.2 GB`
- Extracted log tree: `400 directories, 2291 files`

The honeynet was later shut down for safe offline analysis. The `tpot.service` was stopped and disabled, and Docker containers were verified to be no longer running.

## 3. Data Sources

The following T-Pot log sources were identified in the extracted archive:

| Source | Purpose |
|---|---|
| `cowrie/` | SSH/Telnet honeypot sessions, login attempts, commands, downloads |
| `suricata/log/eve.json*` | IDS alerts, protocol events, flow metadata |
| `dionaea/` | Malware capture and exploitation attempts |
| `p0f/log/p0f.json*` | Passive OS fingerprinting |
| `nginx/log/` | Web access logs for T-Pot-related web services |
| `honeytrap/` | Generic TCP/UDP service interaction data |
| `mailoney/` | SMTP honeypot activity |
| `redishoneypot/` | Redis honeypot activity |
| `wordpot/` | WordPress honeypot activity |
| `sentrypeer/` | SIP/VoIP-related honeypot data |
| `spiderfoot/` | SpiderFoot database and logs |
| `elk/` | Elasticsearch data store |

Sensitive files such as private keys and password files were also present in the extracted tree. These should not be published or committed to GitHub.

## 4. Initial Cowrie Findings

### 4.1 Top Cowrie Source IPs

The Cowrie logs showed repeated SSH/Telnet honeypot activity from several source IPs. The top observed sources included:

| Rank | Source IP | Cowrie Events |
|---:|---|---:|
| 1 | `2.57.122.177` | `5516` |
| 2 | `195.178.110.30` | `4659` |
| 3 | `92.118.39.63` | `3405` |
| 4 | `92.118.39.62` | `3019` |
| 5 | `195.178.110.218` | `2955` |
| 6 | `92.118.39.87` | `2846` |
| 7 | `2.57.122.208` | `2710` |
| 8 | `213.177.179.91` | `2194` |
| 9 | `186.96.145.241` | `2019` |
| 10 | `80.94.92.183` | `1674` |

These counts represent Cowrie event volume, not necessarily individual login attempts. One connection can generate multiple events such as session connect, SSH version exchange, key exchange, login attempt, command input, and session close.

### 4.2 Solana/Crypto-Themed SSH Credential Pattern

A detailed review of source IP `2.57.122.177` showed repeated credential attempts using Solana and crypto-related terms.

Observed usernames/passwords included:

```text
solana / solana
sol / sol
sol / 123
solv / solv
solv / 123456
solv / 12345678
sol / 123456
sol / 12345678
sol / solana
solana / sol
soldev / soldev
sol / dev
raydium / raydium
firedancer / firedancer
solscript / solscript
root / firedancer
root / raydium
helius / helius
```

Several of these are specific to the Solana ecosystem:

- `solana`
- `sol`
- `raydium`
- `firedancer`
- `helius`

This is more targeted than generic SSH brute forcing with usernames such as `root`, `admin`, or `test`.

### 4.3 Post-Login Fingerprinting Command

After Cowrie accepted fake credentials, the actor ran:

```bash
/bin/./uname -s -v -n -r -m
```

This command collects operating system and kernel details:

| Option | Meaning |
|---|---|
| `-s` | Kernel name |
| `-v` | Kernel version/build string |
| `-n` | Hostname |
| `-r` | Kernel release |
| `-m` | Machine architecture |

The command appears to be used for rapid system fingerprinting before deciding what payload or next step to use.

### 4.4 Cowrie Interpretation

The Cowrie evidence suggests automated SSH reconnaissance. The attacker or bot connected, attempted Solana-themed credentials, entered the fake shell after allowed credentials, fingerprinted the system with `uname`, and disconnected quickly.

This pattern is consistent with bot-driven scanning for weakly secured cryptocurrency infrastructure, possibly including validators, RPC nodes, developer servers, or wallet-related Linux systems.

### 4.5 Repeated Campaign Pattern From `2.57.122.177`

The extracted timeline for `2.57.122.177` shows that this was not a single isolated login attempt. The same source repeatedly returned over multiple days and reused a structured credential dictionary.

Observed activity windows included:

```text
2026-03-15
2026-03-16
2026-03-17
2026-03-18
2026-04-01
```

The pattern was highly repetitive:

1. Open SSH session.
2. Attempt one username/password pair.
3. Close session if the login failed.
4. If Cowrie accepted the fake login, immediately run `/bin/./uname -s -v -n -r -m`.
5. Close the session.
6. Return later and continue the same credential list.

The credential dictionary appears to mix Solana/crypto infrastructure terms with common Linux/server defaults. Examples include:

```text
solana / solana
sol / sol
sol / 123
solv / solv
soldev / soldev
solnode / solnode
node / node
validator / validator
raydium / raydium
firedancer / firedancer
helius / helius
ethereum / ethereum
ubuntu / ubuntu
operator / operator
system / system
root / firedancer
root / raydium
```

Several fake successful logins were followed by the exact same fingerprinting command. Successful pairs observed in the timeline included:

```text
solana / solana
sol / sol
sol / 123
solnode / solnode
node / node
validator / validator
ubuntu / ubuntu
solv / solv
```

This repeated behavior strengthens the conclusion that the activity was automated and campaign-like. The actor was likely scanning for weakly secured Linux systems associated with crypto infrastructure, then fingerprinting successful targets to decide what payload or exploitation path to use next.

## 5. Initial Suricata Findings

### 5.1 Top Suricata Alert Signatures

Suricata recorded a large volume of IDS alerts. The highest-count alerts were mostly Suricata engine or capture-layer events:

| Count | Signature |
|---:|---|
| `162026` | `SURICATA AF-PACKET truncated packet` |
| `155219` | `SURICATA IPv4 truncated packet` |
| `6807` | `SURICATA IPv6 truncated packet` |
| `6110` | `SURICATA STREAM 3way handshake wrong seq wrong ack` |
| `2339` | `SURICATA STREAM Packet with broken ack` |
| `1863` | `SURICATA TCPv4 invalid checksum` |
| `1799` | `SURICATA STREAM reassembly sequence GAP -- missing packet(s)` |

These indicate malformed traffic, incomplete captures, abnormal TCP behavior, retransmissions, and packet truncation. They are useful for understanding traffic quality and background Internet noise, but they are not always the most meaningful security findings.

### 5.2 Meaningful IDS Events

More useful rule hits included:

| Count | Signature | Meaning |
|---:|---|---|
| `6969` | `ET INFO SSH session in progress on Expected Port` | SSH traffic observed on normal SSH port |
| `2543` | `SURICATA SSH invalid banner` | SSH-like or malformed banner traffic |
| `2399` | `ET INFO SSH session in progress on Unusual Port` | SSH-like traffic observed on nonstandard ports |
| `634` | `ET INFO Potentially unsafe SMBv1 protocol in use` | SMBv1 probing or traffic |
| `69` | `ET SCAN Zmap User-Agent (Inbound)` | Internet-wide scanner behavior |
| `15` | `ET SCADA IEC-104 TESTFR (Test Frame) Confirmation` | Industrial-control/SCADA IEC-104 activity |
| `12` | `SURICATA MQTT malformed traffic` | MQTT/IoT-style malformed traffic |
| `9` | `ET SCADA IEC-104 STARTDT (Start Data Transfer) Confirmation` | Industrial-control/SCADA IEC-104 activity |

### 5.3 SCADA / ICS Evidence

Suricata recorded SCADA-specific IEC-104 alerts:

| Count | Signature |
|---:|---|
| `15` | `ET SCADA IEC-104 TESTFR (Test Frame) Confirmation` |
| `9` | `ET SCADA IEC-104 STARTDT (Start Data Transfer) Confirmation` |

This is useful local evidence because the alerts are not generic TCP/IP noise. They are protocol-specific Suricata signatures for IEC-104, an industrial-control/SCADA protocol commonly associated with electric power and industrial automation environments.

The local SCADA alert list shows repeated IEC-104 responses involving the honeynet IP `168.119.178.95` and external scanner/source systems. Observed external IPs included:

```text
87.236.176.120
198.235.24.205
64.62.197.62
64.62.197.64
142.93.120.48
162.142.125.199
64.62.197.167
64.62.197.174
167.94.138.198
205.210.31.94
65.49.1.232
65.49.1.237
185.247.137.144
167.94.146.61
198.235.24.89
159.89.87.59
198.235.24.234
65.49.1.152
65.49.1.161
```

Several of these IP ranges are consistent with Internet-scale measurement or scanning behavior. The alerts often show the honeynet IP as the source and the external IP as the destination because the Suricata signature fired on the IEC-104 confirmation response from the honeypot back to the scanner. Therefore, the listed destination ports in this extracted table are likely client-side ephemeral ports rather than the actual ICS service port. The BSI/Hetzner notices separately identified the exposed IEC-104 service as `2404/tcp`.

This local evidence also lines up with the external BSI/Hetzner notifications that reported the VPS as exposing IEC-104 on `2404/tcp`. The combination of local Suricata alerts and external provider notifications strengthens the conclusion that the honeynet was visible as an industrial-control-like target.

### 5.4 SSH Activity Observed by Suricata

Suricata observed repeated SSH activity against the VPS. Examples included SSH sessions on expected port `22` and SSH-like traffic on unusual ports such as:

```text
143
3306
8001
8282
9092
30000
```

This suggests broad service fingerprinting. Attackers were not only trying normal SSH but were also sending SSH-like traffic to other ports to identify hidden services or misconfigured systems.

### 5.4 Suricata Interpretation

The Suricata data indicates broad automated scanning and protocol probing. The most useful findings are SSH activity, unusual-port SSH detection, SMBv1 probing, Zmap scanner activity, MQTT malformed traffic, and SCADA/ICS protocol probes.

The very high count of truncated packets should be treated carefully. These events may reflect malformed traffic, capture-layer artifacts, or noisy Internet scanning rather than distinct attacks.

## 6. Timeline Notes

A dense SSH scanning window appeared around:

```text
2026-03-18 04:33 UTC to 2026-03-18 05:15 UTC
```

During this period, Suricata repeatedly observed SSH traffic from sources such as:

```text
2.57.122.177
92.118.39.62
92.118.39.63
195.178.110.218
207.180.229.239
186.96.145.241
80.94.92.66
45.148.10.196
3.130.168.2
18.116.101.220
```

This timeline should be correlated with Cowrie logs to determine which sources performed credential attempts, which credentials were tried, and which fake sessions progressed to command execution.

## 7. External Abuse/Exposure Notifications

The Hetzner/BSI abuse notifications add strong external validation to the honeynet report. These notifications show that independent Internet-wide scanning systems detected the honeypot as exposing services that resembled real vulnerable systems.

Important notifications included:

| Date reported | Report type | Detected exposure |
|---|---|---|
| 2026-03-18 | Android Debug Bridge | Open ADB-like service, model reported as `SM-G960F`, name `starltexx`, device `starlte` |
| 2026-03-18 | Elasticsearch/OpenSearch | Open Elasticsearch-like service, version `1.4.1`, instance name `USNYES01` |
| 2026-03-18 | SNMP | Open SNMP-like service reporting `Siemens, SIMATIC, S7-300` |
| 2026-03-18 | SMB backdoor | SMB/MS17-010-style backdoor detection on port `445/tcp` |
| 2026-03-18 | Industrial control system | IEC-104 exposed on `2404/tcp` |
| 2026-04-01 | Industrial control system | IEC-104 exposed on `2404/tcp` |
| 2026-04-01 | SNMP | Open SNMP-like service reporting `Siemens, SIMATIC, S7-300` |

These messages should be interpreted carefully. Hetzner stated that the notifications do not necessarily mean the server was involved in abuse; they indicate that the server appeared to expose potentially exploitable services. In this case, that matches the purpose of the T-Pot deployment: honeypot containers intentionally impersonated vulnerable or exposed services to attract scanning and interaction.

The notifications are useful because they show that the honeynet was not only receiving random attacker traffic, but was also visible to large-scale Internet measurement and reporting systems. The server was identified as resembling multiple exposed service categories, including Android ADB, Elasticsearch, SNMP/Siemens S7, IEC-104 industrial control, and SMB backdoor exposure.

Exact timestamp correlation between the abuse reports and local honeypot logs may be limited. The BSI timestamps indicate when an external scanner identified the exposed service, but the corresponding honeypot may not log the scanner request in the same format, may rotate logs, or may only record selected application-layer interactions. Therefore, the abuse notices should be treated primarily as external validation of exposed honeypot service profiles, not as proof that every notice can be matched one-for-one to a local log entry.

This provides an important operational lesson: even educational honeypots can trigger provider abuse notifications when they intentionally expose high-risk-looking services. At the same time, these notices also show the defensive side of Internet scanning. Not every automated scanner is hostile. Some bots and measurement systems exist to identify exposed services, warn providers, and reduce harm before attackers abuse them. In this case, the BSI/Hetzner notifications functioned as a form of defensive Internet hygiene: they detected risky-looking exposed services and notified the server owner through the hosting provider.

A safer future configuration would restrict honeypot exposure to controlled lab networks, use explicit provider approval, or run the honeynet for a short defined window before shutting down and analyzing logs offline.

## 8. Security Handling Notes

The extracted log set should be handled as potentially sensitive and potentially dangerous.

Recommended precautions:

1. Do not execute binaries or scripts recovered from honeypot data.
2. Do not upload the full archive publicly.
3. Do not commit extracted logs to GitHub.
4. Keep private keys, password files, and configuration files out of reports.
5. Analyze captured files using hashes, metadata, and sandboxed tools.
6. Keep the original archive read-only after verification.

## 8. Recommended Next Analysis Steps

### 8.1 Cowrie

- Count top usernames.
- Count top passwords.
- Count username/password pairs.
- Extract successful fake logins.
- Extract commands typed after fake login.
- Identify downloaded payloads and hash them.
- Group attackers by `/24` subnet.

### 8.2 Suricata

- Filter out `SURICATA ...` engine alerts to focus on ET/GPL rule hits.
- Count top external source IPs by signature.
- Extract SSH-related alerts only.
- Extract SMB-related alerts only.
- Extract SCADA/ICS-related alerts only.
- Correlate alert timestamps with Cowrie sessions.

### 8.3 Dionaea

- Locate captured binaries or payloads.
- Hash all captured files.
- Identify file types with `file`.
- Do not execute recovered samples.

### 8.4 p0f

- Summarize passive OS fingerprints.
- Compare OS fingerprint data to source IP clusters.

## 9. Preliminary Conclusions

The honeynet successfully captured real Internet background attack activity. The most important early finding is a Solana/crypto-themed SSH credential attack pattern, suggesting that some automated bot activity is actively searching for weakly secured cryptocurrency-related infrastructure.

Suricata confirmed broader scanning patterns, including SSH activity on expected and unusual ports, SMBv1 probing, Zmap scanner traffic, MQTT malformed traffic, and SCADA/ICS probes.

Overall, the data shows that a public VPS with exposed honeypot services quickly attracts automated scanning, credential attacks, and protocol-specific probes. The Cowrie logs provide the clearest attacker behavior because they show credential attempts and post-login commands, while Suricata provides broader network-level context.

## 10. Appendix: Commands Used

### Top Cowrie Source IPs

```bash
find cowrie -type f -name 'cowrie.json*' -print0 \
  | xargs -0 zcat -f \
  | jq -r '.src_ip? // empty' \
  | sort | uniq -c | sort -nr | head -25
```

### Cowrie Events for One Source IP

```bash
find cowrie -type f -name 'cowrie.json*' -print0 \
  | xargs -0 zcat -f 2>/dev/null \
  | jq -r '
      select(.src_ip=="2.57.122.177")
      | [.timestamp,.eventid,.username,.password,.input] | @tsv
    ' \
  | head -100
```

### Suricata Top Alert Signatures

```bash
find suricata/log -type f -name 'eve.json*' -print0 \
  | xargs -0 zcat -f 2>/dev/null \
  | jq -r 'select(.event_type=="alert") | .alert.signature' \
  | sort | uniq -c | sort -nr | head -50
```

### Suricata SSH Events

```bash
find suricata/log -type f -name 'eve.json*' -print0 \
  | xargs -0 zcat -f 2>/dev/null \
  | jq -r '
      select(.event_type=="alert")
      | select(.alert.signature | test("SSH"; "i"))
      | [.timestamp,.src_ip,.dest_ip,.dest_port,.alert.signature]
      | @tsv
    ' \
  | head -100
```

