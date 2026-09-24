# Honeynet / T-Pot Log Analysis Report
<img width="1043" height="1050" alt="Tpot attack map" src="https://github.com/user-attachments/assets/6ff729a2-ec8a-409b-8ab3-9a3c0491a9f8" />

## 1. Report Summary

This report summarizes an initial offline analysis of logs collected from a T-Pot honeynet deployed on a public VPS. The honeynet captured broad Internet scanning, SSH brute-force activity, protocol fingerprinting, and service-specific probes against exposed honeypot services.

The strongest finding so far is a repeated SSH credential attack pattern targeting Solana/crypto-related infrastructure terms, backed by aggregate Cowrie credential counts and clear post-login command sequences. The successful-login export contained `1,137` fake successful Cowrie logins from `508` unique source IPs. Top successful fake-login pairs included `solana/solana`, `ubuntu/ubuntu`, `sol/sol`, `sol/123`, and `solv/solv`. One source IP, `2.57.122.177`, repeatedly attempted usernames and passwords such as `solana`, `sol`, `raydium`, `firedancer`, `helius`, and related variants. After fake successful Cowrie logins, some actors ran quick system fingerprinting commands such as:

```bash
/bin/./uname -s -v -n -r -m
```

Other sessions went further. The Cowrie command timeline shows repeated attempts to install SSH-key persistence, reset account passwords, inventory CPU/memory/disk details, check logged-in users, inspect cron jobs, and kill competing scripts. This suggests the honeynet captured not only scanning and brute forcing, but also automated post-compromise behavior.

The targeted-port evidence shows that the honeynet attracted activity across multiple service categories, not only SSH. The clearest observed targets were `22/tcp` for SSH, `445/tcp` for SMB, `2404/tcp` for IEC-104/SCADA, `161/udp` for SNMP-like industrial-device exposure, `9200/tcp` for Elasticsearch/OpenSearch, `5555/tcp` for Android Debug Bridge, `1883/tcp` for MQTT, and several unusual ports that received SSH-like probes.

## 2. Environment Overview

- Platform: T-Pot honeynet
- Hostname: `honeynet2`
- Historical public VPS IP: withheld (retired lab)
- Primary log archive: `tpot-logs-20260508-044029.tar.gz`
- Original uncompressed T-Pot data size: `4.2 GB`
- Extracted log tree: `400 directories, 2291 files`

The honeynet was later shut down for safe offline analysis. The `tpot.service` was stopped and disabled, and Docker containers were verified to be no longer running.

## 3. Data Sources

The following T-Pot log sources were identified in the extracted archive:

| Source | Purpose |
|---|---|
| `cowrie/` | SSH/Telnet honeypot sessions, login attempts, commands, downloads |
| Cowrie aggregate exports | Top usernames, passwords, credential pairs, successful fake logins, successful login IPs, command summaries |
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

## 4. Initial Cowrie Findings
<img width="1909" height="821" alt="Tpot Top IP" src="https://github.com/user-attachments/assets/1d84529f-6be0-41ea-bf99-3d454f697a24" />

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

### 4.2 Aggregate Cowrie Credential Results

The aggregate Cowrie exports confirm that the Solana/crypto pattern was not just a hand-picked example. The successful-login file contains `1,137` fake successful Cowrie logins from `508` unique source IPs and `448` unique username/password pairs. The successful login records span 03/15/26 - 04/01/26.

Top attempted usernames:

| Rank | Username | Count |
|---|---|---|
| 1 | `root` | `3903` |
| 2 | `sol` | `1776` |
| 3 | `solana` | `1292` |
| 4 | `ubuntu` | `905` |
| 5 | `solv` | `887` |
| 6 | `admin` | `539` |
| 7 | `345gs5662d34` | `514` |
| 8 | `user` | `288` |
| 9 | `wiki` | `162` |
| 10 | `test` | `160` |

Top attempted password strings:

| Rank | Password string | Count |
|---|---|---|
| 1 | `123456` | `928` |
| 2 | `123` | `651` |
| 3 | `12345678` | `620` |
| 4 | `1234` | `568` |
| 5 | `solana` | `530` |
| 6 | `3245gs5662d34` | `518` |
| 7 | `345gs5662d34` | `514` |
| 8 | `sol` | `472` |
| 9 | `ubuntu` | `323` |
| 10 | `solv` | `307` |

Top attempted username/password pairs:

| Rank | Username | Password | Count |
|---|---|---|---|
| 1 | `345gs5662d34` | `345gs5662d34` | `514` |
| 2 | `solana` | `solana` | `342` |
| 3 | `sol` | `sol` | `310` |
| 4 | `solv` | `solv` | `275` |
| 5 | `ubuntu` | `ubuntu` | `248` |
| 6 | `solv` | `123456` | `233` |
| 7 | `sol` | `123` | `218` |
| 8 | `root` | `3245gs5662d34` | `170` |
| 9 | `sol` | `solana` | `143` |
| 10 | `solana` | `sol` | `140` |

Top successful fake-login credential pairs:

| Rank | Username | Password | Successful fake logins |
|---|---|---|---|
| 1 | `solana` | `solana` | `78` |
| 2 | `ubuntu` | `ubuntu` | `70` |
| 3 | `sol` | `sol` | `48` |
| 4 | `sol` | `123` | `34` |
| 5 | `solv` | `solv` | `30` |
| 6 | `345gs5662d34` | `345gs5662d34` | `25` |
| 7 | `root` | `password` | `21` |
| 8 | `root` | `admin` | `20` |
| 9 | `sol` | `1234` | `19` |
| 10 | `root` | `[blank]` | `13` |

Top source IPs by successful fake logins:

| Rank | Source IP | Successful fake logins |
|---|---|---|
| 1 | `92.118.39.87` | `42` |
| 2 | `195.178.110.30` | `42` |
| 3 | `2.57.122.177` | `36` |
| 4 | `195.178.110.218` | `34` |
| 5 | `2.57.122.208` | `30` |
| 6 | `92.118.39.63` | `22` |
| 7 | `92.118.39.62` | `20` |
| 8 | `80.94.92.183` | `20` |
| 9 | `45.148.10.121` | `20` |
| 10 | `92.118.39.76` | `12` |

The aggregate counts support two findings at the same time. First, there was normal Internet-wide SSH brute forcing against common accounts such as `root`, `admin`, `user`, `test`, and default passwords. Second, there was a clearly visible crypto-themed cluster: `sol`, `solana`, `solv`, `node`, `validator`, `firedancer`, and `raydium` appeared in the top usernames, passwords, or credential pairs.

The repeated `345gs5662d34` / `3245gs5662d34` strings are also notable. They do not appear to be ordinary human-chosen passwords. They look more like bot-dictionary artifacts or campaign-specific credential markers and should be treated as part of the observed attack pattern rather than as normal user behavior.

### 4.3 Solana/Crypto-Themed SSH Credential Pattern

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

### 4.4 Post-Login Fingerprinting Command

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

### 4.5 Cowrie Interpretation

The Cowrie evidence suggests automated SSH reconnaissance. The attacker or bot connected, attempted Solana-themed credentials, entered the fake shell after allowed credentials, fingerprinted the system with `uname`, and disconnected quickly.

This pattern is consistent with bot-driven scanning for weakly secured cryptocurrency infrastructure, possibly including validators, RPC nodes, developer servers, or wallet-related Linux systems.

### 4.6 Repeated Campaign Pattern From `2.57.122.177`

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

### 4.7 Post-Login Persistence and Reconnaissance Sequences

The Cowrie command timeline adds a stronger finding than simple login attempts. Across the extracted command records, the honeypot captured repeated post-login sequences that look like automated compromise playbooks rather than one-off manual testing.

Summary of the Cowrie command timeline:

| Evidence item | Observed count |
|---|---:|
| Parsed Cowrie command records | `10,758` |
| Unique Cowrie command sessions | `1,025` |
| Unique source IPs with commands | `461` |
| Date range | `03/15/26 - 04/01/26` |
| Short `uname` fingerprint commands | `331` |
| Full system/GPU fingerprint scripts | `72` |
| `.ssh` attribute-reset commands | `539` |
| SSH-key persistence commands | `551` |
| Password-change related command records | `1,192` |
| Host resource reconnaissance command records | `6,662` |
| Cleanup / rival-process kill commands | `164` |

A common sequence looked like this, with sensitive key and password material redacted:

```text
1. Reset SSH directory attributes:
   cd ~; chattr -ia .ssh; lockr -ia .ssh

2. Replace or recreate the SSH directory and add an attacker public key:
   cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa [REDACTED ATTACKER PUBLIC KEY]" >> .ssh/authorized_keys && chmod -R go= ~/.ssh && cd ~

3. Inventory CPU resources:
   cat /proc/cpuinfo | grep name | wc -l
   cat /proc/cpuinfo | grep name | head -n 1 | awk '{print $4,$5,$6,$7,$8,$9;}'

4. Attempt to change the account password:
   echo -e "[old value]\n[REDACTED new password]\n[REDACTED new password]" | passwd | bash

5. Gather host information:
   free -m | grep Mem | awk '{print $2,$3,$4,$5,$6,$7}'
   crontab -l
   w
   uname -m
   uname -a
   whoami
   lscpu | grep Model
   df -h | head -n 2 | awk 'FNR == 2 {print $2;}'
```

Some sessions also included cleanup or anti-competitor behavior:

```text
rm -rf /tmp/secure.sh
rm -rf /tmp/auth.sh
pkill -9 secure.sh
pkill -9 auth.sh
echo > /etc/hosts.deny
pkill -9 sleep
```

This is significant because the behavior moves beyond credential guessing. The observed sequence follows a recognizable intrusion workflow:

1. **Prepare persistence** by manipulating `.ssh` permissions and replacing `authorized_keys`.
2. **Maintain account access** by attempting password changes.
3. **Profile the host** by collecting CPU, memory, disk, user, cron, architecture, and kernel details.
4. **Reduce competition or interference** by killing scripts and clearing selected temporary files.

The repeated use of the same attacker SSH public key across many sessions also suggests automation. In the parsed timeline, one SSH public key appeared in `539` persistence commands, and a second key appeared in `12` persistence commands. This supports the conclusion that many different source IPs may have been running the same or closely related bot logic.

Top source IPs for the short `uname` fingerprint pattern included:

| Source IP | Sessions/commands observed |
|---|---:|
| `195.178.110.30` | `42` |
| `92.118.39.87` | `42` |
| `2.57.122.177` | `36` |
| `195.178.110.218` | `34` |
| `2.57.122.208` | `30` |

Top source IPs for SSH-key persistence sequences included:

| Source IP | Commands observed |
|---|---:|
| `130.12.180.51` | `9` |
| `103.76.120.202` | `7` |
| `69.5.189.31` | `6` |
| `103.156.204.2` | `5` |
| `95.90.13.168` | `5` |
| `165.154.22.195` | `5` |

The post-login command evidence is therefore one of the strongest parts of the report. It shows that the honeypot did not merely receive noisy Internet scans. It captured full automated attacker workflows after fake successful logins.


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

The local SCADA alert list shows repeated IEC-104 responses involving the honeynet address (withheld) and external scanner/source systems. Observed external IPs included:

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

### 5.5 Suricata Interpretation

The Suricata data indicates broad automated scanning and protocol probing. The most useful findings are SSH activity, unusual-port SSH detection, SMBv1 probing, Zmap scanner activity, MQTT malformed traffic, and SCADA/ICS protocol probes.

The very high count of truncated packets should be treated carefully. These events may reflect malformed traffic, capture-layer artifacts, or noisy Internet scanning rather than distinct attacks.

## 6. Targeted Ports and Services
<img width="3350" height="709" alt="Dashboard" src="https://github.com/user-attachments/assets/fb12dcee-319e-4dc4-b848-888cbd08cabf" />


### 6.1 Highest-Confidence Targeted Ports
The honeynet exposed many simulated services, but an exposed port is not the same thing as a targeted port. For this report, a port is treated as **targeted** only when Cowrie records, Suricata alerts, T-Pot service logs, or external Hetzner/BSI notifications showed interaction with that service.

| Port | Protocol | Service / Honeypot | Evidence | Interpretation |
|---:|---|---|---|---|
| `22` | TCP | SSH / Cowrie | Cowrie login attempts, Cowrie fake successful logins, Cowrie post-login commands, and Suricata SSH-on-expected-port alerts | This was the strongest target category. Attackers repeatedly attempted SSH credentials and, after fake successful logins, ran reconnaissance and persistence commands. |
| `445` | TCP | SMB / Dionaea | Suricata SMBv1 alerting and external SMB/MS17-010-style notification | Indicates scanning for Windows file-sharing and legacy SMB-style exposure. |
| `2404` | TCP | IEC-104 / Conpot | Suricata IEC-104 SCADA alerts and Hetzner/BSI IEC-104 notifications | Indicates industrial-control/SCADA-style scanning. This was one of the strongest non-SSH findings. |
| `161` | UDP | SNMP / Conpot | Hetzner/BSI SNMP notification identifying Siemens/SIMATIC/S7-like exposure | Suggests scanners recognized the honeypot as an industrial or network-management device. |
| `9200` | TCP | Elasticsearch / Elasticpot | Hetzner/BSI Elasticsearch/OpenSearch notification and exposed Elasticpot service | Indicates probing for exposed search/database infrastructure. |
| `5555` | TCP | Android Debug Bridge / ADBHoney | Hetzner/BSI ADB notification and exposed ADB honeypot service | Suggests scanning for exposed Android Debug Bridge services. |
| `1883` | TCP | MQTT / Dionaea | Suricata malformed MQTT traffic and exposed MQTT-like service | Indicates IoT-style probing against MQTT. |

### 6.2 SSH-Like Probing on Unusual Ports

Suricata also observed SSH-like traffic on ports that are not normal SSH ports:

```text
143
3306
8001
8282
9092
30000
```

These ports are interesting because they suggest broad fingerprinting rather than simple port-22 SSH scanning. Attackers and scanners may probe nonstandard ports to find hidden SSH services, misconfigured systems, or reused service banners.

| Port | Usual association | Observed behavior | Interpretation |
|---:|---|---|---|
| `143` | IMAP | SSH-like Suricata alert | Possible hidden-service probing or malformed banner testing. |
| `3306` | MySQL | SSH-like Suricata alert | Possible probing for SSH on a database port or broad scanner misclassification. |
| `8001` | Common alternate web/API port | SSH-like Suricata alert | Possible nonstandard service fingerprinting. |
| `8282` | Common alternate web/API port | SSH-like Suricata alert | Possible nonstandard service fingerprinting. |
| `9092` | Kafka | SSH-like Suricata alert | Possible probing of high-value infrastructure ports. |
| `30000` | High/custom service port | SSH-like Suricata alert | Possible high-port sweep or hidden-service discovery attempt. |

### 6.4 Port-Based Interpretation

The port evidence makes the report stronger because it connects raw alerts to recognizable service categories:

- `22/tcp` shows credential attack and post-login automation.
- `445/tcp` shows Windows/SMB-style probing.
- `2404/tcp` and `161/udp` show industrial-control and network-management style probing.
- `9200/tcp` shows exposed search/database probing.
- `5555/tcp` shows Android Debug Bridge probing.
- `1883/tcp` shows IoT/MQTT probing.
- Unusual SSH-like ports show broader service fingerprinting beyond default service locations.

Together, these findings show that the honeynet was not only receiving generic background traffic. It was being classified and touched as several different types of exposed systems: Linux SSH server, Windows file-sharing host, industrial-control device, Elasticsearch node, Android device, IoT/MQTT endpoint, and miscellaneous high-port services.

## 7. Timeline Notes

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

## 8. External Abuse/Exposure Notifications


The Hetzner/BSI abuse notifications add strong external validation to the honeynet report. These notifications show that independent Internet-wide scanning systems detected the honeypot as exposing services that resembled real vulnerable systems.

<img width="1086" height="958" alt="abuse hetz" src="https://github.com/user-attachments/assets/20919725-97b2-491d-a2c2-7867fd2a595e" />


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
<img width="709" height="1178" alt="snmp warning" src="https://github.com/user-attachments/assets/28dc473e-8fa9-40f5-8a67-43bc5b391c06" />
These messages should be interpreted carefully. Hetzner stated that the notifications do not necessarily mean the server was involved in abuse; they indicate that the server appeared to expose potentially exploitable services. In this case, that matches the purpose of the T-Pot deployment: honeypot containers intentionally impersonated vulnerable or exposed services to attract scanning and interaction.

The notifications are useful because they show that the honeynet was not only receiving random attacker traffic, but was also visible to large-scale Internet measurement and reporting systems. The server was identified as resembling multiple exposed service categories, including Android ADB, Elasticsearch, SNMP/Siemens S7, IEC-104 industrial control, and SMB backdoor exposure.

This provides an important operational lesson: even educational honeypots can trigger provider abuse notifications when they intentionally expose high-risk-looking services. At the same time, these notices also show the defensive side of Internet scanning. Not every automated scanner is hostile. Some bots and measurement systems exist to identify exposed services, warn providers, and reduce harm before attackers abuse them. In this case, the BSI/Hetzner notifications functioned as a form of defensive Internet hygiene: they detected risky-looking exposed services and notified the server owner through the hosting provider.

## 9. Preliminary Conclusions

The honeynet successfully captured real Internet background attack activity. The most important finding is a Solana/crypto-themed SSH credential attack pattern combined with repeated post-login command sequences. The aggregate Cowrie exports show that crypto-related strings were present among the top attempted usernames, top passwords, top credential pairs, and top successful fake-login pairs. This supports the conclusion that some automated bot activity is actively searching for weakly secured cryptocurrency-related infrastructure, while the command timeline shows what attackers attempted after obtaining shell access in the fake Cowrie environment.

Suricata confirmed broader scanning patterns, including SSH activity on expected and unusual ports, SMBv1 probing, Zmap scanner traffic, MQTT malformed traffic, and SCADA/ICS probes. The targeted-port review adds important context: the most meaningful service categories were SSH on `22/tcp`, SMB on `445/tcp`, IEC-104/SCADA on `2404/tcp`, SNMP-like industrial-device exposure on `161/udp`, Elasticsearch/OpenSearch on `9200/tcp`, Android Debug Bridge on `5555/tcp`, MQTT on `1883/tcp`, and SSH-like probing on unusual ports.

Overall, the data shows that a public VPS with exposed honeypot services quickly attracts automated scanning, credential attacks, protocol-specific probes, port-based fingerprinting, and post-compromise automation. The Cowrie logs provide the clearest attacker behavior because they show credential attempts, fake successful logins, SSH-key persistence attempts, password-change attempts, host reconnaissance, and cleanup commands. Suricata and the external exposure notifications provide broader network-level context by showing which ports and service categories were visible to scanners.


