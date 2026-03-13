# SSH Honeypot Lab with Cowrie

## Overview

This project documents the deployment of an **internet‑facing SSH
honeypot** using [Cowrie](https://github.com/cowrie/cowrie). The goal is
to capture attacker behavior, log commands, collect malware samples, and
store attack telemetry in a structured database for analysis.

The honeypot is deployed on a VPS and designed to mimic a vulnerable
Linux server to attract automated bots and opportunistic attackers.

------------------------------------------------------------------------

## Architecture

    Internet
       │
       │ TCP 22
       ▼
    iptables redirect
       │
       ▼
    Cowrie Honeypot (port 2222)
       │
       ├── Command capture
       ├── Session replay logs
       ├── Malware download capture
       └── SQLite / JSON logging
       
    Real SSH (port 4222)
       │
       ▼
    Admin access

### Port Configuration

  Port   Service    Purpose
  ------ ---------- -----------------------
  22     Redirect   Redirected to Cowrie
  2222   Cowrie     Honeypot SSH service
  4222   OpenSSH    Real admin SSH access

iptables redirect rule:

``` bash
iptables -t nat -A PREROUTING -p tcp --dport 22 -j REDIRECT --to-port 2222
```

------------------------------------------------------------------------

## Features

### Attack Telemetry Collection

The honeypot captures:

-   login attempts
-   attacker IP addresses
-   usernames and passwords
-   commands executed
-   malware download attempts
-   full terminal session recordings

### Command Logging

Commands executed by attackers are stored in a SQLite database.

Example:

    ls
    touch cc.txt
    exit

### Session Replay

Full terminal sessions can be replayed to observe attacker behavior.

    cowrie playlog <session_file>

### Malware Capture

Files downloaded by attackers using tools such as:

    wget
    curl
    tftp

are stored locally for analysis.

------------------------------------------------------------------------

## Logging Architecture

Cowrie produces three primary types of logs:

    cowrie/
     ├── cowrie.db        # SQLite structured logs
     ├── cowrie.json      # full JSON event stream
     ├── var/lib/cowrie/
     │      ├── downloads # captured malware
     │      └── tty       # session replay logs

### SQLite Database

SQLite allows easy querying of attacker activity.

Example queries:

#### Commands executed

``` sql
SELECT session, timestamp, input
FROM input
ORDER BY timestamp;
```

#### Most common commands

``` sql
SELECT input, COUNT(*) as hits
FROM input
GROUP BY input
ORDER BY hits DESC;
```

#### Session commands

``` sql
SELECT timestamp, input
FROM input
WHERE session = '<session_id>';
```

------------------------------------------------------------------------

## Example Captured Session

    ls
    touch poocat.txt
    exit

Session ID:

    254927014eb9

Stored in SQLite:

    id | session        | timestamp | command
    ------------------------------------------
    1  | 254927014eb9   | ...       | ls
    2  | 254927014eb9   | ...       | touch cc.txt
    3  | 254927014eb9   | ...       | exit

------------------------------------------------------------------------

## Security Considerations

The honeypot is isolated to prevent compromise of the host system.

Key measures:

-   Real SSH moved to **port 4222**
-   Honeypot running as **non‑root user**
-   Firewall rules restrict external access
-   Captured malware stored but not executed

------------------------------------------------------------------------

## Research Goals

This project enables analysis of:

-   brute‑force SSH attack patterns
-   common credential lists
-   botnet command behavior
-   malware delivery infrastructure
-   automated exploitation workflows

------------------------------------------------------------------------

## Future Improvements

Potential extensions include:

-   attacker geolocation
-   automated malware hashing
-   threat intelligence enrichment
-   dashboard visualization
-   command frequency analysis
-   bot family classification

------------------------------------------------------------------------

## Tools Used

-   Cowrie
-   SQLite
-   iptables
-   UFW
-   Linux VPS

------------------------------------------------------------------------

## Example Use Cases

-   cybersecurity research
-   attacker behavior analysis
-   malware collection
-   blue team training
-   honeypot experimentation

------------------------------------------------------------------------

## Disclaimer

This honeypot is deployed **for research and defensive purposes only**.
Captured malware and attack data should be handled responsibly and never
executed on production systems.
