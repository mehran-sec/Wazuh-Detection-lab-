# SSH Brute-Force Attack Simulation & Detection with Wazuh

Custom Wazuh correlation rule built and validated to detect SSH brute-force attempts, including a full attack simulation using `sshpass` against a live Ubuntu target.

## Objective

Simulate a realistic SSH brute-force attack against a lab target, then build, tune, and validate a custom Wazuh detection rule that fires on repeated authentication failures and correlates them against a successful login — closing the full attack-to-detection loop.

## Lab Architecture

| Component | Details |
|---|---|
| Wazuh Manager/Indexer/Dashboard | Docker single-node deployment,  |
| Host |  Ubuntu, 16GB RAM |
| Attack Source | Bash script using sshpass |
| Target | Ubuntu VM (SSH server) |
| Base Detection Rule | 5760 (SSH authentication failure ) |
| Custom Rule ID | 100010 |

```
[Attacker Script] --sshpass/SSH--> [Ubuntu Target] --auth logs--> [Wazuh Agent]
                                                                        |
                                                                        v
                                                              [Wazuh Manager: rule 5760]
                                                                        |
                                                                        v
                                                        [Custom Rule 100010: frequency correlation]
                                                                        |
                                                                        v
                                                              [Wazuh Dashboard Alert]
```

##  Attack Simulation

A bash script using `sshpass` performs repeated failed SSH login attempts against the target, followed by one successful login using the correct credentials .

```bash
#!/bin/bash
# ssh_bruteforce_sim.sh
# Simulates SSH brute-force attempts followed by a successful login.
# For use only against systems you own/control in an isolated lab.

TARGET="192.168.x.x"
USER="Ayan"
WRONG_PASSWORDS=("password123" "admin123" "letmein" "qwerty123" "test1234")
CORRECT_PASSWORD="<Khan>"

for pass in "${WRONG_PASSWORDS[@]}"; do
    echo "[*] Trying password: $pass"
    sshpass -p "$pass" ssh -o StrictHostKeyChecking=no "$USER@$TARGET" exit
    sleep 1
done

echo "[*] Attempting correct login..."
sshpass -p "$CORRECT_PASSWORD" ssh -o StrictHostKeyChecking=no "$USER@$TARGET" exit
```


## Custom Detection Rule

`local_rules.xml` 

```xml
<group name="local,ssh_bruteforce,">
  <rule id="100010" level="10" frequency="5" timeframe="120">
    <if_matched_sid>5760</if_matched_sid>
    <description>SSH brute-force attempt detected: 5+ authentication failures from same source in 120 seconds</description>
    <mitre>
      <id>T1110.001</id>
    </mitre>
    <group>authentication_failures,pci_dss_10.2.4,pci_dss_10.2.5,</group>
  </rule>
</group>
```

**Logic:** the rule fires when 5 or more events matching base rule `5760` occur from the same source within a 120-second window — a frequency-based correlation rather than a single-event match, reducing false positives from occasional typos.


## Validation

1. Ran `sshpass`-driven failed login attempts against the target.
2. Confirmed each failure logged and matched against rule `5760` via `wazuh-logtest`.
3. Confirmed rule `100010` triggered after the 5th failure within the timeframe.
4. Followed with a successful login and confirmed the Wazuh Dashboard showed the full sequence: multiple `5760` alerts → `100010` correlation alert → successful auth event.


<img src="Screanshot/SSH_Brute_F.png"  alt="SSH Detection" width="600">
*(Insert dashboard screenshots here: `screenshots/alert-100010.png`, `screenshots/attack-sequence.png`)*

##  MITRE ATT&CK Mapping

| Technique | ID | Notes |
|---|---|---|
| Brute Force: Password Guessing | T1110.001 | Core technique simulated and detected |
| Valid Accounts | T1078 | Represented by the final successful login |

##  Next Steps

- **Success-after-failures rule**: a compound rule that specifically flags a successful login (base rule for successful SSH auth) occurring shortly after a `100010` alert from the same source — a stronger compromise indicator than failures alone.
- Add source IP threat-intel enrichment (e.g., via Wazuh's active response or an external feed).
- Extend to active response: auto-block source IP after `100010` fires.

## Repo Structure

```
.
├── README.md
├── scripts/
│   └── ssh_bruteforce_sim.sh
├── rules/
│   └── local_rules.xml
└── screenshots/
    ├── alert-100010.png
    └── attack-sequence.png
```

##  Environment

- Wazuh 4.14.5 (Docker single-node)
- Ubuntu (host + target)
- `sshpass`

---
*Part of a home SOC lab built for hands-on detection engineering practice.*
