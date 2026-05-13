# ez-ad-env

One-command Attack/Defense CTF environment using [ForcAD](https://github.com/pomo-mondreganto/ForcAD) + WireGuard VPN.

## Prerequisites

- Docker & Docker Compose
- Python 3.10+
- `pip install cryptography` (for WireGuard key generation)
- [ForcAD](https://github.com/pomo-mondreganto/ForcAD) cloned as a sibling directory (`../ForcAD/`)

## Quick Start

```bash
# Clone ForcAD next to this repo
git clone https://github.com/pomo-mondreganto/ForcAD.git ../ForcAD

# Generate a game: 3 teams, 200 rounds, 60 seconds per round
python3 generate_game.py 3 200 60

# Tear down everything
python3 generate_game.py --destroy

 # reset game（remain SSH key、VPN、vulnbox）
 python3 generate_game.py --reset 3 200 60
 
 # only reset default para
 python3 generate_game.py --reset

```

## What It Does

1. **Generates SSH keypairs** — one per team for vulnbox access
2. **Generates WireGuard VPN** — server config + per-team client configs
3. **Builds vulnbox containers** — each team gets isolated services + SSH
4. **Configures ForcAD** — teams, checkers, timing
5. **Starts everything** — Docker network, vulnboxes, VPN, ForcAD platform
6. **Outputs credentials** — team tokens, SSH keys, VPN configs, saved to `generated/game_info.json`

## Architecture

```
Player → WireGuard VPN → 10.80.0.0/16 game network
                            ├── SSH → own vulnbox (10.80.{team}.2)
                            ├── Attack → other vulnboxes :8080 :8081
                            └── ForcAD API (10.80.0.1)
```

## Network Layout

| Resource | IP |
|---|---|
| Docker gateway / ForcAD | 10.80.0.1 |
| Team-A vulnbox | 10.80.0.2 |
| Team-B vulnbox | 10.80.1.2 |
| Team-C vulnbox | 10.80.2.2 |
| WireGuard server | 10.80.200.1 |
| VPN peer Team-A | 10.80.200.10 |
| VPN peer Team-B | 10.80.200.11 |

## Included Challenges

| Challenge | Type | Port | Vulnerability |
|---|---|---|---|
| notekeeper | Web | 8080 | SQL Injection in search |
| calcpwn | Pwn | 8081 | eval() RCE in calc |

## Directory Structure

```
ez-ad-env/
├── generate_game.py          # Main generator script
├── services/
│   ├── notekeeper/           # Web challenge (Flask + SQLite)
│   └── calcpwn/              # Pwn challenge (Flask + eval)
├── checkers/                 # ForcAD checker scripts
│   ├── notekeeper/checker.py
│   └── calcpwn/checker.py
├── exploits/                 # Example exploit scripts
│   ├── notekeeper_exploit.py
│   ├── calcpwn_exploit.py
│   ├── script-template-web.py
│   └── script-template-pwn.py
└── generated/                # (gitignored) runtime output
    ├── keys/                 # SSH keypairs per team
    ├── wireguard/            # VPN configs
    └── game_info.json        # All credentials
```

## ForcAD API
<img width="1007" height="460" alt="image" src="https://github.com/user-attachments/assets/931b04a9-e7ce-4960-8825-c4a0fbcacb08" />

### Scoreboard

```bash
# Web UI
http://<host>:8080/

# Teams & scores
curl http://10.80.0.1:8080/api/client/teams/

# Scoreboard (SSE stream)
curl http://10.80.0.1:8080/api/client/scoreboard/

# Game config (tick info, round length)
curl http://10.80.0.1:8080/api/client/config/

# Attack data (flag IDs to steal)
curl http://10.80.0.1:8080/api/client/attack_data/
```

### Flag Submission

```bash
# Submit stolen flags
curl -X PUT http://10.80.0.1:8080/flags/ \
  -H "X-Team-Token: YOUR_TEAM_TOKEN" \
  -H "Content-Type: application/json" \
  -d '["FLAG_HERE"]'

# Response: [{"flag": "FLAG_HERE", "status": true, "msg": "Accepted"}]
```

| Status | Meaning |
|---|---|
| `true` | Flag accepted |
| `false` + "Flag is too old" | Expired (past round window) |
| `false` + "Flag already submitted" | Duplicate |
| `false` + "Flag is your own" | Can't submit your own flag |
| `false` + "Invalid flag" | Wrong format |

## Adding Custom Challenges

1. Create service under `services/your_challenge/` with `Dockerfile` and `app.py`
2. Create checker under `checkers/your_challenge/checker.py`
3. Update `generate_game.py` to include your challenge in the compose and ForcAD config

## Player Setup (WireGuard)

```bash
# macOS
brew install wireguard-tools
sudo wg-quick up /path/to/team-X.conf

# Linux
sudo apt install wireguard
sudo wg-quick up /path/to/team-X.conf

# Then SSH into your vulnbox
ssh -i team-X root@10.80.{team}.2
```


<img width="520" height="515" alt="image" src="https://github.com/user-attachments/assets/d304cd21-3634-4826-9db7-bacb9c23d4de" />
