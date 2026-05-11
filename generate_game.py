#!/usr/bin/env python3
"""
A/D CTF Game Generator — one command to set up a full local A/D CTF environment.

Usage:
  python3 generate_game.py <num_teams> [ticks_per_game] [tick_seconds]
  python3 generate_game.py 3              # 3 teams, 200 ticks, 60s each
  python3 generate_game.py 5 100 30       # 5 teams, 100 ticks, 30s each
  python3 generate_game.py --destroy      # Tear down everything

What it does:
  1. Creates Docker network 10.80.0.0/16
  2. Generates docker-compose.yml for N team vulnboxes (notekeeper web + calcpwn pwn)
     Each vulnbox gets SSH (port 22) with unique team keypair
     No port mapping — services only reachable from game network
  3. Generates WireGuard VPN configs per team (10.80.200.x peers)
  4. Generates ForcAD config.yml with N teams + game timing
  5. Starts everything: vulnboxes → ForcAD → WireGuard
  6. Prints team credentials (VPN config, SSH key, team token)

Architecture:
  Team player --WireGuard VPN--> 10.80.200.x (peer)
                                   |
                 game network: 10.80.0.0/16
                   |         |         |
             10.80.0.2   10.80.1.2   10.80.2.2  (vulnboxes)
               Team-A     Team-B     Team-C
             :8080 web   :8080 web   :8080 web
             :8081 pwn   :8081 pwn   :8081 pwn
             :22   ssh   :22   ssh   :22   ssh
                                   |
                             10.80.255.1 (ForcAD celery/checker)
"""

import argparse
import datetime
import json
import os
import shutil
import subprocess
import sys
import textwrap
import time

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
FORCAD_DIR = os.path.join(os.path.dirname(SCRIPT_DIR), "ForcAD")
SERVICES_DIR = os.path.join(SCRIPT_DIR, "services")
GENERATED_DIR = os.path.join(SCRIPT_DIR, "generated")
KEYS_DIR = os.path.join(GENERATED_DIR, "keys")
WG_DIR = os.path.join(GENERATED_DIR, "wireguard")
NETWORK_NAME = "ad-ctf-net"
NETWORK_SUBNET = "10.80.0.0/16"
NETWORK_GATEWAY = "10.80.0.1"


def run(cmd, check=True, capture=False, **kwargs):
    """Run a shell command."""
    print(f"  $ {cmd if isinstance(cmd, str) else ' '.join(cmd)}")
    return subprocess.run(
        cmd, shell=isinstance(cmd, str), check=check,
        capture_output=capture, text=True, **kwargs
    )


def ensure_dirs():
    os.makedirs(GENERATED_DIR, exist_ok=True)
    os.makedirs(KEYS_DIR, exist_ok=True)
    os.makedirs(WG_DIR, exist_ok=True)


def generate_ssh_keys(num_teams):
    """Generate SSH keypair per team."""
    print("\n🔑 Generating SSH keys...")
    keys = {}
    for i in range(num_teams):
        team = chr(ord('A') + i) if i < 26 else f"T{i}"
        key_path = os.path.join(KEYS_DIR, f"team-{team.lower()}")
        if not os.path.exists(key_path):
            run(f'ssh-keygen -t ed25519 -f {key_path} -N "" -C "team-{team}@ad-ctf" -q')
        with open(f"{key_path}.pub") as f:
            pub_key = f.read().strip()
        keys[i] = {"name": f"Team-{team}", "key_path": key_path, "pub_key": pub_key}
        print(f"  Team-{team}: {key_path}")
    return keys


def _wg_keypair():
    """Generate a WireGuard (X25519) keypair using pure Python. Returns (priv_b64, pub_b64)."""
    from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat, PrivateFormat, NoEncryption
    import base64
    priv_key = X25519PrivateKey.generate()
    priv_bytes = priv_key.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())
    pub_bytes = priv_key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    return base64.b64encode(priv_bytes).decode(), base64.b64encode(pub_bytes).decode()


def generate_wg_keys(num_teams):
    """Generate WireGuard keypairs using pure Python X25519 — no external tools needed."""
    print("\n🔐 Generating WireGuard keys...")
    wg_keys = {}

    try:
        srv_priv, srv_pub = _wg_keypair()
    except ImportError:
        print("  ⚠️  'cryptography' package not installed — skipping VPN config.")
        print("     Install: pip install cryptography")
        return None

    wg_keys["server"] = {"private": srv_priv, "public": srv_pub}

    for i in range(num_teams):
        team = chr(ord('A') + i) if i < 26 else f"T{i}"
        priv, pub = _wg_keypair()
        wg_keys[i] = {"name": f"Team-{team}", "private": priv, "public": pub}

    return wg_keys


def generate_vulnbox_compose(num_teams, ssh_keys):
    """Generate docker-compose.yml for vulnboxes."""
    print("\n📦 Generating vulnbox docker-compose.yml...")

    services = {}
    volumes = {}

    for i in range(num_teams):
        team = chr(ord('a') + i) if i < 26 else f"t{i}"
        team_upper = team.upper()
        ip = f"10.80.{i}.2"
        pub_key = ssh_keys[i]["pub_key"]

        # Notekeeper (web, port 8080) — main container with network + SSH
        svc_name = f"vuln-team-{team}"
        services[svc_name] = {
            "build": {
                "context": ".",
                "dockerfile": "Dockerfile.vulnbox",
                "args": {"SSH_PUB_KEY": pub_key}
            },
            "container_name": svc_name,
            "restart": "unless-stopped",
            "hostname": f"team-{team}",
            "volumes": [f"team-{team}-data:/data", f"team-{team}-secrets:/app/secrets"],
            "networks": {NETWORK_NAME: {"ipv4_address": ip}},
        }

        # CalcPwn (pwn, port 8081) shares network namespace
        calc_name = f"calcpwn-team-{team}"
        services[calc_name] = {
            "build": "./services/calcpwn",
            "container_name": calc_name,
            "restart": "unless-stopped",
            "network_mode": f"service:{svc_name}",
            "volumes": [f"team-{team}-secrets:/app/secrets"],
        }

        volumes[f"team-{team}-data"] = None
        volumes[f"team-{team}-secrets"] = None

    # Tcpdump on team-a for Tulip
    if num_teams > 0:
        services["tcpdump-team-a"] = {
            "image": "alpine:latest",
            "container_name": "tcpdump-team-a",
            "depends_on": ["vuln-team-a"],
            "network_mode": "service:vuln-team-a",
            "volumes": ["./traffic:/traffic"],
            "command": (
                "sh -c \"apk add --no-cache tcpdump && "
                "mkdir -p /traffic && "
                "tcpdump -i eth0 -U -G 30 -w '/traffic/capture_%Y%m%d_%H%M%S.pcap' "
                "'port 8080 or port 8081 or port 22'\""
            ),
            "restart": "unless-stopped",
        }

    # WireGuard VPN server container
    wg_server_dir = os.path.abspath(os.path.join(WG_DIR, "server"))
    services["wireguard"] = {
        "image": "linuxserver/wireguard:latest",
        "container_name": "wg-vpn",
        "cap_add": ["NET_ADMIN", "SYS_MODULE"],
        "environment": ["PUID=1000", "PGID=1000"],
        "volumes": [
            f"{wg_server_dir}:/config/wg_confs",
            "/lib/modules:/lib/modules:ro",
        ],
        "sysctls": {
            "net.ipv4.ip_forward": 1,
            "net.ipv4.conf.all.src_valid_mark": 1,
        },
        "ports": ["51820:51820/udp"],
        "restart": "unless-stopped",
        "networks": {
            NETWORK_NAME: {"ipv4_address": "10.80.200.1"},
        },
    }

    compose = {
        "services": services,
        "volumes": {k: {} if v is None else v for k, v in volumes.items()},
        "networks": {NETWORK_NAME: {"external": True}},
    }

    compose_path = os.path.join(SCRIPT_DIR, "docker-compose.yml")
    import yaml
    with open(compose_path, "w") as f:
        yaml.dump(compose, f, default_flow_style=False, sort_keys=False)
    print(f"  Written to {compose_path}")
    return compose_path


def generate_vulnbox_dockerfile(ssh_keys):
    """Create a Dockerfile that runs notekeeper + sshd."""
    print("\n🐳 Generating Dockerfile.vulnbox...")
    dockerfile = textwrap.dedent("""\
        FROM python:3.11-slim

        # Install SSH server
        RUN apt-get update && apt-get install -y --no-install-recommends openssh-server && \\
            rm -rf /var/lib/apt/lists/* && \\
            mkdir -p /run/sshd

        # SSH config: key-only auth
        RUN sed -i 's/#PermitRootLogin.*/PermitRootLogin prohibit-password/' /etc/ssh/sshd_config && \\
            sed -i 's/#PasswordAuthentication.*/PasswordAuthentication no/' /etc/ssh/sshd_config && \\
            sed -i 's/#PubkeyAuthentication.*/PubkeyAuthentication yes/' /etc/ssh/sshd_config

        # Add team SSH public key
        ARG SSH_PUB_KEY=""
        RUN mkdir -p /root/.ssh && chmod 700 /root/.ssh && \\
            echo "${SSH_PUB_KEY}" > /root/.ssh/authorized_keys && \\
            chmod 600 /root/.ssh/authorized_keys

        # Install notekeeper
        WORKDIR /app
        COPY services/notekeeper/requirements.txt /app/requirements.txt
        RUN pip install --no-cache-dir -r requirements.txt
        COPY services/notekeeper/app.py /app/app.py
        RUN mkdir -p /data

        EXPOSE 22 8080

        # Start both sshd and gunicorn
        CMD /usr/sbin/sshd && gunicorn -b 0.0.0.0:8080 -w 2 --timeout 30 app:app
    """)
    path = os.path.join(SCRIPT_DIR, "Dockerfile.vulnbox")
    with open(path, "w") as f:
        f.write(dockerfile)
    print(f"  Written to {path}")


def generate_wg_configs(num_teams, wg_keys, host_ip):
    """Generate WireGuard server + client configs."""
    if wg_keys is None:
        return

    print("\n🌐 Generating WireGuard configs...")
    server_dir = os.path.join(WG_DIR, "server")
    os.makedirs(server_dir, exist_ok=True)

    # Server config
    server_conf = textwrap.dedent(f"""\
        [Interface]
        Address = 10.80.200.1/24
        ListenPort = 51820
        PrivateKey = {wg_keys['server']['private']}
        PostUp = iptables -A FORWARD -i wg0 -j ACCEPT; iptables -A FORWARD -o wg0 -j ACCEPT; iptables -t nat -A POSTROUTING -s 10.80.200.0/24 -o eth0 -j MASQUERADE
        PostDown = iptables -D FORWARD -i wg0 -j ACCEPT; iptables -D FORWARD -o wg0 -j ACCEPT; iptables -t nat -D POSTROUTING -s 10.80.200.0/24 -o eth0 -j MASQUERADE
    """)

    for i in range(num_teams):
        team = chr(ord('A') + i) if i < 26 else f"T{i}"
        peer_ip = f"10.80.200.{10 + i}"
        server_conf += textwrap.dedent(f"""
            # Team-{team}
            [Peer]
            PublicKey = {wg_keys[i]['public']}
            AllowedIPs = {peer_ip}/32
        """)

    with open(os.path.join(server_dir, "wg0.conf"), "w") as f:
        f.write(server_conf)

    # Client configs per team
    clients_dir = os.path.join(WG_DIR, "clients")
    os.makedirs(clients_dir, exist_ok=True)

    for i in range(num_teams):
        team = chr(ord('A') + i) if i < 26 else f"T{i}"
        peer_ip = f"10.80.200.{10 + i}"
        client_conf = textwrap.dedent(f"""\
            # Team-{team} WireGuard VPN Config
            [Interface]
            PrivateKey = {wg_keys[i]['private']}
            Address = {peer_ip}/32
            DNS = 8.8.8.8

            [Peer]
            PublicKey = {wg_keys['server']['public']}
            Endpoint = {host_ip}:51820
            AllowedIPs = 10.80.0.0/16
            PersistentKeepalive = 25
        """)
        path = os.path.join(clients_dir, f"team-{team.lower()}.conf")
        with open(path, "w") as f:
            f.write(client_conf)
        print(f"  Team-{team}: {path}")


def generate_forcad_config(num_teams, total_ticks, tick_seconds):
    """Generate ForcAD config.yml."""
    print("\n⚙️  Generating ForcAD config.yml...")
    start_time = datetime.datetime.now() + datetime.timedelta(seconds=90)

    teams = []
    for i in range(num_teams):
        team = chr(ord('A') + i) if i < 26 else f"T{i}"
        teams.append({
            "name": f"Team-{team}",
            "ip": f"10.80.{i}.2",
            "highlighted": i == 0,
        })

    config = {
        "admin": {"username": "admin", "password": "admin123"},
        "game": {
            "checkers_path": "/checkers/",
            "default_score": 2500.0,
            "env_path": "",
            "flag_lifetime": 5,
            "game_hardness": 10.0,
            "inflation": True,
            "mode": "classic",
            "round_time": tick_seconds,
            "start_time": start_time.replace(microsecond=0),
            "timezone": "Asia/Shanghai",
            "volga_attacks_mode": False,
        },
        "storages": {
            "db": {"dbname": "forcad", "host": "postgres", "password": "admin123", "port": 5432, "user": "admin"},
            "rabbitmq": {"host": "rabbitmq", "password": "admin123", "port": 5672, "user": "admin", "vhost": "forcad"},
            "redis": {"db": 0, "host": "redis", "password": "admin123", "port": 6379},
        },
        "tasks": [
            {
                "checker": "notekeeper/checker.py",
                "checker_timeout": 15,
                "checker_type": "pfr",
                "gets": 1,
                "name": "notekeeper",
                "places": 1,
                "puts": 1,
            },
            {
                "checker": "calcpwn/checker.py",
                "checker_timeout": 15,
                "checker_type": "pfr",
                "gets": 1,
                "name": "calcpwn",
                "places": 1,
                "puts": 1,
            },
        ],
        "teams": teams,
    }

    import yaml
    config_path = os.path.join(FORCAD_DIR, "config.yml")
    with open(config_path, "w") as f:
        yaml.dump(config, f, default_flow_style=False, sort_keys=False)

    print(f"  Written to {config_path}")
    print(f"  Game starts at: {start_time.strftime('%H:%M:%S')} ({tick_seconds}s ticks, {total_ticks} rounds)")
    return start_time


def create_network():
    """Create Docker network if not exists."""
    print("\n🌐 Creating Docker network...")
    result = run(f"docker network inspect {NETWORK_NAME}", check=False, capture=True)
    if result.returncode != 0:
        run(f"docker network create --subnet={NETWORK_SUBNET} --gateway={NETWORK_GATEWAY} {NETWORK_NAME}")
        print(f"  Created {NETWORK_NAME} ({NETWORK_SUBNET})")
    else:
        print(f"  {NETWORK_NAME} already exists")


def start_vulnboxes():
    """Build and start vulnbox containers."""
    print("\n🚀 Starting vulnboxes...")
    run(f"docker compose -f {SCRIPT_DIR}/docker-compose.yml up -d --build", check=True)


def start_forcad():
    """Setup and start ForcAD."""
    print("\n🚀 Starting ForcAD...")
    # Clear old DB data
    pg_data = os.path.join(FORCAD_DIR, "docker_volumes", "postgres", "data")
    if os.path.exists(pg_data):
        shutil.rmtree(pg_data)

    run(f"cd {FORCAD_DIR} && python3 control.py setup", check=True)
    run(f"cd {FORCAD_DIR} && docker compose up -d --build", check=True)


def wait_for_services(num_teams):
    """Wait until all vulnbox services respond."""
    print("\n⏳ Waiting for services to be ready...")
    import urllib.request

    for attempt in range(30):
        all_ok = True
        for i in range(num_teams):
            ip = f"10.80.{i}.2"
            team_char = chr(ord('a') + i) if i < 26 else f"t{i}"
            result = run(
                f'docker exec vuln-team-{team_char} python3 -c '
                f'"import urllib.request; print(urllib.request.urlopen(\'http://localhost:8080/health\').read())"',
                check=False, capture=True
            )
            if b"ok" not in (result.stdout or "").encode() and "ok" not in (result.stdout or ""):
                all_ok = False
                break
        if all_ok:
            print(f"  ✅ All {num_teams} vulnboxes healthy!")
            return True
        time.sleep(2)

    print("  ⚠️  Some services may not be ready yet")
    return False


def get_team_tokens():
    """Get team tokens from ForcAD database."""
    result = run(
        'docker exec forcad-postgres-1 psql -U admin -d forcad -t -A -c '
        '"SELECT name, ip, token FROM teams ORDER BY id;"',
        capture=True, check=False
    )
    tokens = {}
    for line in (result.stdout or "").strip().split("\n"):
        parts = line.split("|")
        if len(parts) == 3:
            tokens[parts[0]] = {"ip": parts[1], "token": parts[2]}
    return tokens


def print_summary(num_teams, ssh_keys, wg_keys, tokens, start_time, tick_seconds, total_ticks, host_ip):
    """Print the final game summary with all credentials."""
    print("\n" + "=" * 70)
    print("🏁 A/D CTF GAME READY!")
    print("=" * 70)
    print(f"\n📊 Scoreboard:    http://{host_ip}:8080")
    print(f"🔧 Admin Panel:   http://{host_ip}:8080/admin/  (admin / admin123)")
    print(f"⏱️  Game starts:   {start_time.strftime('%H:%M:%S')}")
    print(f"📏 Rounds:        {total_ticks} × {tick_seconds}s = {total_ticks * tick_seconds // 60}min")
    print(f"🌐 VPN port:      {host_ip}:51820/udp")

    print(f"\n{'─' * 70}")
    print(f"{'Team':<10} {'IP':<15} {'Token':<20} {'SSH Key'}")
    print(f"{'─' * 70}")

    for i in range(num_teams):
        team = chr(ord('A') + i) if i < 26 else f"T{i}"
        name = f"Team-{team}"
        ip = f"10.80.{i}.2"
        token = tokens.get(name, {}).get("token", "pending...")
        key_path = ssh_keys[i]["key_path"]
        print(f"{name:<10} {ip:<15} {token:<20} {key_path}")

    print(f"\n{'─' * 70}")
    print("📋 Per-team instructions (distribute to players):")
    print(f"{'─' * 70}")

    for i in range(num_teams):
        team = chr(ord('A') + i) if i < 26 else f"T{i}"
        name = f"Team-{team}"
        ip = f"10.80.{i}.2"
        token = tokens.get(name, {}).get("token", "???")
        vpn_conf = os.path.join(WG_DIR, "clients", f"team-{team.lower()}.conf")
        key_path = ssh_keys[i]["key_path"]

        print(f"\n  === {name} ===")
        if wg_keys:
            print(f"  1. Import VPN:  {vpn_conf}")
        print(f"  2. SSH to box:  ssh -i {key_path} root@{ip}")
        print(f"  3. Submit flag: curl -X PUT http://10.80.0.1:8080/flags/ \\")
        print(f"                    -H 'X-Team-Token: {token}' \\")
        print(f"                    -H 'Content-Type: application/json' \\")
        print(f"                    -d '[\"FLAG_HERE\"]'")
        print(f"  4. Attack data: curl http://10.80.0.1:8080/api/client/attack_data/")
        print(f"  5. Challenges:  notekeeper (web :8080) | calcpwn (pwn :8081)")

    # Save summary to file
    summary_path = os.path.join(GENERATED_DIR, "game_info.json")
    summary = {
        "scoreboard": f"http://{host_ip}:8080",
        "admin": {"url": f"http://{host_ip}:8080/admin/", "user": "admin", "pass": "admin123"},
        "vpn_port": 51820,
        "start_time": start_time.isoformat(),
        "tick_seconds": tick_seconds,
        "total_ticks": total_ticks,
        "teams": {},
    }
    for i in range(num_teams):
        team = chr(ord('A') + i) if i < 26 else f"T{i}"
        name = f"Team-{team}"
        summary["teams"][name] = {
            "ip": f"10.80.{i}.2",
            "token": tokens.get(name, {}).get("token", ""),
            "ssh_key": ssh_keys[i]["key_path"],
            "vpn_config": os.path.join(WG_DIR, "clients", f"team-{team.lower()}.conf"),
        }

    with open(summary_path, "w") as f:
        json.dump(summary, f, indent=2)
    print(f"\n💾 Game info saved to: {summary_path}")


def destroy():
    """Tear down everything."""
    print("🗑️  Destroying game environment...")
    run(f"cd {SCRIPT_DIR} && docker compose down -v --remove-orphans", check=False)
    run(f"cd {FORCAD_DIR} && docker compose down -v --remove-orphans", check=False)
    run(f"docker network rm {NETWORK_NAME}", check=False)
    if os.path.exists(GENERATED_DIR):
        shutil.rmtree(GENERATED_DIR)
    if os.path.exists(os.path.join(SCRIPT_DIR, "Dockerfile.vulnbox")):
        os.remove(os.path.join(SCRIPT_DIR, "Dockerfile.vulnbox"))
    print("✅ Everything destroyed.")


def detect_host_ip():
    """Detect best host IP (prefer Tailscale, then LAN)."""
    import socket
    # Try Tailscale
    try:
        result = run("ifconfig | grep -o '100\\.[0-9]*\\.[0-9]*\\.[0-9]*'", capture=True, check=False)
        ips = result.stdout.strip().split("\n")
        for ip in ips:
            if ip.startswith("100."):
                return ip
    except Exception:
        pass
    # Fallback to LAN IP
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "localhost"


def main():
    parser = argparse.ArgumentParser(
        description="🏁 A/D CTF Game Generator",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=textwrap.dedent("""\
            Examples:
              python3 generate_game.py 3              # 3 teams, 200 rounds, 60s each
              python3 generate_game.py 5 100 30       # 5 teams, 100 rounds, 30s ticks
              python3 generate_game.py --destroy       # Tear down everything
        """),
    )
    parser.add_argument("num_teams", nargs="?", type=int, default=3, help="Number of teams (default: 3)")
    parser.add_argument("ticks", nargs="?", type=int, default=200, help="Total ticks/rounds (default: 200)")
    parser.add_argument("tick_seconds", nargs="?", type=int, default=60, help="Seconds per tick (default: 60)")
    parser.add_argument("--destroy", action="store_true", help="Tear down the entire game environment")
    parser.add_argument("--host-ip", default=None, help="Host IP for VPN endpoint (auto-detected)")
    args = parser.parse_args()

    if args.destroy:
        destroy()
        return

    num_teams = args.num_teams
    total_ticks = args.ticks
    tick_seconds = args.tick_seconds

    if num_teams < 2 or num_teams > 26:
        print("❌ Need 2-26 teams")
        sys.exit(1)

    host_ip = args.host_ip or detect_host_ip()

    print("=" * 60)
    print(f"🏁 Generating A/D CTF: {num_teams} teams, {total_ticks} rounds × {tick_seconds}s")
    print(f"   Host IP: {host_ip}")
    print("=" * 60)

    # Check dependencies
    try:
        import yaml
    except ImportError:
        print("Installing PyYAML...")
        run("pip3 install pyyaml", check=True)
        import yaml

    # Stop existing if any
    print("\n🧹 Cleaning up previous game...")
    run(f"cd {SCRIPT_DIR} && docker compose down -v --remove-orphans 2>/dev/null", check=False)
    run(f"cd {FORCAD_DIR} && docker compose down -v --remove-orphans 2>/dev/null", check=False)

    ensure_dirs()

    # Step 1: Generate SSH keys
    ssh_keys = generate_ssh_keys(num_teams)

    # Step 2: Generate WireGuard keys
    wg_keys = generate_wg_keys(num_teams)

    # Step 3: Generate Dockerfile with SSH
    generate_vulnbox_dockerfile(ssh_keys)

    # Step 4: Generate vulnbox docker-compose
    generate_vulnbox_compose(num_teams, ssh_keys)

    # Step 5: Generate WireGuard configs
    generate_wg_configs(num_teams, wg_keys, host_ip)

    # Step 6: Generate ForcAD config
    start_time = generate_forcad_config(num_teams, total_ticks, tick_seconds)

    # Step 7: Create Docker network
    create_network()

    # Step 8: Start vulnboxes
    start_vulnboxes()

    # Step 9: Start ForcAD
    start_forcad()

    # Step 10: Wait for services
    wait_for_services(num_teams)

    # Step 11: Wait for ForcAD to initialize and get tokens
    print("\n⏳ Waiting for ForcAD to initialize...")
    tokens = {}
    for _ in range(30):
        time.sleep(2)
        tokens = get_team_tokens()
        if len(tokens) >= num_teams:
            break

    # Print summary
    print_summary(num_teams, ssh_keys, wg_keys, tokens, start_time, tick_seconds, total_ticks, host_ip)


if __name__ == "__main__":
    main()
