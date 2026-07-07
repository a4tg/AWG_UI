import base64
import ipaddress
import json
import re
import shlex
import subprocess
import zlib
from dataclasses import dataclass
from pathlib import Path

try:
    import paramiko
except ImportError:  # pragma: no cover
    paramiko = None


CONTAINER_NAME = "amnezia-awg2"
REMOTE_CONF_PATH = "/opt/amnezia/awg/awg0.conf"
REMOTE_CLIENTS_TABLE_PATH = "/opt/amnezia/awg/clientsTable"
DEFAULT_IDENTITY_FILE = Path.home() / ".ssh" / "id_ed25519"
DEFAULT_PUBLIC_KEY_FILE = Path.home() / ".ssh" / "id_ed25519.pub"


class ProvisioningError(RuntimeError):
    pass


@dataclass
class ServerState:
    config_text: str
    clients_table_text: str
    server_public_key: str


def build_vpn_uri(server_name: str, config_blob: str, client_public_key: str) -> str:
    interface = _parse_ini_section(config_blob, "Interface")
    peer = _parse_ini_section(config_blob, "Peer")
    endpoint_host, endpoint_port = _split_endpoint(peer["Endpoint"])
    allowed_ips = [item.strip() for item in peer["AllowedIPs"].split(",") if item.strip()]
    subnet_address = _subnet_address_from_interface(interface["Address"])

    last_config_payload = {
        "H1": interface.get("H1", ""),
        "H2": interface.get("H2", ""),
        "H3": interface.get("H3", ""),
        "H4": interface.get("H4", ""),
        "I1": interface.get("I1", ""),
        "I2": interface.get("I2", ""),
        "I3": interface.get("I3", ""),
        "I4": interface.get("I4", ""),
        "I5": interface.get("I5", ""),
        "Jc": interface.get("Jc", ""),
        "Jmax": interface.get("Jmax", ""),
        "Jmin": interface.get("Jmin", ""),
        "S1": interface.get("S1", ""),
        "S2": interface.get("S2", ""),
        "S3": interface.get("S3", ""),
        "S4": interface.get("S4", ""),
        "allowed_ips": allowed_ips,
        "clientId": client_public_key,
        "client_ip": interface["Address"].split("/")[0],
        "client_priv_key": interface["PrivateKey"],
        "client_pub_key": client_public_key,
        "config": config_blob,
        "hostName": endpoint_host,
        "mtu": "1376",
        "persistent_keep_alive": peer.get("PersistentKeepalive", "25"),
        "port": int(endpoint_port),
        "psk_key": peer["PresharedKey"],
        "server_pub_key": peer["PublicKey"],
    }

    payload = {
        "containers": [
            {
                "awg": {
                    "H1": last_config_payload["H1"],
                    "H2": last_config_payload["H2"],
                    "H3": last_config_payload["H3"],
                    "H4": last_config_payload["H4"],
                    "I1": last_config_payload["I1"],
                    "I2": last_config_payload["I2"],
                    "I3": last_config_payload["I3"],
                    "I4": last_config_payload["I4"],
                    "I5": last_config_payload["I5"],
                    "Jc": last_config_payload["Jc"],
                    "Jmax": last_config_payload["Jmax"],
                    "Jmin": last_config_payload["Jmin"],
                    "S1": last_config_payload["S1"],
                    "S2": last_config_payload["S2"],
                    "S3": last_config_payload["S3"],
                    "S4": last_config_payload["S4"],
                    "last_config": json.dumps(last_config_payload, ensure_ascii=False, indent=4) + "\n",
                    "port": endpoint_port,
                    "protocol_version": "2",
                    "subnet_address": subnet_address,
                    "transport_proto": "udp",
                },
                "container": CONTAINER_NAME,
            }
        ],
        "defaultContainer": CONTAINER_NAME,
        "description": server_name,
        "dns1": "1.1.1.1",
        "dns2": "1.0.0.1",
        "hostName": endpoint_host,
        "nameOverriddenByUser": True,
    }

    raw = json.dumps(payload, ensure_ascii=False, indent=4).encode("utf-8")
    compressed = zlib.compress(raw)
    wrapped = len(compressed).to_bytes(4, "big") + compressed
    encoded = base64.urlsafe_b64encode(wrapped).decode("ascii").rstrip("=")
    return f"vpn://{encoded}"


def _parse_ini_section(config_blob: str, section_name: str) -> dict[str, str]:
    pattern = rf"\[{re.escape(section_name)}\](.*?)(?:\n\[|\Z)"
    match = re.search(pattern, config_blob, re.DOTALL)
    if not match:
        raise ProvisioningError(f"Missing [{section_name}] section in config blob")
    section = {}
    for line in match.group(1).splitlines():
        if "=" not in line:
            continue
        key, value = line.split("=", 1)
        section[key.strip()] = value.strip()
    return section


def _split_endpoint(endpoint: str) -> tuple[str, str]:
    host, port = endpoint.rsplit(":", 1)
    return host.strip(), port.strip()


def _subnet_address_from_interface(address: str) -> str:
    network = ipaddress.ip_network(address, strict=False)
    return str(network.network_address)


def _require_paramiko() -> None:
    if paramiko is None:
        raise ProvisioningError(
            "Password-based server setup requires paramiko. Install it with: python -m pip install paramiko"
        )


def _run_ssh(server: dict, remote_command: str, stdin_text: str | None = None) -> str:
    ssh_user = server.get("ssh_user", "root")
    ssh_port = str(server.get("ssh_port", 22))
    host = server["host"]
    target = f"{ssh_user}@{host}"
    command = [
        "ssh",
        "-o",
        "BatchMode=yes",
        "-o",
        "ConnectTimeout=10",
        "-o",
        "StrictHostKeyChecking=accept-new",
    ]
    identity_file = server.get("identity_file")
    if identity_file:
        command.extend(["-i", identity_file])

    command.extend(["-p", ssh_port, target, remote_command])
    result = subprocess.run(
        command,
        input=stdin_text,
        text=True,
        capture_output=True,
        check=False,
        timeout=30,
    )
    if result.returncode != 0:
        error_text = (result.stderr or result.stdout).strip()
        if "Permission denied" in error_text:
            raise ProvisioningError(
                f"{server['name']}: SSH access denied. Configure key-based login for {target}"
                + (" via identity_file" if identity_file else "")
                + " or add a working SSH key to your agent."
            )
        raise ProvisioningError(f"{server['name']}: SSH command failed: {error_text}")
    return result.stdout


def _paramiko_connect(server: dict, password: str):
    _require_paramiko()
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        client.connect(
            hostname=server["host"],
            port=int(server.get("ssh_port", 22)),
            username=server.get("ssh_user", "root"),
            password=password,
            timeout=15,
            look_for_keys=False,
            allow_agent=False,
        )
        return client
    except Exception as exc:  # pragma: no cover
        raise ProvisioningError(f"{server['name']}: password login failed: {exc}") from exc


def _paramiko_run(client, command: str) -> tuple[int, str, str]:
    stdin, stdout, stderr = client.exec_command(command, timeout=30)
    exit_status = stdout.channel.recv_exit_status()
    return exit_status, stdout.read().decode("utf-8", errors="replace"), stderr.read().decode("utf-8", errors="replace")


def _read_public_key() -> str:
    if not DEFAULT_PUBLIC_KEY_FILE.exists():
        raise ProvisioningError(f"Local public key not found: {DEFAULT_PUBLIC_KEY_FILE}")
    return DEFAULT_PUBLIC_KEY_FILE.read_text(encoding="utf-8").strip()


def bootstrap_server(server: dict, password: str) -> dict:
    public_key = _read_public_key()
    client = _paramiko_connect(server, password)
    try:
        checks = [
            "command -v docker >/dev/null 2>&1",
            f"docker ps --format '{{{{.Names}}}}' | grep -x {CONTAINER_NAME}",
            f"docker exec {CONTAINER_NAME} test -f {REMOTE_CONF_PATH}",
            f"docker exec {CONTAINER_NAME} test -f {REMOTE_CLIENTS_TABLE_PATH}",
        ]
        for command in checks:
            code, _, err = _paramiko_run(client, command)
            if code != 0:
                raise ProvisioningError(f"{server['name']}: server check failed for `{command}`: {err.strip() or 'not found'}")

        escaped_key = public_key.replace("'", "'\"'\"'")
        install_key_command = (
            "mkdir -p /root/.ssh && chmod 700 /root/.ssh && "
            f"grep -qxF '{escaped_key}' /root/.ssh/authorized_keys 2>/dev/null || "
            f"printf '%s\\n' '{escaped_key}' >> /root/.ssh/authorized_keys && "
            "chmod 600 /root/.ssh/authorized_keys"
        )
        code, _, err = _paramiko_run(client, install_key_command)
        if code != 0:
            raise ProvisioningError(f"{server['name']}: failed to install public key: {err.strip() or 'unknown error'}")
    finally:
        client.close()

    configured = dict(server)
    configured["identity_file"] = str(DEFAULT_IDENTITY_FILE)
    return configured


def _docker_exec(server: dict, shell_command: str, stdin_text: str | None = None) -> str:
    remote = f"docker exec -i {CONTAINER_NAME} sh -lc {shlex.quote(shell_command)}"
    return _run_ssh(server, remote, stdin_text=stdin_text)


def check_server_access(server: dict) -> dict:
    try:
        output = _run_ssh(server, "echo ok").strip()
        if output != "ok":
            return {
                "server_id": server["id"],
                "server_name": server["name"],
                "ok": False,
                "message": f"Unexpected SSH response: {output or 'empty'}",
            }
        return {
            "server_id": server["id"],
            "server_name": server["name"],
            "ok": True,
            "message": "SSH access is working",
        }
    except ProvisioningError as exc:
        return {
            "server_id": server["id"],
            "server_name": server["name"],
            "ok": False,
            "message": str(exc),
        }


def _fetch_server_state(server: dict) -> ServerState:
    config_text = _docker_exec(server, f"cat {shlex.quote(REMOTE_CONF_PATH)}").strip()
    clients_table_text = _docker_exec(server, f"cat {shlex.quote(REMOTE_CLIENTS_TABLE_PATH)}").strip()
    server_public_key = _docker_exec(server, "cat /opt/amnezia/awg/wireguard_server_public_key.key").strip()
    return ServerState(
        config_text=config_text,
        clients_table_text=clients_table_text,
        server_public_key=server_public_key,
    )


def _generate_remote_keys(server: dict) -> tuple[str, str, str]:
    script = (
        'priv="$(awg genkey)"\n'
        'pub="$(printf %s "$priv" | awg pubkey)"\n'
        'psk="$(awg genpsk)"\n'
        'printf "%s\\n%s\\n%s\\n" "$priv" "$pub" "$psk"\n'
    )
    output = _docker_exec(server, script).strip().splitlines()
    if len(output) != 3:
        raise ProvisioningError(f"{server['name']}: failed to generate client keys")
    return output[0], output[1], output[2]


def _network_from_config(config_text: str) -> ipaddress.IPv4Network:
    network_raw = _extract_interface_value(config_text, "Address")
    return ipaddress.ip_network(network_raw, strict=False)


def _next_client_ip(config_text: str) -> str:
    network = _network_from_config(config_text)
    used_hosts: set[str] = set()
    for line in config_text.splitlines():
        if "AllowedIPs" not in line:
            continue
        match = re.search(r"AllowedIPs\s*=\s*([0-9.]+)/32", line)
        if match:
            used_hosts.add(match.group(1))

    for host in network.hosts():
        host_text = str(host)
        if host_text == str(network.network_address):
            continue
        if host_text == str(network.broadcast_address):
            continue
        if host_text.endswith(".1"):
            continue
        if host_text not in used_hosts:
            return host_text
    raise ProvisioningError(f"No free client IP addresses left in {network}")


def _extract_interface_value(config_text: str, key: str) -> str:
    match = re.search(rf"^{re.escape(key)}\s*=\s*(.+)$", config_text, re.MULTILINE)
    if not match:
        raise ProvisioningError(f"Missing {key} in server config")
    return match.group(1).strip()


def _extract_interface_section(config_text: str) -> str:
    match = re.search(r"\[Interface\](.*?)(?:\n\[Peer\]|\Z)", config_text, re.DOTALL)
    if not match:
        raise ProvisioningError("Missing [Interface] section in server config")
    return match.group(1)


def _extract_optional_values(config_text: str, keys: list[str]) -> dict[str, str | None]:
    section = _extract_interface_section(config_text)
    values: dict[str, str | None] = {}
    for key in keys:
        match = re.search(rf"^\s*#?\s*{re.escape(key)}\s*=\s*(.*)$", section, re.MULTILINE)
        if match:
            value = match.group(1).strip()
            values[key] = value if value else None
    return values


def _peer_exists(config_text: str, public_key: str) -> bool:
    pattern = rf"(?ms)^\[Peer\]\s+.*?^PublicKey\s*=\s*{re.escape(public_key)}\s*$"
    return re.search(pattern, config_text) is not None


def _append_peer(config_text: str, public_key: str, psk: str, client_ip: str) -> str:
    if _peer_exists(config_text, public_key):
        return config_text.rstrip() + "\n"
    peer_block = (
        "\n[Peer]\n"
        f"PublicKey = {public_key}\n"
        f"PresharedKey = {psk}\n"
        f"AllowedIPs = {client_ip}/32\n"
    )
    return config_text.rstrip() + "\n" + peer_block


def _remove_peer(config_text: str, public_key: str) -> tuple[str, bool]:
    chunks = re.split(r"(?m)^\[Peer\]\s*$", config_text.strip())
    if len(chunks) == 1:
        return config_text.rstrip() + "\n", False

    result = [chunks[0].rstrip() + "\n"]
    removed = False
    for chunk in chunks[1:]:
        block = chunk.strip()
        if not block:
            continue
        match = re.search(r"^PublicKey\s*=\s*(.+)$", block, re.MULTILINE)
        block_public_key = match.group(1).strip() if match else ""
        if block_public_key == public_key and not removed:
            removed = True
            continue
        result.append("[Peer]\n" + block.rstrip() + "\n")
    return "".join(result).rstrip() + "\n", removed


def _load_clients_table(clients_table_text: str) -> list[dict]:
    try:
        return json.loads(clients_table_text or "[]")
    except json.JSONDecodeError as exc:
        raise ProvisioningError(f"Invalid clientsTable JSON: {exc}") from exc


def _upsert_client_entry(clients_table_text: str, public_key: str, client_name: str) -> str:
    clients = _load_clients_table(clients_table_text)
    updated = False
    for item in clients:
        if item.get("clientId") == public_key:
            item["userData"] = item.get("userData") or {}
            item["userData"]["clientName"] = client_name
            updated = True
            break

    if not updated:
        clients.append(
            {
                "clientId": public_key,
                "userData": {
                    "clientName": client_name,
                    "creationDate": subprocess.run(
                        ["powershell", "-Command", "Get-Date -Format 'ddd MMM d HH:mm:ss yyyy'"],
                        text=True,
                        capture_output=True,
                        check=False,
                        timeout=10,
                    ).stdout.strip()
                    or "Generated by AWG Manager",
                },
            }
        )
    return json.dumps(clients, ensure_ascii=False, indent=4)


def _remove_client_entry(clients_table_text: str, public_key: str) -> tuple[str, bool]:
    clients = _load_clients_table(clients_table_text)
    filtered = [item for item in clients if item.get("clientId") != public_key]
    removed = len(filtered) != len(clients)
    return json.dumps(filtered, ensure_ascii=False, indent=4), removed


def _write_remote_file(server: dict, path: str, content: str) -> None:
    _docker_exec(server, f"cat > {shlex.quote(path)}", stdin_text=content)


def _apply_server_config(server: dict) -> None:
    _docker_exec(server, f"awg-quick strip {shlex.quote(REMOTE_CONF_PATH)} | awg syncconf awg0 /dev/stdin")


def _sanitize_label(raw_name: str) -> str:
    cleaned = re.sub(r"\s+", " ", raw_name.strip())
    cleaned = re.sub(r'[\\/:*?"<>|]', "_", cleaned)
    return cleaned[:64] or "client"


def make_client_label(user_name: str, user_id: int, server_name: str) -> str:
    return f"{_sanitize_label(user_name)} [{server_name}] #{user_id}"


def _build_client_config(
    server: dict,
    state: ServerState,
    client_private_key: str,
    client_psk: str,
    client_ip: str,
) -> str:
    listen_port = _extract_interface_value(state.config_text, "ListenPort")
    optional = _extract_optional_values(
        state.config_text,
        ["Jc", "Jmin", "Jmax", "S1", "S2", "S3", "S4", "H1", "H2", "H3", "H4", "I1", "I2", "I3", "I4", "I5"],
    )
    endpoint_host = server.get("endpoint_host") or server["host"]

    peer_lines = [
        f"PublicKey = {state.server_public_key}",
        f"PresharedKey = {client_psk}",
        f"Endpoint = {endpoint_host}:{listen_port}",
        "AllowedIPs = 0.0.0.0/0, ::/0",
        "PersistentKeepalive = 25",
    ]

    interface_lines = [
        "[Interface]",
        f"PrivateKey = {client_private_key}",
        f"Address = {client_ip}/32",
        "DNS = 1.1.1.1, 1.0.0.1",
    ]
    for key in ["Jc", "Jmin", "Jmax", "S1", "S2", "S3", "S4", "H1", "H2", "H3", "H4", "I1", "I2", "I3", "I4", "I5"]:
        if key not in optional:
            continue
        value = optional[key]
        if value is None:
            interface_lines.append(f"{key} =")
        else:
            interface_lines.append(f"{key} = {value}")

    return "\n".join(interface_lines) + "\n\n[Peer]\n" + "\n".join(peer_lines) + "\n"


def _validate_network(config_text: str) -> None:
    network = _network_from_config(config_text)
    if network.prefixlen > 30:
        raise ProvisioningError(f"Unexpected AWG network: {network}")


def _restore_details_from_client_config(config_blob: str) -> tuple[str, str]:
    interface = _parse_ini_section(config_blob, "Interface")
    peer = _parse_ini_section(config_blob, "Peer")
    client_ip = interface["Address"].split("/")[0].strip()
    client_psk = peer["PresharedKey"]
    return client_ip, client_psk


def provision_server_key(user_id: int, user_name: str, server: dict) -> dict:
    state = _fetch_server_state(server)
    _validate_network(state.config_text)

    client_private_key, client_public_key, client_psk = _generate_remote_keys(server)
    client_ip = _next_client_ip(state.config_text)
    client_label = make_client_label(user_name, user_id, server["name"])

    new_config = _append_peer(state.config_text, client_public_key, client_psk, client_ip)
    new_clients_table = _upsert_client_entry(state.clients_table_text, client_public_key, client_label)

    _write_remote_file(server, REMOTE_CONF_PATH, new_config)
    _write_remote_file(server, REMOTE_CLIENTS_TABLE_PATH, new_clients_table + "\n")
    _apply_server_config(server)

    return {
        "server_id": server["id"],
        "server_name": server["name"],
        "public_key": client_public_key,
        "private_key_masked": f"{client_private_key[:6]}...{client_private_key[-6:]}",
        "config_blob": _build_client_config(server, state, client_private_key, client_psk, client_ip),
        "client_label": client_label,
    }


def disable_server_key(server: dict, public_key: str) -> None:
    state = _fetch_server_state(server)
    new_config, removed_peer = _remove_peer(state.config_text, public_key)
    new_clients_table, removed_client = _remove_client_entry(state.clients_table_text, public_key)

    if removed_peer:
        _write_remote_file(server, REMOTE_CONF_PATH, new_config)
    if removed_client:
        _write_remote_file(server, REMOTE_CLIENTS_TABLE_PATH, new_clients_table + "\n")
    if removed_peer:
        _apply_server_config(server)


def enable_server_key(server: dict, public_key: str, config_blob: str, client_name: str) -> None:
    state = _fetch_server_state(server)
    client_ip, client_psk = _restore_details_from_client_config(config_blob)
    new_config = _append_peer(state.config_text, public_key, client_psk, client_ip)
    new_clients_table = _upsert_client_entry(state.clients_table_text, public_key, client_name)

    _write_remote_file(server, REMOTE_CONF_PATH, new_config)
    _write_remote_file(server, REMOTE_CLIENTS_TABLE_PATH, new_clients_table + "\n")
    _apply_server_config(server)
