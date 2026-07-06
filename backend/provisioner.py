import ipaddress
import json
import re
import shlex
import subprocess
from dataclasses import dataclass


CONTAINER_NAME = "amnezia-awg2"
REMOTE_CONF_PATH = "/opt/amnezia/awg/awg0.conf"
REMOTE_CLIENTS_TABLE_PATH = "/opt/amnezia/awg/clientsTable"


class ProvisioningError(RuntimeError):
    pass


@dataclass
class ServerState:
    config_text: str
    clients_table_text: str
    server_public_key: str


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

    command.extend(
        [
            "-p",
            ssh_port,
            target,
            remote_command,
        ]
    )
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


def _docker_exec(server: dict, shell_command: str, stdin_text: str | None = None) -> str:
    remote = f"docker exec -i {CONTAINER_NAME} sh -lc {shlex.quote(shell_command)}"
    return _run_ssh(server, remote, stdin_text=stdin_text)


def _fetch_server_state(server: dict) -> ServerState:
    config_text = _docker_exec(server, f"cat {shlex.quote(REMOTE_CONF_PATH)}").strip()
    clients_table_text = _docker_exec(server, f"cat {shlex.quote(REMOTE_CLIENTS_TABLE_PATH)}").strip()
    server_public_key = _docker_exec(
        server, "cat /opt/amnezia/awg/wireguard_server_public_key.key"
    ).strip()
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


def _next_client_ip(config_text: str) -> str:
    used_hosts: set[int] = set()
    for line in config_text.splitlines():
        if "AllowedIPs" not in line:
            continue
        match = re.search(r"10\.8\.1\.(\d+)/32", line)
        if match:
            used_hosts.add(int(match.group(1)))

    for host in range(2, 255):
        if host not in used_hosts:
            return f"10.8.1.{host}"
    raise ProvisioningError("No free client IP addresses left in 10.8.1.0/24")


def _extract_interface_value(config_text: str, key: str) -> str:
    match = re.search(rf"^{re.escape(key)}\s*=\s*(.+)$", config_text, re.MULTILINE)
    if not match:
        raise ProvisioningError(f"Missing {key} in server config")
    return match.group(1).strip()


def _extract_optional_values(config_text: str, keys: list[str]) -> dict[str, str]:
    values: dict[str, str] = {}
    for key in keys:
        match = re.search(rf"^#?\s*{re.escape(key)}\s*=\s*(.*)$", config_text, re.MULTILINE)
        if match:
            value = match.group(1).strip()
            if value:
                values[key] = value
    return values


def _append_peer(config_text: str, public_key: str, psk: str, client_ip: str) -> str:
    peer_block = (
        "\n[Peer]\n"
        f"PublicKey = {public_key}\n"
        f"PresharedKey = {psk}\n"
        f"AllowedIPs = {client_ip}/32\n"
    )
    return config_text.rstrip() + "\n" + peer_block


def _update_clients_table(clients_table_text: str, public_key: str, client_name: str) -> str:
    try:
        clients = json.loads(clients_table_text or "[]")
    except json.JSONDecodeError as exc:
        raise ProvisioningError(f"Invalid clientsTable JSON: {exc}") from exc

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


def _write_remote_file(server: dict, path: str, content: str) -> None:
    _docker_exec(server, f"cat > {shlex.quote(path)}", stdin_text=content)


def _apply_server_config(server: dict) -> None:
    _docker_exec(server, f"awg syncconf awg0 {shlex.quote(REMOTE_CONF_PATH)}")


def _sanitize_label(raw_name: str) -> str:
    cleaned = re.sub(r"\s+", " ", raw_name.strip())
    cleaned = re.sub(r'[\\/:*?"<>|]', "_", cleaned)
    return cleaned[:64] or "client"


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
    interface_lines.extend(f"{key} = {value}" for key, value in optional.items())

    return (
        "\n".join(interface_lines)
        + "\n\n"
        "[Peer]\n"
        + "\n".join(peer_lines)
        + "\n"
    )


def _validate_network(config_text: str) -> None:
    network_raw = _extract_interface_value(config_text, "Address")
    network = ipaddress.ip_network(network_raw, strict=False)
    if str(network.network_address) != "10.8.1.0":
        raise ProvisioningError(f"Unexpected AWG network: {network_raw}")


def _provision_server_bundle(user_name: str, user_id: int, server: dict) -> dict:
    state = _fetch_server_state(server)
    _validate_network(state.config_text)

    client_private_key, client_public_key, client_psk = _generate_remote_keys(server)
    client_ip = _next_client_ip(state.config_text)
    client_label = f"{_sanitize_label(user_name)} [{server['name']}] #{user_id}"

    new_config = _append_peer(state.config_text, client_public_key, client_psk, client_ip)
    new_clients_table = _update_clients_table(state.clients_table_text, client_public_key, client_label)

    _write_remote_file(server, REMOTE_CONF_PATH, new_config)
    _write_remote_file(server, REMOTE_CLIENTS_TABLE_PATH, new_clients_table + "\n")
    _apply_server_config(server)

    return {
        "server_id": server["id"],
        "server_name": server["name"],
        "public_key": client_public_key,
        "private_key_masked": f"{client_private_key[:6]}...{client_private_key[-6:]}",
        "config_blob": _build_client_config(server, state, client_private_key, client_psk, client_ip),
    }


def provision_user_bundle(user_id: int, user_name: str, servers: list[dict]) -> list[dict]:
    bundle = []
    for server in servers:
        bundle.append(_provision_server_bundle(user_name, user_id, server))
    return bundle
