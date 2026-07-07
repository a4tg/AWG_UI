import json
import sqlite3
import traceback
from datetime import datetime, timezone
from http import HTTPStatus
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

from backend.provisioner import (
    ProvisioningError,
    bootstrap_server,
    build_vpn_uri,
    check_server_access,
    disable_server_key,
    enable_server_key,
    make_client_label,
    provision_server_key,
)


ROOT = Path(__file__).resolve().parent.parent
DATA_DIR = ROOT / "data"
DB_PATH = DATA_DIR / "awg_manager.db"
CONFIG_PATH = ROOT / "config" / "servers.json"
WEB_DIR = ROOT / "web"


def now_utc() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def parse_timestamp(value: str | None) -> datetime | None:
    if not value:
        return None
    normalized = value.replace("Z", "+00:00")
    return datetime.fromisoformat(normalized)


def ensure_directories() -> None:
    DATA_DIR.mkdir(exist_ok=True)
    CONFIG_PATH.parent.mkdir(exist_ok=True)
    if not CONFIG_PATH.exists():
        CONFIG_PATH.write_text(json.dumps({"servers": []}, indent=2), encoding="utf-8")


def get_db() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def _existing_columns(conn: sqlite3.Connection, table_name: str) -> set[str]:
    rows = conn.execute(f"PRAGMA table_info({table_name})").fetchall()
    return {row["name"] for row in rows}


def init_db() -> None:
    ensure_directories()
    with get_db() as conn:
        conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                contact TEXT,
                note TEXT,
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
            );

            CREATE TABLE IF NOT EXISTS keys (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                server_id TEXT NOT NULL,
                server_name TEXT NOT NULL,
                public_key TEXT NOT NULL,
                private_key_masked TEXT NOT NULL,
                config_blob TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'active',
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY(user_id) REFERENCES users(id)
            );
            """
        )

        columns = _existing_columns(conn, "keys")
        migrations = {
            "expires_at": "ALTER TABLE keys ADD COLUMN expires_at TEXT",
            "is_perpetual": "ALTER TABLE keys ADD COLUMN is_perpetual INTEGER NOT NULL DEFAULT 1",
            "blocked_at": "ALTER TABLE keys ADD COLUMN blocked_at TEXT",
            "block_reason": "ALTER TABLE keys ADD COLUMN block_reason TEXT",
        }
        for name, statement in migrations.items():
            if name not in columns:
                conn.execute(statement)


def load_servers() -> list[dict]:
    ensure_directories()
    payload = json.loads(CONFIG_PATH.read_text(encoding="utf-8"))
    return payload.get("servers", [])


def save_servers(servers: list[dict]) -> None:
    ensure_directories()
    CONFIG_PATH.write_text(json.dumps({"servers": servers}, ensure_ascii=False, indent=2), encoding="utf-8")


def server_map() -> dict[str, dict]:
    return {server["id"]: server for server in load_servers()}


def require_server(server_id: str) -> dict:
    server = server_map().get(server_id)
    if not server:
        raise LookupError("Server not found")
    return server


def add_server(payload: dict) -> dict:
    name = (payload.get("name") or "").strip()
    host = (payload.get("host") or "").strip()
    location = (payload.get("location") or name).strip()
    ssh_user = (payload.get("ssh_user") or "root").strip()
    ssh_port = int(payload.get("ssh_port") or 22)
    password = payload.get("password") or ""
    endpoint_host = (payload.get("endpoint_host") or host).strip()

    if not name:
        raise ValueError("Server name is required")
    if not host:
        raise ValueError("Server host is required")
    if not password:
        raise ValueError("Server password is required for first-time setup")

    server_id = (payload.get("id") or name.lower().strip()).replace(" ", "-")
    server = {
        "id": server_id,
        "name": name,
        "host": host,
        "endpoint_host": endpoint_host,
        "location": location,
        "ssh_user": ssh_user,
        "ssh_port": ssh_port,
    }

    configured = bootstrap_server(server, password=password)
    servers = load_servers()
    if any(item["id"] == configured["id"] for item in servers):
        raise ValueError(f"Server with id '{configured['id']}' already exists")
    servers.append(configured)
    save_servers(servers)
    return configured


def list_users() -> list[dict]:
    with get_db() as conn:
        rows = conn.execute(
            """
            SELECT
                u.id,
                u.name,
                u.contact,
                u.note,
                u.created_at,
                COUNT(k.id) AS keys_total,
                SUM(CASE WHEN k.status = 'active' THEN 1 ELSE 0 END) AS active_keys
            FROM users u
            LEFT JOIN keys k ON k.user_id = u.id
            GROUP BY u.id
            ORDER BY u.name COLLATE NOCASE, u.id
            """
        ).fetchall()
    return [dict(row) for row in rows]


def serialize_key(row: sqlite3.Row) -> dict:
    item = dict(row)
    item["is_perpetual"] = bool(item.get("is_perpetual"))
    item["vpn_uri"] = build_vpn_uri(item["server_name"], item["config_blob"], item["public_key"])
    item["is_expired_now"] = bool(
        item["status"] == "expired"
        or (not item["is_perpetual"] and parse_timestamp(item.get("expires_at")) and parse_timestamp(item.get("expires_at")) <= datetime.now(timezone.utc))
    )
    return item


def fetch_key(conn: sqlite3.Connection, key_id: int) -> sqlite3.Row | None:
    return conn.execute(
        """
        SELECT
            k.id,
            k.user_id,
            k.server_id,
            k.server_name,
            k.public_key,
            k.private_key_masked,
            k.config_blob,
            k.status,
            k.expires_at,
            k.is_perpetual,
            k.blocked_at,
            k.block_reason,
            k.created_at,
            u.name AS user_name,
            u.contact AS user_contact,
            u.note AS user_note
        FROM keys k
        JOIN users u ON u.id = k.user_id
        WHERE k.id = ?
        """,
        (key_id,),
    ).fetchone()


def fetch_server_keys(server_id: str) -> list[dict]:
    with get_db() as conn:
        rows = conn.execute(
            """
            SELECT
                k.id,
                k.user_id,
                k.server_id,
                k.server_name,
                k.public_key,
                k.private_key_masked,
                k.config_blob,
                k.status,
                k.expires_at,
                k.is_perpetual,
                k.blocked_at,
                k.block_reason,
                k.created_at,
                u.name AS user_name,
                u.contact AS user_contact,
                u.note AS user_note
            FROM keys k
            JOIN users u ON u.id = k.user_id
            WHERE k.server_id = ?
            ORDER BY
                CASE k.status
                    WHEN 'active' THEN 0
                    WHEN 'blocked' THEN 1
                    WHEN 'expired' THEN 2
                    ELSE 3
                END,
                u.name COLLATE NOCASE,
                k.id DESC
            """,
            (server_id,),
        ).fetchall()
    return [serialize_key(row) for row in rows]


def _server_stats_by_id() -> dict[str, dict]:
    with get_db() as conn:
        rows = conn.execute(
            """
            SELECT
                server_id,
                COUNT(*) AS total_keys,
                SUM(CASE WHEN status = 'active' THEN 1 ELSE 0 END) AS active_keys,
                SUM(CASE WHEN status = 'blocked' THEN 1 ELSE 0 END) AS blocked_keys,
                SUM(CASE WHEN status = 'expired' THEN 1 ELSE 0 END) AS expired_keys
            FROM keys
            GROUP BY server_id
            """
        ).fetchall()
    stats = {}
    for row in rows:
        stats[row["server_id"]] = {
            "total_keys": row["total_keys"] or 0,
            "active_keys": row["active_keys"] or 0,
            "blocked_keys": row["blocked_keys"] or 0,
            "expired_keys": row["expired_keys"] or 0,
        }
    return stats


def list_servers_with_stats() -> list[dict]:
    stats = _server_stats_by_id()
    items = []
    for server in load_servers():
        merged = dict(server)
        merged.update(stats.get(server["id"], {"total_keys": 0, "active_keys": 0, "blocked_keys": 0, "expired_keys": 0}))
        items.append(merged)
    return items


def server_details(server_id: str) -> dict:
    server = require_server(server_id)
    enriched = next((item for item in list_servers_with_stats() if item["id"] == server_id), dict(server))
    return {"server": enriched, "keys": fetch_server_keys(server_id)}


def get_or_create_user(payload: dict) -> sqlite3.Row:
    name = (payload.get("name") or "").strip()
    if not name:
        raise ValueError("Client name is required")

    contact = (payload.get("contact") or "").strip()
    note = (payload.get("note") or "").strip()

    with get_db() as conn:
        existing = conn.execute(
            """
            SELECT id, name, contact, note, created_at
            FROM users
            WHERE lower(name) = lower(?)
            ORDER BY id
            LIMIT 1
            """,
            (name,),
        ).fetchone()
        if existing:
            next_contact = contact or (existing["contact"] or "")
            next_note = note or (existing["note"] or "")
            if next_contact != (existing["contact"] or "") or next_note != (existing["note"] or ""):
                conn.execute(
                    "UPDATE users SET contact = ?, note = ? WHERE id = ?",
                    (next_contact, next_note, existing["id"]),
                )
                existing = conn.execute(
                    "SELECT id, name, contact, note, created_at FROM users WHERE id = ?",
                    (existing["id"],),
                ).fetchone()
            return existing

        cursor = conn.execute(
            "INSERT INTO users (name, contact, note) VALUES (?, ?, ?)",
            (name, contact, note),
        )
        return conn.execute(
            "SELECT id, name, contact, note, created_at FROM users WHERE id = ?",
            (cursor.lastrowid,),
        ).fetchone()


def parse_validity(payload: dict) -> tuple[str | None, int]:
    if payload.get("is_perpetual"):
        return None, 1

    expires_at_raw = (payload.get("expires_at") or "").strip()
    if not expires_at_raw:
        raise ValueError("Specify 'Годен до' or enable perpetual access")

    if len(expires_at_raw) == 10:
        expires_at = f"{expires_at_raw}T23:59:59Z"
    else:
        parsed = datetime.fromisoformat(expires_at_raw.replace("Z", "+00:00"))
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)
        expires_at = parsed.astimezone(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")

    if parse_timestamp(expires_at) <= datetime.now(timezone.utc):
        raise ValueError("Expiration date must be in the future")
    return expires_at, 0


def sync_expired_keys() -> int:
    current_time = now_utc()
    with get_db() as conn:
        rows = conn.execute(
            """
            SELECT
                k.id,
                k.server_id,
                k.public_key,
                k.server_name
            FROM keys k
            WHERE k.status = 'active'
              AND k.is_perpetual = 0
              AND k.expires_at IS NOT NULL
              AND k.expires_at <= ?
            ORDER BY k.id
            """,
            (current_time,),
        ).fetchall()

    if not rows:
        return 0

    servers = server_map()
    updated = 0
    for row in rows:
        server = servers.get(row["server_id"])
        if server:
            disable_server_key(server, row["public_key"])
        with get_db() as conn:
            conn.execute(
                """
                UPDATE keys
                SET status = 'expired',
                    blocked_at = ?,
                    block_reason = 'expired'
                WHERE id = ? AND status = 'active'
                """,
                (current_time, row["id"]),
            )
        updated += 1
    return updated


def issue_key(payload: dict) -> dict:
    server_id = (payload.get("server_id") or "").strip()
    if not server_id:
        raise ValueError("Server id is required")

    server = require_server(server_id)
    user = get_or_create_user(payload)
    expires_at, is_perpetual = parse_validity(payload)
    issued = provision_server_key(user["id"], user["name"], server)

    with get_db() as conn:
        cursor = conn.execute(
            """
            INSERT INTO keys (
                user_id,
                server_id,
                server_name,
                public_key,
                private_key_masked,
                config_blob,
                status,
                expires_at,
                is_perpetual
            )
            VALUES (?, ?, ?, ?, ?, ?, 'active', ?, ?)
            """,
            (
                user["id"],
                issued["server_id"],
                issued["server_name"],
                issued["public_key"],
                issued["private_key_masked"],
                issued["config_blob"],
                expires_at,
                is_perpetual,
            ),
        )
        row = fetch_key(conn, cursor.lastrowid)
    return serialize_key(row)


def update_key_validity(payload: dict) -> dict:
    key_id = int(payload.get("key_id", 0))
    if not key_id:
        raise ValueError("Key id is required")
    expires_at, is_perpetual = parse_validity(payload)
    with get_db() as conn:
        if not fetch_key(conn, key_id):
            raise LookupError("Key not found")
        conn.execute(
            "UPDATE keys SET expires_at = ?, is_perpetual = ? WHERE id = ?",
            (expires_at, is_perpetual, key_id),
        )
        row = fetch_key(conn, key_id)
    return serialize_key(row)


def block_key(payload: dict) -> dict:
    key_id = int(payload.get("key_id", 0))
    if not key_id:
        raise ValueError("Key id is required")

    with get_db() as conn:
        row = fetch_key(conn, key_id)
        if not row:
            raise LookupError("Key not found")
        if row["status"] != "active":
            return serialize_key(row)

    server = require_server(row["server_id"])
    disable_server_key(server, row["public_key"])
    with get_db() as conn:
        conn.execute(
            """
            UPDATE keys
            SET status = 'blocked',
                blocked_at = ?,
                block_reason = 'manual'
            WHERE id = ?
            """,
            (now_utc(), key_id),
        )
        updated = fetch_key(conn, key_id)
    return serialize_key(updated)


def unblock_key(payload: dict) -> dict:
    key_id = int(payload.get("key_id", 0))
    if not key_id:
        raise ValueError("Key id is required")

    with get_db() as conn:
        row = fetch_key(conn, key_id)
        if not row:
            raise LookupError("Key not found")
        if row["status"] == "active":
            return serialize_key(row)

    if not row["is_perpetual"]:
        expires_at = parse_timestamp(row["expires_at"])
        if not expires_at or expires_at <= datetime.now(timezone.utc):
            raise ValueError("This key is expired. Extend 'Годен до' or switch it to perpetual before unblocking.")

    server = require_server(row["server_id"])
    label = make_client_label(row["user_name"], row["user_id"], row["server_name"])
    enable_server_key(server, row["public_key"], row["config_blob"], label)
    with get_db() as conn:
        conn.execute(
            """
            UPDATE keys
            SET status = 'active',
                blocked_at = NULL,
                block_reason = NULL
            WHERE id = ?
            """,
            (key_id,),
        )
        updated = fetch_key(conn, key_id)
    return serialize_key(updated)


def delete_key(key_id: int) -> None:
    with get_db() as conn:
        row = fetch_key(conn, key_id)
        if not row:
            raise LookupError("Key not found")

    if row["status"] == "active":
        server = require_server(row["server_id"])
        disable_server_key(server, row["public_key"])

    with get_db() as conn:
        conn.execute("DELETE FROM keys WHERE id = ?", (key_id,))
        remaining = conn.execute("SELECT COUNT(*) AS total FROM keys WHERE user_id = ?", (row["user_id"],)).fetchone()
        if (remaining["total"] or 0) == 0:
            conn.execute("DELETE FROM users WHERE id = ?", (row["user_id"],))


def check_servers_status() -> list[dict]:
    return [check_server_access(server) for server in load_servers()]


class ApiHandler(SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=str(WEB_DIR), **kwargs)

    def do_GET(self) -> None:
        parsed = urlparse(self.path)
        try:
            if parsed.path.startswith("/api/"):
                sync_expired_keys()

            if parsed.path == "/api/servers":
                self._send_json({"servers": list_servers_with_stats()})
                return
            if parsed.path == "/api/server-details":
                query = parse_qs(parsed.query)
                server_id = (query.get("id", [""])[0] or "").strip()
                if not server_id:
                    self._send_json({"error": "Missing server id"}, status=HTTPStatus.BAD_REQUEST)
                    return
                self._send_json(server_details(server_id))
                return
            if parsed.path == "/api/users":
                self._send_json({"users": list_users()})
                return
            if parsed.path == "/api/server-check":
                self._send_json({"servers": check_servers_status()})
                return
            if parsed.path == "/health":
                self._send_json({"status": "ok"})
                return
            return super().do_GET()
        except ValueError as exc:
            self._send_json({"error": str(exc)}, status=HTTPStatus.BAD_REQUEST)
        except LookupError as exc:
            self._send_json({"error": str(exc)}, status=HTTPStatus.NOT_FOUND)
        except Exception as exc:
            traceback.print_exc()
            self._send_json({"error": f"Unexpected error: {exc}"}, status=HTTPStatus.INTERNAL_SERVER_ERROR)

    def do_POST(self) -> None:
        parsed = urlparse(self.path)
        body = self._read_json()

        try:
            if parsed.path.startswith("/api/"):
                sync_expired_keys()

            if parsed.path == "/api/servers":
                server = add_server(body)
                self._send_json(server, status=HTTPStatus.CREATED)
                return

            if parsed.path == "/api/keys":
                key = issue_key(body)
                self._send_json(key, status=HTTPStatus.CREATED)
                return

            if parsed.path == "/api/keys/block":
                key = block_key(body)
                self._send_json(key)
                return

            if parsed.path == "/api/keys/unblock":
                key = unblock_key(body)
                self._send_json(key)
                return

            if parsed.path == "/api/keys/validity":
                key = update_key_validity(body)
                self._send_json(key)
                return

            self._send_json({"error": "Not found"}, status=HTTPStatus.NOT_FOUND)
        except ValueError as exc:
            self._send_json({"error": str(exc)}, status=HTTPStatus.BAD_REQUEST)
        except LookupError as exc:
            self._send_json({"error": str(exc)}, status=HTTPStatus.NOT_FOUND)
        except ProvisioningError as exc:
            self._send_json({"error": str(exc)}, status=HTTPStatus.BAD_REQUEST)
        except Exception as exc:
            traceback.print_exc()
            self._send_json({"error": f"Unexpected error: {exc}"}, status=HTTPStatus.INTERNAL_SERVER_ERROR)

    def do_DELETE(self) -> None:
        parsed = urlparse(self.path)
        try:
            if parsed.path == "/api/servers/all":
                save_servers([])
                self._send_json({"deleted": True})
                return

            if parsed.path == "/api/servers":
                query = parse_qs(parsed.query)
                server_id = (query.get("id", [""])[0] or "").strip()
                if not server_id:
                    self._send_json({"error": "Missing server id"}, status=HTTPStatus.BAD_REQUEST)
                    return

                servers = load_servers()
                filtered = [server for server in servers if server["id"] != server_id]
                if len(filtered) == len(servers):
                    self._send_json({"error": "Server not found"}, status=HTTPStatus.NOT_FOUND)
                    return
                save_servers(filtered)
                self._send_json({"deleted": True})
                return

            if parsed.path == "/api/keys":
                query = parse_qs(parsed.query)
                key_id = int(query.get("id", ["0"])[0])
                delete_key(key_id)
                self._send_json({"deleted": True})
                return

            self._send_json({"error": "Not found"}, status=HTTPStatus.NOT_FOUND)
        except ValueError as exc:
            self._send_json({"error": str(exc)}, status=HTTPStatus.BAD_REQUEST)
        except LookupError as exc:
            self._send_json({"error": str(exc)}, status=HTTPStatus.NOT_FOUND)
        except ProvisioningError as exc:
            self._send_json({"error": str(exc)}, status=HTTPStatus.BAD_REQUEST)
        except Exception as exc:
            traceback.print_exc()
            self._send_json({"error": f"Unexpected error: {exc}"}, status=HTTPStatus.INTERNAL_SERVER_ERROR)

    def _read_json(self) -> dict:
        length = int(self.headers.get("Content-Length", "0"))
        raw = self.rfile.read(length) if length else b"{}"
        return json.loads(raw.decode("utf-8") or "{}")

    def _send_json(self, payload: dict, status: HTTPStatus = HTTPStatus.OK) -> None:
        raw = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)


def run(host: str = "127.0.0.1", port: int = 8080) -> None:
    init_db()
    sync_expired_keys()
    server = ThreadingHTTPServer((host, port), ApiHandler)
    print(f"AWG Manager running at http://{host}:{port}")
    server.serve_forever()
