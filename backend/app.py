import json
import sqlite3
import traceback
from http import HTTPStatus
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

from backend.provisioner import provision_user_bundle


ROOT = Path(__file__).resolve().parent.parent
DATA_DIR = ROOT / "data"
DB_PATH = DATA_DIR / "awg_manager.db"
CONFIG_PATH = ROOT / "config" / "servers.json"
WEB_DIR = ROOT / "web"


def ensure_directories() -> None:
    DATA_DIR.mkdir(exist_ok=True)
    CONFIG_PATH.parent.mkdir(exist_ok=True)
    if not CONFIG_PATH.exists():
        CONFIG_PATH.write_text(
            json.dumps(
                {
                    "servers": [
                        {"id": "ch", "name": "Switzerland", "host": "swiss.example.com", "location": "Zurich"},
                        {"id": "de", "name": "Germany", "host": "germany.example.com", "location": "Frankfurt"},
                        {"id": "nl", "name": "Netherlands", "host": "nl.example.com", "location": "Amsterdam"},
                    ]
                },
                indent=2,
            ),
            encoding="utf-8",
        )


def get_db() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


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


def load_servers() -> list[dict]:
    ensure_directories()
    payload = json.loads(CONFIG_PATH.read_text(encoding="utf-8"))
    return payload.get("servers", [])


def serialize_user(row: sqlite3.Row, keys: list[dict]) -> dict:
    return {
        "id": row["id"],
        "name": row["name"],
        "contact": row["contact"] or "",
        "note": row["note"] or "",
        "created_at": row["created_at"],
        "keys": keys,
    }


def fetch_user_keys(conn: sqlite3.Connection, user_id: int) -> list[dict]:
    rows = conn.execute(
        """
        SELECT id, server_id, server_name, public_key, private_key_masked, config_blob, status, created_at
        FROM keys
        WHERE user_id = ?
        ORDER BY id
        """,
        (user_id,),
    ).fetchall()
    return [dict(row) for row in rows]


def list_users() -> list[dict]:
    with get_db() as conn:
        rows = conn.execute(
            "SELECT id, name, contact, note, created_at FROM users ORDER BY id DESC"
        ).fetchall()
        return [serialize_user(row, fetch_user_keys(conn, row["id"])) for row in rows]


def create_user(payload: dict) -> dict:
    name = (payload.get("name") or "").strip()
    if not name:
        raise ValueError("Name is required")

    contact = (payload.get("contact") or "").strip()
    note = (payload.get("note") or "").strip()
    with get_db() as conn:
        cursor = conn.execute(
            "INSERT INTO users (name, contact, note) VALUES (?, ?, ?)",
            (name, contact, note),
        )
        user_id = cursor.lastrowid
        row = conn.execute(
            "SELECT id, name, contact, note, created_at FROM users WHERE id = ?",
            (user_id,),
        ).fetchone()
        return serialize_user(row, [])


def provision_bundle(user_id: int) -> dict:
    servers = load_servers()
    with get_db() as conn:
        user = conn.execute(
            "SELECT id, name, contact, note, created_at FROM users WHERE id = ?",
            (user_id,),
        ).fetchone()
        if user is None:
            raise LookupError("User not found")

        existing = conn.execute(
            "SELECT COUNT(*) AS total FROM keys WHERE user_id = ?",
            (user_id,),
        ).fetchone()
        if existing["total"] > 0:
            return serialize_user(user, fetch_user_keys(conn, user_id))

        issued_keys = provision_user_bundle(user["id"], user["name"], servers)
        for item in issued_keys:
            conn.execute(
                """
                INSERT INTO keys (user_id, server_id, server_name, public_key, private_key_masked, config_blob, status)
                VALUES (?, ?, ?, ?, ?, ?, 'active')
                """,
                (
                    user_id,
                    item["server_id"],
                    item["server_name"],
                    item["public_key"],
                    item["private_key_masked"],
                    item["config_blob"],
                ),
            )
        return serialize_user(user, fetch_user_keys(conn, user_id))


class ApiHandler(SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=str(WEB_DIR), **kwargs)

    def do_GET(self) -> None:
        parsed = urlparse(self.path)
        if parsed.path == "/api/servers":
            self._send_json({"servers": load_servers()})
            return
        if parsed.path == "/api/users":
            self._send_json({"users": list_users()})
            return
        if parsed.path == "/health":
            self._send_json({"status": "ok"})
            return
        return super().do_GET()

    def do_POST(self) -> None:
        parsed = urlparse(self.path)
        body = self._read_json()

        try:
            if parsed.path == "/api/users":
                user = create_user(body)
                self._send_json(user, status=HTTPStatus.CREATED)
                return

            if parsed.path == "/api/provision":
                user_id = int(body.get("user_id", 0))
                user = provision_bundle(user_id)
                self._send_json(user)
                return

            self._send_json({"error": "Not found"}, status=HTTPStatus.NOT_FOUND)
        except ValueError as exc:
            self._send_json({"error": str(exc)}, status=HTTPStatus.BAD_REQUEST)
        except LookupError as exc:
            self._send_json({"error": str(exc)}, status=HTTPStatus.NOT_FOUND)
        except Exception as exc:
            traceback.print_exc()
            self._send_json({"error": f"Unexpected error: {exc}"}, status=HTTPStatus.INTERNAL_SERVER_ERROR)

    def do_DELETE(self) -> None:
        parsed = urlparse(self.path)
        if parsed.path != "/api/users":
            self._send_json({"error": "Not found"}, status=HTTPStatus.NOT_FOUND)
            return

        query = parse_qs(parsed.query)
        try:
            user_id = int(query.get("id", ["0"])[0])
        except ValueError:
            self._send_json({"error": "Invalid user id"}, status=HTTPStatus.BAD_REQUEST)
            return

        with get_db() as conn:
            conn.execute("DELETE FROM keys WHERE user_id = ?", (user_id,))
            deleted = conn.execute("DELETE FROM users WHERE id = ?", (user_id,)).rowcount
        if not deleted:
            self._send_json({"error": "User not found"}, status=HTTPStatus.NOT_FOUND)
            return
        self._send_json({"deleted": True})

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
    server = ThreadingHTTPServer((host, port), ApiHandler)
    print(f"AWG Manager running at http://{host}:{port}")
    server.serve_forever()
