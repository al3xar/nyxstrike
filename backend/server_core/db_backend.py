"""
backend/server_core/db_backend.py

Pluggable database backend for NyxStrike's shared DB (backend/server_core/db.py).

NyxStrike's own persistence (LLM sessions, vulnerabilities, chat, credentials,
loot) historically lives in a single SQLite file. For the cyber-range Kubernetes
deployment we need N-safe, networked persistence, so this module abstracts the
connection behind a *drop-in, connection-compatible* object and lets the SAME SQL
that db.py already writes run on either SQLite (local dev/build) or PostgreSQL
(in-cluster).

Design goal — MINIMAL FOOTPRINT on db.py:
  db.py talks to `self._conn` using a small slice of the sqlite3.Connection API
  (execute / executescript / commit / cursor / close, plus cursor.lastrowid /
  fetchone / fetchall, and one `PRAGMA table_info(...)`). This module returns an
  object exposing exactly that surface, so db.py's ONLY change is its `_connect()`
  factory — every query, migration and DDL string in db.py stays byte-for-byte
  identical. That keeps our fork decoupled from upstream: future upstream edits to
  db.py's queries merge cleanly because we never touched them.

Backend selection (resolved once, at process start):
  - NYXSTRIKE_DB_BACKEND = "sqlite" (default) | "postgres" / "postgresql"
  - If DATABASE_URL (or NYXSTRIKE_DATABASE_URL) starts with postgres://, the
    backend is inferred as Postgres even if NYXSTRIKE_DB_BACKEND is unset.
  - Anything else falls back to SQLite → the local flow is NEVER broken.

What the Postgres adapter normalizes so db.py's SQLite-flavoured SQL just works:
  - Parameter placeholder:  "?"              -> "%s"
  - "INSERT OR IGNORE INTO" -> "INSERT INTO ... ON CONFLICT DO NOTHING"
  - "datetime('now')"       -> "CURRENT_TIMESTAMP"
  - "INTEGER PRIMARY KEY AUTOINCREMENT" (DDL) -> "BIGSERIAL PRIMARY KEY"
  - lastrowid: SQLite has cursor.lastrowid; Postgres has none, so INSERTs are
    rewritten to "... RETURNING id" and the value is read back (tables whose PK
    is a TEXT column have no "id" and transparently fall back to no RETURNING).
  - Rows behave like BOTH a dict (row["col"]) and a tuple (row[0]) — db.py does
    both (row["tags"] in query helpers, row[0]/row[1] in COUNT and PRAGMA paths).
  - "PRAGMA table_info(<table>)" is answered from information_schema, shaped like
    SQLite's PRAGMA output so `{row[1] for row in cur.fetchall()}` keeps working.

Concurrency note:
  Locking is owned by the CALLER (NyxStrikeDB._lock in db.py), which already wraps
  every multi-statement operation. On SQLite we hand back the real connection; on
  Postgres one long-lived connection under that same lock mirrors the original
  single-writer model. Horizontal scaling can later swap in a pool without db.py
  changes.

  psycopg (v3) is imported LAZILY and only when Postgres is actually selected, so
  SQLite-only installs need no extra dependency.
"""

import logging
import os
import re
import sqlite3
import threading
from typing import Any, List, Optional, Sequence

logger = logging.getLogger(__name__)

SQLITE = "sqlite"
POSTGRES = "postgres"


def resolve_backend() -> str:
  """Return the active backend id ("sqlite" or "postgres")."""
  explicit = os.environ.get("NYXSTRIKE_DB_BACKEND", "").strip().lower()
  if explicit in ("postgres", "postgresql", "pg"):
    return POSTGRES
  if explicit in ("sqlite", "sqlite3"):
    return SQLITE
  url = (
    os.environ.get("DATABASE_URL")
    or os.environ.get("NYXSTRIKE_DATABASE_URL")
    or ""
  ).strip().lower()
  if url.startswith("postgres://") or url.startswith("postgresql://"):
    return POSTGRES
  return SQLITE


def database_url() -> str:
  """Return the configured Postgres connection URL (DSN)."""
  return (
    os.environ.get("DATABASE_URL")
    or os.environ.get("NYXSTRIKE_DATABASE_URL")
    or ""
  ).strip()


def connect(sqlite_path: str) -> Any:
  """Return a connection object db.py can use exactly like a sqlite3.Connection.

  SQLite  -> the real, fully-configured sqlite3.Connection (zero behaviour change).
  Postgres -> a _PostgresConnection adapter exposing the same method surface.
  """
  backend = resolve_backend()
  if backend == POSTGRES:
    conn = _connect_postgres()
    logger.info("db backend: postgres")
    return conn
  conn = _connect_sqlite(sqlite_path)
  logger.info("db backend: sqlite (%s)", sqlite_path)
  return conn


def _connect_sqlite(path: str) -> sqlite3.Connection:
  conn = sqlite3.connect(path, check_same_thread=False)
  conn.row_factory = sqlite3.Row
  conn.execute("PRAGMA journal_mode=WAL")
  conn.execute("PRAGMA foreign_keys=ON")
  conn.commit()
  return conn


def _connect_postgres() -> "_PostgresConnection":
  dsn = database_url()
  if not dsn:
    raise RuntimeError(
      "Postgres backend selected but no DATABASE_URL/NYXSTRIKE_DATABASE_URL set"
    )
  try:
    import psycopg  # noqa: F401  (imported for the clear error message below)
  except ImportError as exc:  # pragma: no cover - only hit in pg deployments
    raise RuntimeError(
      "Postgres backend requires the 'psycopg[binary]' package. "
      "Install the 'postgres' extra (pip install '.[postgres]') or set "
      "NYXSTRIKE_DB_BACKEND=sqlite."
    ) from exc
  return _PostgresConnection(dsn)


# ── SQL dialect translation (SQLite-flavoured source -> Postgres) ─────────────

_DATETIME_NOW_RE = re.compile(r"datetime\(\s*'now'\s*\)", re.IGNORECASE)
_INSERT_OR_IGNORE_RE = re.compile(r"INSERT\s+OR\s+IGNORE\s+INTO", re.IGNORECASE)
_AUTOINCR_RE = re.compile(
  r"INTEGER\s+PRIMARY\s+KEY\s+AUTOINCREMENT", re.IGNORECASE
)
_PRAGMA_TABLE_INFO_RE = re.compile(
  r"^\s*PRAGMA\s+table_info\(\s*([A-Za-z_][A-Za-z0-9_]*)\s*\)\s*;?\s*$",
  re.IGNORECASE,
)


def _to_postgres_sql(sql: str) -> str:
  """Translate a single SQLite-flavoured statement to valid Postgres SQL."""
  sql = _DATETIME_NOW_RE.sub("CURRENT_TIMESTAMP", sql)
  # "?" placeholders -> "%s". Identifiers/string literals in db.py never embed
  # "?", so a plain replace is safe.
  sql = sql.replace("?", "%s")
  # "INSERT OR IGNORE INTO" -> plain INSERT (the ON CONFLICT tail is appended in
  # _PostgresCursor.execute once we know it was an insert-or-ignore).
  sql = _INSERT_OR_IGNORE_RE.sub("INSERT INTO", sql)
  return sql


def _ddl_to_postgres(script: str) -> str:
  """Translate a CREATE TABLE / INDEX / ALTER script from db.py to Postgres."""
  s = script
  s = _AUTOINCR_RE.sub("BIGSERIAL PRIMARY KEY", s)
  s = _DATETIME_NOW_RE.sub("CURRENT_TIMESTAMP", s)
  # SQLite stores TEXT timestamps; Postgres accepts TEXT here too, so column
  # types are left as-is to preserve db.py's read/write data contract.
  return s


def _split_statements(script: str) -> List[str]:
  """Split a multi-statement DDL script on top-level ';'.

  db.py's schema scripts contain no ';' inside string literals or parentheses,
  so a plain split is correct and keeps this simple.
  """
  return [stmt.strip() for stmt in script.split(";") if stmt.strip()]


# ── Postgres connection/cursor adapters (sqlite3-compatible surface) ──────────

class _StaticCursor:
  """Cursor holding pre-computed tuple rows (used for the PRAGMA table_info path).

  Rows are plain tuples so the caller's index access (`row[1]`) works exactly as
  it does against SQLite's PRAGMA output.
  """

  def __init__(self, rows: List[tuple]):
    self._rows = rows
    self.lastrowid = None

  def fetchone(self):
    return self._rows[0] if self._rows else None

  def fetchall(self):
    return list(self._rows)


class _PostgresCursor:
  """Wraps a psycopg cursor, adding sqlite-style translation + lastrowid."""

  def __init__(self, conn: "_PostgresConnection"):
    self._conn = conn
    self._cur = conn.raw.cursor()
    self.lastrowid: Optional[Any] = None

  # -- write / read --------------------------------------------------------------

  def execute(self, sql: str, params: Sequence[Any] = ()):  # noqa: C901
    # SQLite silently coerces Python bools into its INTEGER flag columns
    # (verified, is_summarized, ...); Postgres is strict, so match SQLite's lax
    # behaviour without editing any call site in db.py.
    params = [int(p) if isinstance(p, bool) else p for p in params]

    is_insert_ignore = bool(_INSERT_OR_IGNORE_RE.search(sql))
    pg_sql = _to_postgres_sql(sql)
    is_insert = pg_sql.lstrip().upper().startswith("INSERT")
    if is_insert_ignore:
      pg_sql = pg_sql.rstrip().rstrip(";") + " ON CONFLICT DO NOTHING"

    if is_insert:
      # Try to read the generated integer id back; tables keyed by a TEXT PK have
      # no "id" column, so RETURNING id raises and we retry without it.
      try:
        self._cur.execute(pg_sql.rstrip().rstrip(";") + " RETURNING id", tuple(params))
      except Exception:
        self._conn.raw.rollback()
        self._cur = self._conn.raw.cursor()
        self._cur.execute(pg_sql, tuple(params))
      else:
        try:
          row = self._cur.fetchone()
          if row is not None:
            self.lastrowid = row["id"] if isinstance(row, dict) else row[0]
        except Exception:
          self.lastrowid = None
      return self

    self._cur.execute(pg_sql, tuple(params))
    return self

  def executescript(self, script: str):
    for stmt in _split_statements(_ddl_to_postgres(script)):
      self._cur.execute(stmt)
    return self

  def fetchone(self):
    return self._cur.fetchone()

  def fetchall(self):
    return self._cur.fetchall()


class _PostgresConnection:
  """A sqlite3.Connection look-alike backed by a single psycopg connection.

  Only the surface db.py actually uses is implemented; each method mirrors the
  sqlite3 semantics db.py relies on.
  """

  # Settable no-op so db.py-style `conn.row_factory = ...` (if ever re-added) is
  # harmless; rows are already dual dict/tuple via the psycopg row factory.
  row_factory = None

  def __init__(self, dsn: str):
    import psycopg
    self.raw = psycopg.connect(dsn, autocommit=False, row_factory=_dual_row)
    logger.debug("db: connected postgres")

  def execute(self, sql: str, params: Sequence[Any] = ()):
    # PRAGMA table_info(<table>) -> information_schema, shaped like SQLite's
    # PRAGMA output (cid, name, type, notnull, dflt_value, pk) so db.py's
    # `{row[1] for row in cur.fetchall()}` migration probe keeps working.
    m = _PRAGMA_TABLE_INFO_RE.match(sql)
    if m:
      table = m.group(1)
      cur = self.raw.cursor()
      cur.execute(
        "SELECT column_name FROM information_schema.columns "
        "WHERE table_name = %s ORDER BY ordinal_position",
        (table,),
      )
      rows = []
      for i, r in enumerate(cur.fetchall()):
        name = r["column_name"] if isinstance(r, dict) else r[0]
        rows.append((i, name, "", 0, None, 0))
      return _StaticCursor(rows)

    cur = _PostgresCursor(self)
    return cur.execute(sql, params)

  def executescript(self, script: str):
    cur = _PostgresCursor(self)
    return cur.executescript(script)

  def cursor(self) -> _PostgresCursor:
    return _PostgresCursor(self)

  def commit(self) -> None:
    self.raw.commit()

  def rollback(self) -> None:
    self.raw.rollback()

  def close(self) -> None:
    try:
      self.raw.close()
    except Exception as exc:  # pragma: no cover
      logger.warning("db: error closing postgres connection: %s", exc)


def _dual_row(cursor) -> Any:
  """psycopg3 row factory: build rows usable as BOTH dict and tuple.

  db.py reads rows by column name (row["tags"]) in its query helpers and by
  position (row[0] in COUNT queries) — a plain dict_row breaks the latter and a
  tuple_row breaks the former, so we return a dict subclass that also honours
  integer indexing by column position.
  """
  cols = [c.name for c in cursor.description] if cursor.description else []

  def make(values) -> "_DualRow":
    return _DualRow(cols, values)

  return make


class _DualRow(dict):
  """A dict row that also supports positional access and dict(row)."""

  __slots__ = ("_values",)

  def __init__(self, cols: Sequence[str], values: Sequence[Any]):
    super().__init__(zip(cols, values))
    self._values = tuple(values)

  def __getitem__(self, key):
    if isinstance(key, int):
      return self._values[key]
    return super().__getitem__(key)
