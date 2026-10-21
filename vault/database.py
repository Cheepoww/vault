"""
database.py
SQLite veritabanı katmanı.

Tablo yapısı:
  master  → salt (hex) saklar; Master Password doğrulama için
  entries → şifreli parola kayıtları

Güvenlik notu:
  - encrypted_password sütunu BLOB tipindedir; düz metin asla yazılmaz.
  - username düz metin saklanır (şifrelenmesi isteğe bağlı genişletilebilir).
  - Salt veritabanında saklanır; bu güvenlidir çünkü salt gizli değildir,
    sadece benzersiz olması yeterlidir. Gizli olan Master Password'dür.
"""

import sqlite3
from pathlib import Path
from typing import List, Optional, Tuple


class VaultDB:
    def __init__(self, db_path: str = "vault.db"):
        self._path = db_path
        self._conn = sqlite3.connect(db_path)
        self._conn.row_factory = sqlite3.Row
        self._init_tables()

    def _init_tables(self) -> None:
        self._conn.executescript("""
            CREATE TABLE IF NOT EXISTS master (
                id      INTEGER PRIMARY KEY CHECK (id = 1),
                salt    BLOB    NOT NULL,
                verify  BLOB    NOT NULL
            );

            CREATE TABLE IF NOT EXISTS entries (
                id                 INTEGER PRIMARY KEY AUTOINCREMENT,
                platform           TEXT    NOT NULL,
                username           TEXT    NOT NULL,
                encrypted_password BLOB    NOT NULL,
                created_at         TEXT    DEFAULT (datetime('now'))
            );
        """)
        self._conn.commit()

    # ------------------------------------------------------------------
    # Master / Salt işlemleri
    # ------------------------------------------------------------------

    def is_initialized(self) -> bool:
        """Kasanın daha önce oluşturulup oluşturulmadığını kontrol eder."""
        row = self._conn.execute("SELECT COUNT(*) FROM master").fetchone()
        return row[0] > 0

    def save_master(self, salt: bytes, verify_token: bytes) -> None:
        """
        Salt ve doğrulama token'ını kaydeder.
        verify_token: "VAULT_OK" metninin türetilen anahtarla şifrelenmiş hali.
        Master Password doğruluğunu test etmek için kullanılır.
        """
        self._conn.execute(
            "INSERT OR REPLACE INTO master (id, salt, verify) VALUES (1, ?, ?)",
            (salt, verify_token),
        )
        self._conn.commit()

    def get_master(self) -> Optional[Tuple[bytes, bytes]]:
        """(salt, verify_token) döner. Kasa oluşturulmamışsa None."""
        row = self._conn.execute("SELECT salt, verify FROM master").fetchone()
        if row is None:
            return None
        return bytes(row["salt"]), bytes(row["verify"])

    # ------------------------------------------------------------------
    # Parola kayıt işlemleri
    # ------------------------------------------------------------------

    def add_entry(self, platform: str, username: str, encrypted_password: bytes) -> int:
        """Yeni şifreli kayıt ekler. Eklenen kaydın ID'sini döner."""
        cur = self._conn.execute(
            "INSERT INTO entries (platform, username, encrypted_password) VALUES (?, ?, ?)",
            (platform, username, encrypted_password),
        )
        self._conn.commit()
        return cur.lastrowid

    def get_all_entries(self) -> List[sqlite3.Row]:
        """Tüm kayıtları döner (encrypted_password dahil)."""
        return self._conn.execute(
            "SELECT id, platform, username, encrypted_password, created_at FROM entries ORDER BY platform"
        ).fetchall()

    def get_entry_by_id(self, entry_id: int) -> Optional[sqlite3.Row]:
        return self._conn.execute(
            "SELECT * FROM entries WHERE id = ?", (entry_id,)
        ).fetchone()

    def delete_entry(self, entry_id: int) -> bool:
        cur = self._conn.execute("DELETE FROM entries WHERE id = ?", (entry_id,))
        self._conn.commit()
        return cur.rowcount > 0

    def search_entries(self, keyword: str) -> List[sqlite3.Row]:
        return self._conn.execute(
            "SELECT * FROM entries WHERE platform LIKE ? OR username LIKE ?",
            (f"%{keyword}%", f"%{keyword}%"),
        ).fetchall()

    def close(self) -> None:
        self._conn.close()
