"""
vault.py
Uygulama iş mantığı katmanı.
crypto.py ve database.py'yi bir araya getirir.
CLI katmanı (main.py) bu sınıfla konuşur; kriptografi detaylarını bilmez.
"""

import sys
from typing import List, Optional, Tuple

from cryptography.fernet import InvalidToken

from crypto import decrypt, derive_key, encrypt, generate_salt
from database import VaultDB

# Master Password doğrulama için kullanılan sabit metin.
# Bu metin şifrelenir ve veritabanına kaydedilir.
# Açılışta çözülerek parolanın doğruluğu test edilir.
VERIFY_PLAINTEXT = "VAULT_OK_v1"


class WrongPasswordError(Exception):
    """Yanlış Master Password girildiğinde fırlatılır."""
    pass


class Vault:
    """
    Parola kasasının tüm işlevlerini yöneten sınıf.

    Kullanım akışı:
        vault = Vault()
        if vault.is_new():
            vault.initialize("master_parolam")
        else:
            vault.unlock("master_parolam")   # WrongPasswordError fırlatabilir

        vault.add("github.com", "kullanici", "gizli_parola")
        entries = vault.list_entries()
        vault.close()
    """

    def __init__(self, db_path: str = "vault.db"):
        self._db = VaultDB(db_path)
        self._fernet_key: Optional[bytes] = None  # None iken kasa kilitli

    # ------------------------------------------------------------------
    # Kasa başlatma ve kilit açma
    # ------------------------------------------------------------------

    def is_new(self) -> bool:
        """Kasanın daha önce oluşturulup oluşturulmadığını kontrol eder."""
        return not self._db.is_initialized()

    def initialize(self, master_password: str) -> None:
        """
        Kasayı ilk kez oluşturur.
        1. Rastgele salt üretir.
        2. Salt + Master Password → Fernet anahtarı türetir.
        3. Doğrulama token'ı şifreler ve salt ile birlikte kaydeder.
        """
        salt = generate_salt()
        key = derive_key(master_password, salt)
        verify_token = encrypt(VERIFY_PLAINTEXT, key)
        self._db.save_master(salt, verify_token)
        self._fernet_key = key
        print("[✓] Kasa başarıyla oluşturuldu.")

    def unlock(self, master_password: str) -> None:
        """
        Master Password ile kasayı açar.
        Yanlış parola → WrongPasswordError.

        Doğrulama mantığı:
          - Veritabanındaki salt alınır.
          - Salt + girilen parola → anahtar türetilir.
          - Türetilen anahtar ile verify_token çözülmeye çalışılır.
          - Fernet InvalidToken fırlatırsa parola yanlıştır.
        """
        master_data = self._db.get_master()
        if master_data is None:
            raise RuntimeError("Kasa henüz oluşturulmamış. initialize() çağırın.")

        salt, verify_token = master_data
        key = derive_key(master_password, salt)

        try:
            result = decrypt(verify_token, key)
            if result != VERIFY_PLAINTEXT:
                raise WrongPasswordError()
        except InvalidToken:
            raise WrongPasswordError("Yanlış Master Password.")

        self._fernet_key = key
        print("[✓] Kasa açıldı.")

    def _require_unlocked(self) -> None:
        if self._fernet_key is None:
            raise RuntimeError("Kasa kilitli. Önce unlock() çağırın.")

    # ------------------------------------------------------------------
    # Parola işlemleri
    # ------------------------------------------------------------------

    def add(self, platform: str, username: str, password: str) -> int:
        """Yeni parola kaydı ekler. Eklenen kaydın ID'sini döner."""
        self._require_unlocked()
        ciphertext = encrypt(password, self._fernet_key)
        entry_id = self._db.add_entry(platform, username, ciphertext)
        print(f"[✓] '{platform}' için kayıt eklendi (ID: {entry_id}).")
        return entry_id

    def list_entries(self) -> List[dict]:
        """
        Tüm kayıtları döner. Parolalar çözülmüş halde gelir.
        Yanlış anahtar durumunda (teorik) WrongPasswordError fırlatır.
        """
        self._require_unlocked()
        rows = self._db.get_all_entries()
        result = []
        for row in rows:
            try:
                plain_pw = decrypt(bytes(row["encrypted_password"]), self._fernet_key)
            except InvalidToken:
                plain_pw = "[ÇÖZÜLEMEDI]"
            result.append({
                "id":       row["id"],
                "platform": row["platform"],
                "username": row["username"],
                "password": plain_pw,
                "created":  row["created_at"],
            })
        return result

    def get(self, entry_id: int) -> Optional[dict]:
        """Tek bir kaydı ID ile getirir."""
        self._require_unlocked()
        row = self._db.get_entry_by_id(entry_id)
        if row is None:
            return None
        plain_pw = decrypt(bytes(row["encrypted_password"]), self._fernet_key)
        return {
            "id":       row["id"],
            "platform": row["platform"],
            "username": row["username"],
            "password": plain_pw,
            "created":  row["created_at"],
        }

    def delete(self, entry_id: int) -> bool:
        """Kaydı siler. Başarılıysa True döner."""
        self._require_unlocked()
        success = self._db.delete_entry(entry_id)
        if success:
            print(f"[✓] ID {entry_id} silindi.")
        return success

    def search(self, keyword: str) -> List[dict]:
        """Platform veya kullanıcı adına göre arama yapar."""
        self._require_unlocked()
        rows = self._db.search_entries(keyword)
        result = []
        for row in rows:
            try:
                plain_pw = decrypt(bytes(row["encrypted_password"]), self._fernet_key)
            except InvalidToken:
                plain_pw = "[ÇÖZÜLEMEDI]"
            result.append({
                "id":       row["id"],
                "platform": row["platform"],
                "username": row["username"],
                "password": plain_pw,
                "created":  row["created_at"],
            })
        return result

    def close(self) -> None:
        """Kasayı kilitler ve veritabanı bağlantısını kapatır."""
        self._fernet_key = None
        self._db.close()
