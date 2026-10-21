"""
crypto.py
Kriptografik işlemlerin tamamı bu modülde toplanır.
Uygulama katmanı şifreleme detaylarını bilmez.

Kullanılan standartlar:
  - Anahtar türetme : PBKDF2HMAC + SHA-256 + rastgele Salt (32 byte)
  - Şifreleme       : Fernet (AES-128-CBC + HMAC-SHA256)
  - İterasyon sayısı: 480.000 (OWASP 2023 önerisi)
"""

import base64
import os

from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

# OWASP 2023 önerisi: SHA-256 için minimum 480.000 iterasyon
PBKDF2_ITERATIONS = 480_000
SALT_SIZE = 32  # byte


def generate_salt() -> bytes:
    """
    Kriptografik olarak güvenli rastgele salt üretir.
    Yalnızca kasa ilk oluşturulurken bir kez çağrılır.
    """
    return os.urandom(SALT_SIZE)


def derive_key(master_password: str, salt: bytes) -> bytes:
    """
    Master Password + Salt → Fernet uyumlu 32-byte anahtar.

    PBKDF2HMAC, kaba kuvvet saldırılarını yavaşlatmak için
    parolayı 480.000 kez hash'ler. Salt ise önceden
    hesaplanmış sözlük (rainbow table) saldırılarını engeller.

    Dönen değer: URL-safe base64 kodlu 32-byte anahtar
    """
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=PBKDF2_ITERATIONS,
    )
    raw_key = kdf.derive(master_password.encode("utf-8"))
    return base64.urlsafe_b64encode(raw_key)


def encrypt(plaintext: str, fernet_key: bytes) -> bytes:
    """
    Düz metni Fernet ile şifreler.
    Fernet = AES-128-CBC şifreleme + HMAC-SHA256 kimlik doğrulaması.
    Her şifreleme çağrısında rastgele IV (Initialization Vector) üretilir.
    """
    f = Fernet(fernet_key)
    return f.encrypt(plaintext.encode("utf-8"))


def decrypt(ciphertext: bytes, fernet_key: bytes) -> str:
    """
    Şifreli veriyi çözer.
    Yanlış anahtar → InvalidToken hatası fırlatır (sessizce başarısız olmaz).
    Bu davranış kasıtlıdır: yanlış Master Password tüm veriyi çözülemez kılar.
    """
    f = Fernet(fernet_key)
    return f.decrypt(ciphertext).decode("utf-8")
