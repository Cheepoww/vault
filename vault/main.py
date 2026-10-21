"""
main.py
CLI arayüzü — kullanıcıyla etkileşim bu katmanda gerçekleşir.
Vault sınıfını kullanır; kriptografi detaylarından habersizdir.

Komutlar:
  python main.py add      → Yeni parola ekle
  python main.py list     → Tüm parolaları listele
  python main.py get      → ID ile tek kayıt getir
  python main.py delete   → Kayıt sil
  python main.py search   → Arama yap
"""

import getpass
import sys

from vault import Vault, WrongPasswordError

MAX_UNLOCK_ATTEMPTS = 3


def prompt_master_password(prompt: str = "Master Password: ") -> str:
    """
    Parolayı ekranda göstermeden okur (getpass).
    Terminal yoksa (pipe, test) normal input kullanır.
    """
    try:
        return getpass.getpass(prompt)
    except Exception:
        return input(prompt)


def open_vault() -> Vault:
    """
    Kasayı açar. Yeni kasaysa oluşturur, mevcutsa kilidini açar.
    3 yanlış denemede programdan çıkar.
    """
    vault = Vault()

    if vault.is_new():
        print("=" * 50)
        print("  İlk kullanım: Yeni kasa oluşturuluyor.")
        print("=" * 50)
        while True:
            pw1 = prompt_master_password("Yeni Master Password: ")
            pw2 = prompt_master_password("Tekrar girin         : ")
            if pw1 != pw2:
                print("[!] Parolalar eşleşmiyor. Tekrar deneyin.")
                continue
            if len(pw1) < 8:
                print("[!] Parola en az 8 karakter olmalıdır.")
                continue
            vault.initialize(pw1)
            return vault

    print("=" * 50)
    print("  Kriptografik Parola Kasası")
    print("=" * 50)

    for attempt in range(1, MAX_UNLOCK_ATTEMPTS + 1):
        pw = prompt_master_password(f"Master Password ({attempt}/{MAX_UNLOCK_ATTEMPTS}): ")
        try:
            vault.unlock(pw)
            return vault
        except WrongPasswordError:
            print(f"[✗] Yanlış parola.")

    print("[!] Çok fazla hatalı deneme. Çıkılıyor.")
    sys.exit(1)


def cmd_add(vault: Vault) -> None:
    print("\n── Yeni Parola Ekle ──")
    platform = input("Platform (örn: github.com): ").strip()
    username = input("Kullanıcı adı / e-posta  : ").strip()
    password = prompt_master_password("Parola                   : ")
    if not platform or not username or not password:
        print("[!] Tüm alanlar doldurulmalıdır.")
        return
    vault.add(platform, username, password)


def cmd_list(vault: Vault) -> None:
    entries = vault.list_entries()
    if not entries:
        print("\n[i] Kayıtlı parola bulunamadı.")
        return
    print(f"\n{'ID':<5} {'Platform':<25} {'Kullanıcı':<25} {'Parola':<30} {'Tarih'}")
    print("-" * 100)
    for e in entries:
        print(f"{e['id']:<5} {e['platform']:<25} {e['username']:<25} {e['password']:<30} {e['created']}")


def cmd_get(vault: Vault) -> None:
    try:
        entry_id = int(input("Kayıt ID: ").strip())
    except ValueError:
        print("[!] Geçerli bir ID girin.")
        return
    entry = vault.get(entry_id)
    if entry is None:
        print("[!] Kayıt bulunamadı.")
        return
    print(f"\nPlatform  : {entry['platform']}")
    print(f"Kullanıcı : {entry['username']}")
    print(f"Parola    : {entry['password']}")
    print(f"Oluşturma : {entry['created']}")


def cmd_delete(vault: Vault) -> None:
    try:
        entry_id = int(input("Silinecek kayıt ID: ").strip())
    except ValueError:
        print("[!] Geçerli bir ID girin.")
        return
    confirm = input(f"ID {entry_id} silinecek. Emin misiniz? (e/h): ").strip().lower()
    if confirm != "e":
        print("[i] İptal edildi.")
        return
    vault.delete(entry_id)


def cmd_search(vault: Vault) -> None:
    keyword = input("Arama kelimesi: ").strip()
    if not keyword:
        return
    results = vault.search(keyword)
    if not results:
        print("[i] Sonuç bulunamadı.")
        return
    print(f"\n{'ID':<5} {'Platform':<25} {'Kullanıcı':<25} {'Parola'}")
    print("-" * 80)
    for e in results:
        print(f"{e['id']:<5} {e['platform']:<25} {e['username']:<25} {e['password']}")


COMMANDS = {
    "add":    cmd_add,
    "list":   cmd_list,
    "get":    cmd_get,
    "delete": cmd_delete,
    "search": cmd_search,
}


def print_help() -> None:
    print("\nKullanım: python main.py <komut>")
    print("\nKomutlar:")
    print("  add     Yeni parola ekle")
    print("  list    Tüm parolaları listele")
    print("  get     ID ile kayıt getir")
    print("  delete  Kayıt sil")
    print("  search  Platform/kullanıcı adına göre ara")


def main() -> None:
    if len(sys.argv) < 2 or sys.argv[1] not in COMMANDS:
        print_help()
        sys.exit(0)

    command = sys.argv[1]
    vault = open_vault()

    try:
        COMMANDS[command](vault)
    finally:
        vault.close()


if __name__ == "__main__":
    main()
