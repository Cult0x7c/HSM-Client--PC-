import sys
import hashlib
import re
import os

def verify_log_chain_from_file(file_path):
    if not os.path.exists(file_path):
        print(f"❌ Datei nicht gefunden: {file_path}")
        return

    with open(file_path, "r", encoding="utf-8") as f:
        log_lines = [line.strip() for line in f.readlines() if line.strip()]

    previous_hash = bytes([0x00] * 32)
    all_ok = True

    print(f"\n🔍 Überprüfe Audit-Log: {file_path}\n{'-'*60}")

    for idx in range(0, len(log_lines), 2):
        if idx + 1 >= len(log_lines):
            print(f"⚠️ Unvollständiger Log-Eintrag bei Zeile {idx}, übersprungen.")
            continue

        message_line = log_lines[idx]
        hash_line = log_lines[idx + 1]

        # Extrahiere erwarteten Hash
        match = re.match(r"Hash:\s*([a-fA-F0-9]{64})", hash_line)
        if not match:
            print(f"❌ Kein gültiger Hash bei Zeile {idx + 2}: {hash_line}")
            all_ok = False
            continue

        expected_hash = match.group(1).lower()

        # Bereite Nachricht vor (60 Bytes, nullgepadded)
        message_bytes = message_line.encode("utf-8")
        if len(message_bytes) > 60:
            print(f"⚠️ WARNUNG: Nachricht länger als 60 Bytes! Möglicher Fehler.")
        padded_msg = message_bytes.ljust(60, b'\x00')

        # Kombinieren mit vorherigem Hash
        combined = previous_hash + padded_msg
        computed_hash = hashlib.sha256(combined).hexdigest()

        if computed_hash != expected_hash:
            print(f"❌ Ungültiger Hash bei Eintrag {idx // 2}:")
            print(f"  Nachricht   : {message_line}")
            print(f"  Erwarteter : {expected_hash}")
            print(f"  Berechnet  : {computed_hash}")
            all_ok = False
        else:
            print(f"✅ Eintrag {idx // 2} verifiziert.")

        previous_hash = bytes.fromhex(expected_hash)

    print("\n" + ("✅ Audit-Hash-Chain ist intakt!" if all_ok else "❌ Audit-Log wurde manipuliert oder ist beschädigt."))


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("❗️Benutzung: py verify.py <pfad_zur_auditlog.txt>")
        sys.exit(1)

    log_path = sys.argv[1]
    verify_log_chain_from_file(log_path)
