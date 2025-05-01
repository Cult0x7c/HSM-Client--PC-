import serial
import time
import hashlib
import datetime
import re
import statistics
import csv
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature

# ========================== Configuration ==========================
SERIAL_PORT = "COM3"  # STM32 Port
BAUD_RATE = 115200
TIMEOUT = 1  # Timeout for serial responses

# ========================== GLOBAL VAR ==========================
stm32_public_key = None # the received public key from MCU

# ========================== Serial Setup ==========================
try:
    ser = serial.Serial(SERIAL_PORT, BAUD_RATE, timeout=TIMEOUT)
    print(f"✅ Connected to STM32 on {SERIAL_PORT} at {BAUD_RATE} baud.")
except serial.SerialException:
    print(f"❌ ERROR: Could not open {SERIAL_PORT}. Check your connection!")
    exit()

# ========================== Helper Functions ==========================

def send_command(command):
    ser.reset_input_buffer()  # Clear old incoming data
    ser.write(command.encode('utf-8') + b'\n')
    while True:
        response = ser.readline().decode(errors='ignore').strip()
        if response:
            print(f"📡 STM32: {response}")
        if "Waiting for command..." in response:
            break

def verify_signature(message, raw_signature, public_key):
    """
    Verifies an ECDSA signature using the received public key.
    """
    nums = public_key.public_numbers()
    print(f"🔐 Public Key X: {nums.x:064x}")
    print(f"🔐 Public Key Y: {nums.y:064x}")
    # Step 1: Hash the message using SHA-256
    message_bytes = message.encode('utf-8')
    message_hash = hashlib.sha256(message_bytes).digest()

    print(f"\n📦 Raw Message: {repr(message)}")
    print(f"🔢 Message Bytes: {message_bytes.hex()}")
    print(f"🔍 Python Hash: {message_hash.hex()}")

    # Step 2: Extract raw r and s values
    if len(raw_signature) != 64:
        print(f"❌ ERROR: Signature should be 64 bytes (r||s), got {len(raw_signature)} bytes")
        return

    # STM32 is sending s || r, so we flip
    r = int.from_bytes(raw_signature[:32], byteorder='big')
    s = int.from_bytes(raw_signature[32:], byteorder='big')



    print(f"🔑 Signature r: {r:064x}")
    print(f"🔑 Signature s: {s:064x}")

    # Step 3: Check if s is "high" (non-canonical)
    order = int("FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551", 16)
    print(f"⚠️ s is high: {s > order // 2}")
    if s > order // 2:
        print("📉 Normalizing s to low form (s = order - s)")
        s = order - s

    # Step 3: Convert raw r/s into DER-encoded format
    try:
        der_signature = encode_dss_signature(r, s)
        print(f"📄 DER-encoded Signature: {der_signature.hex()}")
    except Exception as e:
        print(f"❌ Failed to encode signature to DER: {e}")
        return
    

    # Step 4: Verify the signature using the public key
    try:
        public_key.verify(
            der_signature,
            message.encode('utf-8'),
            ec.ECDSA(hashes.SHA256())
        )
        print("✅ Signature is VALID!")
    except InvalidSignature:
        print("❌ Signature is INVALID!")
    except Exception as e:
        print(f"❌ Unexpected error during verification: {e}")

def send_message_for_signature(message):
    ser.reset_input_buffer()  # Clear leftover messages
    ser.write(b"SIGN\n")
    time.sleep(0.2)

    print("📨 Sent SIGN command. Waiting for STM32...")

    # Check initial STM32 response
    while True:
        response = ser.readline().decode(errors='ignore').strip()

        print(f"📡 STM32: {response}")
        if "ERROR" in response:
            print("❌ Aborting: STM32 not ready to sign.")
            return
        if "Waiting for message" in response:
            break  # STM32 is ready for the message
        if "Waiting for command" in response:
            print("ℹ️ STM32 didn't recognize SIGN in time — resending...")
            return  # or retry by calling send_message_for_signature(message) again


    # Now send the message and end marker
    ser.write(message.encode('utf-8') + b"\n")
    ser.write(b"[ENDSIGN]\n")
    print("📨 Sent message for signing...")
    print(f"[DEBUG] Message bytes: {message.encode('utf-8').hex()}")

    # Wait for STM32 to start sending the signature
    while True:
        response = ser.readline().decode(errors='ignore').strip()
        print(f"📡 STM32: {response}")
        if "[SIGN]" in response:
            break

    # Read the 64-byte signature
    signature = ser.read(64)

    if len(signature) == 64:
        print(f"🔏 Received Signature: {signature.hex()}")
    else:
        print(f"❌ ERROR: Signature length mismatch! Received {len(signature)} bytes.")

    # Wait for "[ENDSIGN]" marker
    while True:
        response = ser.readline().decode(errors='ignore').strip()
        if "[ENDSIGN]" in response:
            print("✅ Signature Transmission Completed.")
            break

    # Verify the signature
    if stm32_public_key is not None:
        verify_signature(message, signature, stm32_public_key)
    else:
        print("❌ ERROR: STM32 Public Key is missing! Please retrieve it first.")

def receive_public_key():
    """
    Receives the STM32 ECC public key (64 bytes) and ensures integrity.
    """
    ser.write(b"SENDPUB\n")
    print("🔄 Waiting for STM32 Public Key...")

    while True:
        response = ser.readline().decode(errors='ignore').strip()

        if "[PUBKEY]" in response:
            break  # continue receiving key

        if "No public key" in response:
            print(f"📡 STM32: {response}")
            return None  # abort early

        # Optional debug print
        print(f"📡 STM32: {response}")

    # Now read the key (same as before)
    received_public_key_bytes = bytearray()
    while len(received_public_key_bytes) < 64:
        chunk = ser.read(64 - len(received_public_key_bytes))
        if not chunk:
            print("❌ Error: Timeout while reading public key!")
            return None
        received_public_key_bytes.extend(chunk)

    # Wait for end marker
    while True:
        response = ser.readline().decode(errors='ignore').strip()
        if "[ENDKEY]" in response:
            print("✅ Public Key Transmission Completed.")
            return received_public_key_bytes

def reconstruct_pub_key(received_public_key_bytes):
    # Extract X and Y coordinates
    x = int.from_bytes(received_public_key_bytes[:32], byteorder="big")
    y = int.from_bytes(received_public_key_bytes[32:], byteorder="big")
    

    # Reconstruct the public key
    try:
        public_key = ec.EllipticCurvePublicNumbers(x, y, ec.SECP256R1()).public_key()
        print("🔑 Successfully reconstructed STM32 public key!")
        numbers = public_key.public_numbers()
        print(f"🔐 Public Key X: {numbers.x:064x}")
        print(f"🔐 Public Key Y: {numbers.y:064x}")

        return public_key
    except ValueError:
        print("❌ ERROR: Invalid EC key. The point is not on the SECP256R1 curve.")
        return None

def get_flash_logs():
    ser.reset_input_buffer()
    ser.write(b"GETLOGS\n")

    print("\n📜 Flash Audit Logs from STM32:\n" + "-" * 40)

    log_lines = []
    start_time = time.time()

    while True:
        line = ser.readline().decode(errors="ignore").strip()

        if not line:
            if time.time() - start_time > 1.0:
                break
            continue

        start_time = time.time()

        if (
            not line
            or line.isspace()
            or any(x in line for x in ("\x00", "\x01", "\x1b"))
            or line.startswith("Received:")
            or "Waiting for" in line
        ):
            continue

        print("•", line)
        log_lines.append(line)

        if line.startswith("Latest Hash:"):
            break

    if log_lines:
        filename = f"audit_flash_log_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
        with open(filename, "w") as f:
            for entry in log_lines:
                f.write(entry + "\n")
        print(f"\n✅ Logs saved to: {filename}")

        print("\n🔎 Überprüfe Hash-Chain...")
        verify_log_chain(log_lines)
    else:
        print("⚠️ No logs found.")

def verify_log_chain(log_lines):
    previous_hash = bytes([0x00] * 32)
    last_computed_hash = None
    final_hash_from_stm32 = None

    print("\n🔎 Hash-Chain-Debug:\n" + "-" * 64)

    for idx, line in enumerate(log_lines):
        line = line.strip()

        if line.startswith("Latest Hash:"):
            match = re.search(r"([a-fA-F0-9]{64})", line)
            if match:
                final_hash_from_stm32 = match.group(1).lower()
            continue

        message_bytes = line.encode("utf-8")
        if len(message_bytes) > 64:
            print(f"⚠️ WARNUNG: Log-Eintrag {idx} -+ als 64 Bytes. Er wird abgeschnitten.")
            message_bytes = message_bytes[:64]

        padded = message_bytes.ljust(64, b'\x00')
        combined = previous_hash + padded
        computed_hash = hashlib.sha256(combined).digest()

        # Debug info
        print(f"🔹 MSG[{idx}]: {repr(line)}")
        print(f"🔹 PAD : {padded.hex()}")
        print(f"🔹 INPUT: {combined.hex()}")
        print(f"🔹 HASH : {computed_hash.hex()}")
        print("-" * 64)

        last_computed_hash = computed_hash
        previous_hash = computed_hash

    if final_hash_from_stm32 is None:
        print("❌ Kein gültiger Final-Hash vom STM32 empfangen.")
        return

    if last_computed_hash is None:
        print("❌ Keine gültigen Log-Einträge zur Hash-Berechnung.")
        return

    computed_hex = last_computed_hash.hex()
    print("\n🔍 Vergleich mit STM32 Final Hash:")
    print(f"📦 Erwartet : {final_hash_from_stm32}")
    print(f"🧮 Berechnet: {computed_hex}")

    if computed_hex == final_hash_from_stm32:
        print("✅ Audit-Hash-Chain ist intakt!")
    else:
        print("❌ Audit-Hash-Chain ist ungültig!")

def send_rtc_time():

    # Get current local system time
    now = datetime.datetime.now()
    rtc_cmd = now.strftime("SETRTC %Y-%m-%d %H:%M:%S\n")

    # Send the command over UART
    ser.reset_input_buffer()
    ser.write(rtc_cmd.encode())

    print(f"Sent to STM32: {rtc_cmd.strip()}")

    # Read response from STM32
    time.sleep(0.2)  # short wait to allow STM32 to respond
    while ser.in_waiting:
        response = ser.readline().decode(errors="ignore").strip()
        if response:
            print(f"📡 STM32: {response}")

def send_message_for_signature_noverify(message):
    ser.reset_input_buffer()  # Clear leftover messages
    ser.write(b"SIGN\n")
    time.sleep(0.2)

    while True:
        response = ser.readline().decode(errors='ignore').strip()
        if "ERROR" in response:
            return False
        if "Waiting for message" in response:
            break
        if "Waiting for command" in response:
            return False

    ser.write(message.encode('utf-8') + b"\n")
    ser.write(b"[ENDSIGN]\n")

    while True:
        response = ser.readline().decode(errors='ignore').strip()
        if "[SIGN]" in response:
            break

    signature = ser.read(64)
    while True:
        response = ser.readline().decode(errors='ignore').strip()
        if "[ENDSIGN]" in response:
            break

    return True  

def benchmark_operation(label, command, iterations, message=None):
    times = []

    for i in range(iterations):
        start = time.perf_counter()
        if command == "SIGN":
            send_message_for_signature_noverify(message)
            print(f"Sign Benchmark: {i+1} / {iterations}")
        else:
            send_command(command)
            print(f"KeyGen Benchmark: {i+1} / {iterations}")
        end = time.perf_counter()
        elapsed = (end - start) * 1000  # ms
        times.append(elapsed)
        time.sleep(0.5)  # waitime for response

    print(f"\n=== ⏱️ Benchmark-Ergebnisse für {label} ({iterations} Durchläufe) ===")
    print(f"Min. Zeit        : {min(times):.3f} ms")
    print(f"Max. Zeit        : {max(times):.3f} ms")
    print(f"Durchschnitt     : {statistics.mean(times):.3f} ms")
    print(f"Median           : {statistics.median(times):.3f} ms")
    print(f"Standardabweichung: {statistics.stdev(times):.3f} ms")

    # CSV-Export 
    export_results_to_csv("benchmark_ergebnisse.csv", label, times)
    return times

def export_results_to_csv(filename, test_label, values):
    """
    Exportiert Benchmark-Ergebnisse in eine CSV-Datei.
    Fügt Zeitstempel, Testnamen und Messwerte hinzu.
    """
    with open(filename, "a", newline="") as csvfile: 
        writer = csv.writer(csvfile)
        
        # Kopfzeile nur bei leerer Datei hinzufügen
        if csvfile.tell() == 0:
            writer.writerow(["Zeitstempel", "Test", "Durchlauf", "Laufzeit (ms)"])
        
        timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        for i, val in enumerate(values, 1):
            writer.writerow([timestamp, test_label, i, f"{val:.3f}"])

def run_performance_analysis():
    iterations = 1000
    benchmark_operation("ECC Key Generation", "GENKEY", iterations)
    benchmark_operation("ECDSA Signatur", "SIGN", iterations, message="TestString123")

# ========================== Main Interactive Menu ==========================
if __name__ == '__main__':
    MENU = {
        "1": "GENKEY",
        "2": "SENDPUB",
        "3": "SIGN",
        "4": "EXIT",
        "5": "USEKEY 0",
        "6": "USEKEY 1",
        "7": "USEKEY 2",
        "8": "DELKEYS",
        "9": "KEYINFO",
        "10": "GETLOGS",
        "11": "CLEARLOGS",
    }   

    send_rtc_time()  # set time at startup

    while True:
        print("\n🔹 Wähle eine Option:")
        print("  1 - GENKEY    (Schlüssel generieren)")
        print("  2 - SENDPUB   (Public Key senden)")
        print("  3 - SIGN      (Nachricht signieren)")
        print("  4 - EXIT      (Beenden)")
        print("  5 - USEKEY 0  (Key 0 verwenden)")
        print("  6 - USEKEY 1  (Key 1 verwenden)")
        print("  7 - USEKEY 2  (Key 2 verwenden)")
        print("  8 - DELKEYS   (Alle Schlüssel löschen)")
        print("  9 - KEYINFO   (Public Key Hex Werte zeigen)")
        print(" 10 - GETLOGS   (Audit-Log speichern)")
        print(" 11 - CLEARLOGS (Audit-Log löschen)")


        ser.reset_input_buffer()

        choice = input("> ").strip().upper()
        command = MENU.get(choice, choice)  
        
        if command == "EXIT":
            print("🔌 Closing connection...")
            ser.close()
            break
        elif command == "SIGN":
            message = input("📝 Enter the message to sign: ")
            send_message_for_signature(message)
        elif command == "SENDPUB":
            received_public_key_bytes = receive_public_key()
            if received_public_key_bytes is not None:
                stm32_public_key = reconstruct_pub_key(received_public_key_bytes)
            else:
                print("❌ Kein gültiger Public Key empfangen.")
        elif command == "GETLOGS":
            get_flash_logs()
        elif command == "SETRTC":
            send_rtc_time()
        elif command == "PERFTEST":
            run_performance_analysis()

        else:
            send_command(command)
