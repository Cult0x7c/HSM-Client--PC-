import serial
import time
import hashlib
import datetime
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
        #print(f"🔍 RAW: {repr(line)}")

        # If line is empty: check for timeout
        if not line:
            if time.time() - start_time > 1:
                break
            continue

        # Got something → reset timeout window
        start_time = time.time()

        # Filter junk/system lines
        if (
            not line
            or line.isspace()
            or any(x in line for x in ("\x00", "\x01", "\x1b"))
            or line.startswith("Received:")
            or "Waiting for" in line
        ):
            continue

        # Valid log line
        print("•", line)
        log_lines.append(line)

    # Optional: save to file
    if log_lines:
        filename = f"audit_flash_log_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
        with open(filename, "w") as f:
            for entry in log_lines:
                f.write(entry + "\n")
        print(f"\n✅ Logs saved to: {filename}")
    else:
        print("⚠️ No logs found.")

# ========================== Main Interactive Menu ==========================
if __name__ == '__main__':
    MENU = {
        "1": "GENKEY",
        "2": "SENDPUB",
        "3": "SIGN",
        "4": "HELP",
        "5": "EXIT",
        "6": "USEKEY 0",
        "7": "USEKEY 1",
        "8": "USEKEY 2",
        "9": "DELKEYS",
        "10": "KEYINFO",
        "11": "GETLOGS"
    }   
        
    while True:
        print("\n🔹 Wähle eine Option:")
        print("  1 - GENKEY  (Schlüssel generieren)")
        print("  2 - SENDPUB (Public Key senden)")
        print("  3 - SIGN    (Nachricht signieren)")
        print("  4 - HELP    (Befehlsübersicht)")
        print("  5 - EXIT    (Beenden)")
        print("  6 - USEKEY 0 (Key 0 verwenden)")
        print("  7 - USEKEY 1 (Key 1 verwenden)")
        print("  8 - USEKEY 2 (Key 2 verwenden)")
        print("  9 - DELKEYS (Alle Schlüssel löschen)")
        print(" 10 - KEYINFO (Public Key Hex Werte zeigen)")
        print(" 11 - GETLOGS (Audit-Log speichern)")

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

        else:
            send_command(command)
