import json
import os
from pycardano import PaymentSigningKey

INPUT_FILE = "wallets.json"
OUTPUT_DIR = "skeys"
os.makedirs(OUTPUT_DIR, exist_ok=True)

# Load the wallet list
with open(INPUT_FILE, "r") as f:
    wallets = json.load(f)

# Export signing keys
for wallet in wallets:
    wid = wallet["id"]
    sk_hex = wallet["signing_key"]

    # Rebuild key from raw bytes
    sk = PaymentSigningKey.from_primitive(bytes.fromhex(sk_hex))

    # Export in proper cardano-cli format
    sk_file = os.path.join(OUTPUT_DIR, f"wallet_{wid}.skey")
    with open(sk_file, "w") as fsk:
        fsk.write(sk.to_json())

    print(f"✅ Exported {sk_file}")

print(f"\n🎉 Done! {len(wallets)} signing keys saved in '{OUTPUT_DIR}/'")
