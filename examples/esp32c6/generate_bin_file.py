import os
import re
import subprocess
import sys

# Define file paths
CARGO_TOML = "Cargo.toml"
CONFIG_TOML = os.path.join(".cargo", "config.toml")
CHIP_TYPE = "esp32c6"

# Determine target directory based on CHIP_TYPE
if CHIP_TYPE == "esp32c3":
    TARGET_DIR = os.path.join("target", "riscv32imc-unknown-none-elf", "release")
elif CHIP_TYPE == "esp32c6":
    TARGET_DIR = os.path.join("target", "riscv32imac-unknown-none-elf", "release")
else:
    print(f"[ERROR] Unsupported CHIP_TYPE: {CHIP_TYPE}")
    sys.exit(1)

def extract_value_from_toml(file_path, key):
    """
    Extracts the value of a given key from a TOML file.
    """
    if not os.path.exists(file_path):
        print(f"[ERROR] {file_path} not found.")
        sys.exit(1)

    with open(file_path, "r", encoding="utf-8") as file:
        for line in file:
            match = re.match(rf'^\s*{key}\s*=\s*"([^"]+)"', line)
            if match:
                return match.group(1)
    
    print(f"[ERROR] Could not extract {key} from {file_path}.")
    sys.exit(1)

# Extract package name from Cargo.toml
print("[INFO] Checking Cargo.toml file...")
PACKAGE_NAME = extract_value_from_toml(CARGO_TOML, "name")
print(f"[INFO] Extracted package name: {PACKAGE_NAME}")

# Extract device name and version from .cargo/config.toml
print("[INFO] Checking .cargo/config.toml file...")
DEVICE_NAME = extract_value_from_toml(CONFIG_TOML, "ESP_DEVICE_NAME")
DEVICE_VERSION = extract_value_from_toml(CONFIG_TOML, "ESP_DEVICE_VERSION")

print(f"[INFO] Extracted ESP_DEVICE_NAME: {DEVICE_NAME}")
print(f"[INFO] Extracted ESP_DEVICE_VERSION: {DEVICE_VERSION}")

# Construct firmware filename
FIRMWARE_FILE = f"{DEVICE_NAME}-{DEVICE_VERSION}.bin"

# Ensure target directory exists
if not os.path.exists(TARGET_DIR):
    print(f"[ERROR] Target directory {TARGET_DIR} does not exist.")
    sys.exit(1)

# Construct and print the final command
ESPFLASH_CMD = f'espflash save-image --chip {CHIP_TYPE} "{os.path.join(TARGET_DIR, PACKAGE_NAME)}" "{FIRMWARE_FILE}"'
print("[INFO] Running command:")
print(ESPFLASH_CMD)

# Execute espflash command
try:
    subprocess.run(ESPFLASH_CMD, shell=True, check=True)
    print("[INFO] Firmware image successfully created.")
except subprocess.CalledProcessError as e:
    print(f"[ERROR] Failed to execute espflash command: {e}")
    sys.exit(1)
