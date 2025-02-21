import os
import re
import subprocess
import sys

# Define file paths
CARGO_TOML = "Cargo.toml"
CONFIG_TOML = os.path.join(".cargo", "config.toml")
CHIP_TYPE = "esp32c6"  # Change to "esp32c6" if needed

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

# Extract device type, name, and version from .cargo/config.toml
print("[INFO] Checking .cargo/config.toml file...")
DEVICE_TYPE = extract_value_from_toml(CONFIG_TOML, "ESP_DEVICE_TYPE")
DEVICE_NAME = extract_value_from_toml(CONFIG_TOML, "ESP_DEVICE_NAME")
DEVICE_VERSION = extract_value_from_toml(CONFIG_TOML, "ESP_DEVICE_VERSION")

print(f"[INFO] Extracted ESP_DEVICE_TYPE: {DEVICE_TYPE}")
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

# Create generate_mender_file.sh script
MENDER_SCRIPT = "generate_mender_file.sh"
mender_content = f"""#!/bin/bash

mender-artifact write rootfs-image --compression none --device-type {DEVICE_TYPE} --artifact-name {DEVICE_NAME}-{DEVICE_VERSION} --output-path {DEVICE_NAME}-{DEVICE_VERSION}.mender --file {FIRMWARE_FILE}
"""

with open(MENDER_SCRIPT, "w", encoding="utf-8") as script_file:
    script_file.write(mender_content)

# Make the script executable
os.chmod(MENDER_SCRIPT, 0o755)

print(f"[INFO] {MENDER_SCRIPT} script created successfully.")

# Print the generated command
mender_cmd = f"mender-artifact write rootfs-image --compression none --device-type {DEVICE_TYPE} --artifact-name {DEVICE_NAME}-{DEVICE_VERSION} --output-path {DEVICE_NAME}-{DEVICE_VERSION}.mender --file {FIRMWARE_FILE}"
print("[INFO] Run command to generate mender file:")
print(mender_cmd)
