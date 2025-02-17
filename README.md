# 🚀 ESP32 Mender Client in Rust 🦀

A **pure Rust** implementation of the Mender client for the ESP32 platform, designed for secure and reliable over-the-air (OTA) firmware updates. This project combines the performance and safety of Rust with the robustness of [Mender.io](https://mender.io/), bringing modern OTA solutions to embedded IoT devices.

Futher more, we enabling the capability of 
- Updating AI model for edge devices 
- Remote command for edge devices
- Peform updating for other via CAN bus

It is build and test on esp32-c6 for now.
![image](https://github.com/user-attachments/assets/b33603c2-42bd-4634-ac8f-c4ab864c722e)

<img width="1468" alt="image" src="https://github.com/user-attachments/assets/31c2c963-585a-4074-b28d-a693922ed45e" />

---

## 🔥 Key Features

- 🔒 **Secure OTA Updates** – Seamless integration with Mender for secure, encrypted firmware delivery.
- 🔄 **Enabling for Updating AI model at the Edge**
- ⚡ **Remote Command - Remote Control**
- ⚡ **Firmware/Software/AI model update for other components via CAN bus** 
- ⚡ **Lightweight & Efficient** – Optimized for resource-constrained ESP32 devices.  
- 🔄 **Automatic Rollback** – Fail-safe mechanisms for firmware deployment.  
- 🦀 **Powered by Rust** – Memory safety and performance without a garbage collector.  
- 📦 **Modular Design** – Easy to extend and adapt for various embedded projects.

---

## 📁 Project Structure

---

## ⚙️ Getting Started

### Prerequisites

- 📦 **Rust Toolchain** (`rustup`)  
- 🛠 **ESP-IDF for Rust** (`espup`)  
- 🔌 **ESP32 Development Board**  
- 🌐 **Mender Server Account** (Hosted or Open Source)

Configure environment variables:

```shell
MENDER_CLIENT_WIFI_SSID
MENDER_CLIENT_WIFI_PSK
MENDER_CLIENT_URL
MENDER_CLIENT_TENANT_TOKEN (optional)
```
---

### 🚀 Installation & Setup

1. **Install Rust for ESP32**  
   ```bash
   rustup install stable
   cargo install espup
   espup install
   cargo install espflash



2. **Compile and build the project**
   
Try on esp32c3
  ```bash
cd examples/esp32c3
cargo run --release
```

Try on esp32c6
  ```bash
cd examples/esp32c6
cargo run --release
```

# Further Discussioin on Discord
Please join us : https://discord.gg/b7vk6fza

# Demo 
- video demo on esp32c3 : https://youtu.be/N24ugg88bFo
