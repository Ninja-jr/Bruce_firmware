BLE Security Suite Module

⚠️ DISCLAIMER

For authorized testing and educational purposes only. Success varies by target device, firmware, and patch level. Modern/patched devices will resist most attacks.

About

BLE Suite is a comprehensive Bluetooth Low Energy security testing framework for ESP32 devices running Bruce firmware. Provides reconnaissance, protocol exploitation, and post-exploitation capabilities.

Hardware Integration

· NRF24L01+ - BLE frequency jamming (jamming modes, jam & connect attacks)
· FastPair Crypto - mbedTLS-based cryptographic operations (ECDH, AES-CCM)

Core Components

BLEStateManager

Handles BLE stack lifecycle, client tracking, and cleanup.

ScannerData

Stores discovered devices with service detection:

· HFP detection (UUIDs 111E/111F)
· FastPair detection (UUID FE2C)
· Audio/HID service flags

Attack Engines

NimbleExploitEngine

· CVE-2024-47248 - Mesh buffer overflow
· CVE-2024-47249 - HCI OOB

A2DPAttackEngine

· Protocol-level AVDTP attacks (discovery, codec, stream)

HIDExploitEngine

· OS-specific attacks (Apple spoof, Windows bypass, Android JustWorks)
· Connection parameter manipulation
· Service discovery hijacking

WhisperPairExploit

· FastPair cryptographic handshake simulation
· Protocol state confusion
· Crypto overflow attacks

AudioAttackService

· AVRCP media control hijacking
· Audio stack crashing
· Telephony alert injection

FastPairExploitEngine

· Device scanning with model identification
· Memory corruption attempts
· Popup spam (Regular/Fun/Prank)
· Vulnerability testing

AuthBypassEngine

· Address spoofing
· Zero-key auth attempts
· Legacy pairing force

MultiConnectionAttack

· Connection flooding
· Advertising spam
· NRF24 jamming coordination

Attack Menu (11 Main Items)

Reconnaissance

1. Quick Vulnerability Scan - HFP + FastPair testing
2. Deep Device Profiling - Full service enumeration

Protocol Suites

1. FastPair Suite - 6 options (test, memory corruption, state confusion, crypto overflow, popup spam, all)
2. HFP Suite - 4 options (CVE-2025-36911 test, connection, full chain, HID pivot)
3. Audio Suite - 5 options (AVRCP, A2DP discovery, codec overflow, stack crash, all)
4. HID Suite - 6 options (vulnerability test, force connection, keystrokes, DuckyScript, OS exploits, all)

Advanced Attacks

1. Memory Corruption Suite - 5 options (FastPair crypto/state, NimBLE mesh/HCI, all)
2. DoS Attacks - 4 options (flood, spam, jam & connect, fuzzer)
3. Payload Delivery - 3 options (DuckyScript, PIN brute force, auth bypass)
4. Testing Tools - 4 options (write access, audio control, fuzzer, HID test)

Chain Attacks

1. Universal Attack Chain - Attempts HFP → HID → FastPair sequentially

Smart Features

· Auto-detection of HFP/FastPair services during scan
· Context-aware attack suggestions
· Seamless pivot chains (HFP→HID, FastPair→HID)
· Device model identification for FastPair

Dependencies

· NimBLE-Arduino 2.3.7
· mbedTLS (ECDH, AES-CCM)
· TFT_eSPI
· SD card support

Flow

Welcome screen (once per session) → Main menu → Select attack → Scan for targets → Execute → Return to menu