ABOUT BLE SUITE:

The system is basically a Swiss Army knife for BLE security testing - recon, exploitation, and post-exploitation all in one. It's designed to be both automated (for quick testing) and manual (for targeted attacks).

Core Managers

· BLEAttackManager - Handles BLE setup/cleanup, device connections, and profiling
· ScannerData - Stores found devices during scans, handles deduplication

Connection Attacks

· Multiple Connection Strategies - Normal, aggressive, and exploit-based BLE connections
· HIDExploitEngine - Forces HID connections with various OS-specific attacks:
  · Apple Magic Keyboard spoofing
  · Windows HID bypass
  · Android "Just Works" pairing
  · Boot protocol injection
  · Rapid state confusion attacks

Specific Exploits

· WhisperPairExploit - FastPair buffer overflow attacks:
  · Protocol state confusion
  · Crypto overflow attacks
  · Handshake manipulation

HID Attacks

· HIDDuckyService - DuckyScript injection for keystroke injection
· HIDAttackServiceClass - Basic HID keystroke injection (Enter, Windows key, etc.)
· DuckyScriptEngine - Parses and executes DuckyScript payloads

Audio Attacks

· AudioAttackService - Targets AVRCP/media services:
  · Play/volume control hijacking
  · Audio stack crashing
  · Telephony alert injection

Auth & Pairing Attacks

· AuthBypassEngine - Authentication bypass attempts:
  · Address spoofing (pretending to be paired device)
  · Zero-key auth bypass
  · Legacy pairing attacks
· PairingAttackServiceClass - PIN brute force (tries common PINs like 0000, 1234)

DoS & Jamming

· MultiConnectionAttack - Connection flooding and advertising spam
· DoSAttackServiceClass - Simple DoS attacks
· NRF24 Jammer Integration - BLE frequency jamming (requires NRF24 module)

Recon & Scanning

· VulnerabilityScanner - Comprehensive device vulnerability testing
· Device profiling - Service enumeration and characteristic analysis
· Live BLE scanning - Active/passive scanning with filtering

UI & Menu System

· Interactive menus - Scrollable target selection
· Attack progress display - Real-time status updates
· Script selection system - Built-in examples + SD card loading
· Confirmation prompts - Safety checks before attacks

Key Features

· Multi-OS targeting - Different attacks for Apple, Windows, Android, Linux, IoT
· Persistent scanning - Device database with RSSI/sorting
· SD card support - Load DuckyScripts from files
· Exploit chaining - Try multiple attack methods automatically
· Result reporting - Success/failure feedback with details

Built-in Payloads

· Calculator/CMD/Terminal opening
· WiFi credential extraction
· Reverse shell execution
· Rickroll prank
· Custom script support


Main Menu Items (21 Attacks)

1. FastPair Buffer Overflow

· Targets Google FastPair devices with buffer overflow exploits
· Can cause crashes or memory corruption

2. Advanced Protocol Attack

· Submenu with 4 options:
  · Protocol State Confusion
  · Crypto Overflow
  · Handshake Only
  · All Attacks (full suite)

3. Audio Stack Crash

· Crashes target's audio services
· Sends malformed packets to AVRCP services

4. Media Control Hijack

· Takes over music/video playback controls
· Play/pause/volume injection

5. HID Keystroke Injection

· Basic keyboard keystroke injection
· Enter key, Windows key, etc.

6. Ducky Script Injection

· Full DuckyScript execution via HID
· Submenu with example scripts:
  · Open Calculator
  · Open CMD/Terminal
  · WiFi Credentials
  · Reverse Shell
  · Rickroll
  · Load from SD Card

7. PIN Brute Force

· Tries common BLE PINs (0000, 1234, etc.)
· Tests weak authentication

8. Connection Flood DoS

· Rapid connection attempts to overwhelm target
· Basic denial of service

9. Advertising Spam

· Floods area with BLE advertisements
· Can disrupt nearby BLE devices

10. Quick Test (silent)

· Fast, quiet vulnerability check
· No UI output during test

11. Device Profiling

· Comprehensive service enumeration
· Lists all services and characteristics
· Shows which are writable

12. Test Write Access

· Checks all characteristics for write permissions
· Identifies potential attack surfaces

13. Protocol Fuzzer

· Sends random/malformed data to BLE services
· Tests parsing vulnerabilities

14. Jam & Connect Attack

· Uses NRF24 module to jam BLE while connecting
· Increases exploit success rate

15. Test HID Services

· Scans for HID keyboard/mouse services
· Identifies potential HID injection targets

16. Audio Control Test

· Submenu with 4 audio tests:
  · Test AVRCP Service
  · Test Media Control
  · Test Telephony
  · Test All Audio

17. Vulnerability Scan

· Comprehensive security assessment
· Tests multiple vulnerability categories
· Generates risk report

18. Force HID Injection

· Aggressive HID connection + DuckyScript
· Bypasses pairing requirements

19. HID Connection Exploit

· Tests OS-specific HID connection methods
· Shows which bypasses work

20. Advanced Ducky Injection

· Enhanced script injection menu
· Pre-built complex payloads
· Multi-stage attacks

21. HID Vulnerability Test

· Basic HID service detection
· Checks if keystroke injection is possible

Submenu Systems

· Script Selection - Pick from examples or load from SD
· Audio Tests - Individual audio service testing
· Advanced Attacks - Protocol-specific exploit selection
· Target Selection - Scrollable device picker with RSSI/sorting

Workflow

1. Scan → Find BLE devices
2. Select → Choose target from list
3. Profile → Optional reconnaissance
4. Attack → Pick appropriate exploit
5. Execute → Run attack with progress display
6. Report → View success/failure results

Each menu item targets specific BLE vulnerabilities or attack vectors, with increasing complexity from basic (keystroke injection) to advanced (protocol exploitation).