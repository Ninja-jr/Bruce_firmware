BLE Security Suite Module

⚠️ IMPORTANT DISCLAIMER

Attack success depends entirely on target device configuration and patch level.

This tool implements known attack vectors and proof-of-concept exploits for educational and authorized testing purposes. Results will vary:

· Older/Unpatched Devices - Higher success rate for buffer overflows, FastPair exploits
· Modern/Patched Devices - May resist many attacks due to security updates
· Enterprise/Managed Devices - Often have additional security hardening
· Manufacturer Variations - Different implementations of BLE standards affect vulnerability

No exploit is guaranteed to work. The suite attempts multiple approaches, but:

· Many CVEs have been patched in recent firmware updates
· Device manufacturers implement BLE security differently
· Some attacks only work on specific OS versions/configurations

Use this tool to understand attack surfaces, not as a "hack everything" solution.

About BLE Suite

The system is basically a Swiss Army knife for BLE security testing - recon, exploitation, and post-exploitation all in one. It's designed to be both automated (for quick testing) and manual (for targeted attacks).

Part of the Bruce firmware for ESP32 devices. This module provides comprehensive Bluetooth Low Energy security testing capabilities with hardware integration and multi-stage attack chains.

Realistic Expectations

Success rates vary by:

· Device Age - Older devices ≈ higher vulnerability
· Manufacturer - Some have better/worse BLE implementations
· OS Version - Major security patches in recent updates
· Configuration - Enterprise vs consumer settings
· Usage State - Already-paired vs unpaired devices

Typical scenarios:

· ✅ Testing lab devices - Good for understanding vulnerabilities
· ✅ Legacy IoT devices - Often vulnerable to basic attacks
· ⚠️ Modern smartphones - Many protections in place
· ❌ Enterprise laptops - Usually well-hardened

Hardware Integration

NRF24 Module Support:

· Jam & Connect Attack - Uses modules/NRF24/nrf_jammer_api.cpp for BLE frequency jamming
· Three jamming modes:
· Advertising channel jamming
· Hopping advertisement jamming
· Full BLE channel hopping
· Requires: NRF24L01+ module connected to ESP32
· Purpose: Disrupts target BLE while attempting connection, increasing exploit success rate

FastPair Crypto Engine:

· Crypto Operations - Uses fastpair_crypto.cpp for Google FastPair cryptographic attacks
· Handshake Operations:
· Key pair generation
· ECDH shared secret computation
· Nonce generation
· Protocol message encryption/decryption
· Purpose: Enables realistic FastPair handshake simulation for protocol-level attacks

Module Dependencies

Internal Bruce Modules:

· modules/NRF24/nrf_jammer_api - For BLE jamming capabilities
· fastpair_crypto - For cryptographic operations in FastPair attacks
· HFP_Exploit - For Hands-free Profile vulnerability testing
· core/display.h - Bruce's display system
· core/mykeyboard.h - Bruce's menu patterns
· core/utils.h - Utility functions
· globals.h - Configuration system

External Libraries:

· NimBLE-Arduino - BLE stack implementation
· TFT_eSPI - Display rendering
· SD - Filesystem for script storage

Core Components

BLEAttackManager - Handles BLE setup/cleanup, device connections, and profiling
ScannerData - Stores found devices during scans, handles deduplication with HFP detection
HFPExploitEngine - Tests and exploits Hands-free Profile vulnerabilities including CVE-2025-36911
FastPairExploitEngine - FastPair-specific scanning, exploitation, and popup spam capabilities

Attack Capabilities

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
· FastPairExploitEngine - Comprehensive FastPair exploitation:
· Device-specific targeting (Samsung, Google, Sony, etc.)
· Memory corruption attacks
· Popup spam categories (Regular, Fun, Prank)
· Crypto overflow testing
· Device scanning with model identification

HFP (Hands-free Profile) Attacks

· HFPExploitEngine - Tests and exploits CVE-2025-36911 vulnerabilities:
· HFP service detection (UUIDs 0x111E, 0x111F)
· Unauthorized pairing attempts
· Microphone access vulnerability testing
· Automatic pivot to HID attacks

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
· HFP service detection - Identifies devices with Hands-free Profile
· FastPair device scanning - Dedicated FastPair service discovery (UUID FE2C)

UI & Menu System

· Interactive menus - Scrollable target selection
· Attack progress display - Real-time status updates
· Script selection system - Built-in examples + SD card loading
· Confirmation prompts - Safety checks before attacks
· Smart suggestions - Recommends HFP pivot when device has HFP service

Key Features

· Multi-OS targeting - Different attacks for Apple, Windows, Android, Linux, IoT
· Persistent scanning - Device database with RSSI/sorting
· SD card support - Load DuckyScripts from files
· Exploit chaining - Try multiple attack methods automatically
· Result reporting - Success/failure feedback with details
· Hardware Integration - NRF24 jamming + BLE exploit coordination
· Multi-Stage Attacks - Jamming → Connection → Exploitation workflow
· HFP vulnerability testing - CVE-2025-36911 detection and exploitation
· Smart attack chaining - Auto-suggests HFP pivot for HFP-enabled devices
· Integrated attack pipelines - HFP → HID → DuckyScript automatic chains
· FastPair popup spam - Different categories (Regular devices, Fun popups, Prank alerts)
· Device model database - Organized by manufacturer for targeted attacks

Advanced Attack Chains

Jam & Connect Exploit:

Jamming Phase - Activates NRF24 to jam BLE frequencies
Connection Phase - Attempts aggressive connection during jamming window
Exploitation Phase - Executes selected exploit on connected target
Cleanup - Stops jamming, closes connection
FastPair Crypto Attack:

Handshake - Performs real cryptographic handshake using fastpair_crypto.cpp
State Analysis - Determines device's security posture
Exploit Selection - Chooses appropriate attack (buffer overflow, state confusion, crypto overflow)
Execution - Sends crafted packets targeting specific vulnerabilities
FastPair → HID Chain Attack:

FastPair Exploitation - Executes FastPair protocol attack
HID Pivot - Uses successful FastPair connection to access HID services
Payload Delivery - Executes keystroke injection or DuckyScript
OS-Specific Targeting - Device-specific attacks based on model detection
HFP → HID Pivot Attack:

HFP Vulnerability Test - Checks for CVE-2025-36911
HFP Connection - Establishes Hands-free Profile connection via exploit
HID Discovery - Locates HID services from privileged position
DuckyScript Injection - Executes payload via HID channel
OS-Specific Payloads - Auto-selects Windows/Apple/Android scripts
Smart HID Injection:

Device Analysis - Checks for HFP and FastPair service availability
User Prompt - Suggests appropriate pivot based on available services
Attack Selection - User chooses direct HID or service-pivot approach
Execution - Runs chosen attack chain with appropriate payload
Attack Methodology

The suite implements adaptive attack strategies that respond to target behavior:

Reconnaissance Phase
· Active/passive scanning with device fingerprinting
· RSSI-based proximity estimation
· Service/characteristic enumeration
· HFP service detection - Identifies microphone-capable devices
· FastPair service detection - Scans for Google FastPair (UUID FE2C)

Connection Establishment
Multiple fallback strategies:

· Normal BLE connection
· Aggressive timing parameters
· Exploit-based connection (disabled security)
· Jamming-assisted connection (with NRF24)
· HFP vulnerability exploitation - CVE-2025-36911 bypass
· FastPair protocol exploitation

Vulnerability Assessment
· FastPair buffer overflow testing
· HID service write access verification
· Authentication bypass attempts
· PIN strength testing
· HFP vulnerability testing - CVE-2025-36911 check
· FastPair vulnerability scanning - Systematic test suite

Exploit Execution
· Protocol-specific payload delivery
· State confusion attacks
· Cryptographic manipulation
· Persistent injection (DuckyScript)
· HFP pivot attacks - Privileged escalation via audio profile
· FastPair popup spam - Notification flooding attacks

Cleanup & Reporting
· Graceful disconnection
· BLE stack reinitialization
· Success/failure logging
· Detailed result display

Built-in Payloads

· Calculator/CMD/Terminal opening
· WiFi credential extraction
· Reverse shell execution
· Rickroll prank
· Custom script support
· OS-specific payloads - Auto-selected based on device detection
· FastPair popup models - Device-specific advertisements

Main Menu Items (35 Attacks)

FastPair Buffer Overflow
· Targets Google FastPair devices with buffer overflow exploits
· Can cause crashes or memory corruption

Advanced Protocol Attack
· Submenu with 4 options:
· Protocol State Confusion
· Crypto Overflow
· Handshake Only
· All Attacks (full suite)

Audio Stack Crash
· Crashes target's audio services
· Sends malformed packets to AVRCP services

Media Control Hijack
· Takes over music/video playback controls
· Play/pause/volume injection

HID Keystroke Injection
· Basic keyboard keystroke injection
· Enter key, Windows key, etc.
· Enhanced: Suggests HFP pivot for HFP-enabled devices

Ducky Script Injection
· Full DuckyScript execution via HID
· Submenu with example scripts:
· Open Calculator
· Open CMD/Terminal
· WiFi Credentials
· Reverse Shell
· Rickroll
· Load from SD Card
· Enhanced: Smart HFP pivot suggestions

PIN Brute Force
· Tries common BLE PINs (0000, 1234, etc.)
· Tests weak authentication

Connection Flood DoS
· Rapid connection attempts to overwhelm target
· Basic denial of service

Advertising Spam
· Floods area with BLE advertisements
· Can disrupt nearby BLE devices

Quick Test (silent)
· Fast, quiet vulnerability check
· No UI output during test

Device Profiling
· Comprehensive service enumeration
· Lists all services and characteristics
· Shows which are writable
· New: Includes HFP service detection

Test Write Access
· Checks all characteristics for write permissions
· Identifies potential attack surfaces

Protocol Fuzzer
· Sends random/malformed data to BLE services
· Tests parsing vulnerabilities

Jam & Connect Attack
· Uses NRF24 module to jam BLE while connecting
· Increases exploit success rate

Test HID Services
· Scans for HID keyboard/mouse services
· Identifies potential HID injection targets

Audio Control Test
· Submenu with 4 audio tests:
· Test AVRCP Service
· Test Media Control
· Test Telephony
· Test All Audio

Vulnerability Scan
· Comprehensive security assessment
· Tests multiple vulnerability categories
· Generates risk report
· New: Includes HFP vulnerability testing

Force HID Injection
· Aggressive HID connection + DuckyScript
· Bypasses pairing requirements
· Enhanced: Can use HFP as entry vector

HID Connection Exploit
· Tests OS-specific HID connection methods
· Shows which bypasses work
· Enhanced: HFP bypass integration

Advanced Ducky Injection
· Enhanced script injection menu
· Pre-built complex payloads
· Multi-stage attacks

HID Vulnerability Test
· Basic HID service detection
· Checks if keystroke injection is possible

HFP Vulnerability Test
· Tests for CVE-2025-36911 vulnerability
· Checks HFP service accessibility
· Reports potential microphone access risks

HFP Attack Chain
· Full HFP exploitation pipeline
· Tests vulnerability → establishes connection
· Demonstrates HFP access capability

HFP → HID Pivot Attack
· Complete attack chain:

Tests CVE-2025-36911
Establishes HFP connection via exploit
Automatically pivots to HID services
Executes DuckyScript payload
Uses OS-specific scripts (Windows CMD, Apple Calculator, etc.)
· One-click multi-stage attack

FastPair Device Scanner
· Dedicated FastPair device discovery
· Identifies device models (Samsung, Google, Sony, etc.)
· Shows manufacturer and device type

FastPair Vulnerability Test
· Systematic FastPair security assessment
· Tests service discovery, characteristic access, buffer overflows
· Generates comprehensive vulnerability report

FastPair Memory Corruption
· Targets FastPair protocol with memory corruption attacks
· Sends oversized packets to trigger buffer overflows

FastPair State Confusion
· Attempts to confuse FastPair protocol state machine
· Invalid state transitions and rapid connection attempts

FastPair Crypto Overflow
· Cryptographic overflow attacks on FastPair
· Malformed key exchanges and handshake faults

FastPair Popup Spam (Regular)
· Sends regular FastPair device advertisements
· Uses real device models (Galaxy Buds, Pixel Buds, etc.)

FastPair Popup Spam (Fun)
· Sends entertaining FastPair popups
· Tesla vehicle notifications
· Novelty device advertisements

FastPair Popup Spam (Prank)
· Sends prank FastPair popups
· FBI surveillance alerts
· Government/authority notifications

FastPair All Exploits
· Executes complete FastPair attack suite
· Memory corruption, state confusion, crypto overflow, rapid connection
· Comprehensive testing in one operation

FastPair → HID Chain Attack
· FastPair exploitation followed by HID pivot
· Uses successful FastPair connection to access HID services
· Delivers keystroke injection or DuckyScript payloads

Smart Integration Features

Auto-Suggestion System

When selecting HID/Ducky attacks on HFP-enabled devices:

· Detects HFP service in scanned devices
· Prompts user with HFP pivot suggestion
· Smart defaults - Recommends best approach based on device
· Seamless integration - Works with existing attack functions

Enhanced Existing Attacks

The following attacks now include HFP pivot suggestions:

· HID Keystroke Injection - Suggests HFP pivot when available
· Ducky Script Injection - Offers HFP → DuckyScript chain
· Force HID Injection - Can use HFP as entry vector
· HID Connection Exploit - Enhanced with HFP bypass options

Context-Aware Payloads

· Windows devices - Auto-selects CMD/PS scripts
· Apple devices - Uses GUI/Calculator payloads
· Android/Linux - Generic terminal commands
· HFP-enabled - Prioritizes stealthy audio-based entry
· FastPair devices - Device-specific targeting based on model ID

Submenu Systems

· Script Selection - Pick from examples or load from SD
· Audio Tests - Individual audio service testing
· Advanced Attacks - Protocol-specific exploit selection
· Target Selection - Scrollable device picker with RSSI/sorting
· HFP Integration - Smart suggestions for HFP-enabled targets
· FastPair Popup Types - Regular, Fun, and Prank categories

Workflow

Scan → Find BLE devices (now detects HFP and FastPair services)
Select → Choose target from list (HFP/FastPair devices marked)
Profile → Optional reconnaissance (includes HFP/FastPair detection)
Attack → Pick appropriate exploit (HFP/FastPair attacks available)
Execute → Run attack with progress display (smart chains for HFP/FastPair)
Report → View success/failure results
Public Interfaces

· BleSuiteMenu() - Main entry point
· showAttackMenuWithTarget() - Direct attack menu
· runHFPHIDPivotAttack() - Complete HFP → HID chain
· runFastPairScan() - FastPair device discovery
· runFastPairPopupSpam() - FastPair advertisement attacks
· Scanner data accessible via scannerData global (includes HFP/FastPair detection)

Tested Configurations (Examples)

Note: Your mileage WILL vary. These are examples, not guarantees.

Vulnerable to FastPair attacks:

· Some older Android phones (pre-2020)
· Certain Bluetooth speakers/headsets
· Early IoT devices with FastPair support
· Samsung Galaxy Buds (older models)
· Google Pixel Buds (first generation)

Susceptible to HID injection:

· Unpatched Windows 10 machines
· Some Linux distributions with default settings
· Older smart TVs/streaming devices

Potential HFP vulnerabilities (CVE-2025-36911):

· Bluetooth headsets with microphone support
· Car audio systems with hands-free calling
· Conference room speakers with voice capability
· Note: Requires specific firmware versions

Resistant to most attacks:

· iOS devices after version 14+
· Modern Android (12+ with security updates)
· Enterprise Windows 11 systems
· Recent macOS versions
· HFP-patched devices - Updated against CVE-2025-36911
· FastPair-patched devices - Updated Google security patches

Recent Additions (v2.0+)

HFP Exploitation Module

· CVE-2025-36911 testing - Latest Bluetooth vulnerability
· Hands-free Profile detection - Identifies microphone-capable devices
· Smart pivot system - Auto-suggests HFP → HID attack chains
· Integrated with existing attacks - Enhances HID/DuckyScript success rates

FastPair Integration Module

· Comprehensive FastPair attack suite - 10 new attack options
· Device model database - Organized by manufacturer (Samsung, Google, Sony, etc.)
· Popup spam categories - Regular, Fun, and Prank advertisement types
· Vulnerability testing - Systematic FastPair security assessment
· Chain attacks - FastPair → HID pivot capabilities

Enhanced User Experience

· Context-aware suggestions - Recommends best attack approach
· Seamless integration - HFP/FastPair detection in scanning phase
· One-click attack chains - HFP/FastPair → HID → DuckyScript automation
· Improved device profiling - HFP/FastPair service identification

Technical Improvements

· Modular architecture - Separate HFP_Exploit and FastPair modules
· Clean integration - Minimal changes to existing code
· Backward compatibility - All existing features preserved
· Professional tooling - Multi-stage attack pipelines

Each menu item targets specific BLE vulnerabilities or attack vectors, with increasing complexity from basic (keystroke injection) to advanced (HFP/FastPair protocol exploitation). The system adapts to target responses, employs multiple strategies, and now includes smart suggestions for HFP/FastPair-enabled devices to maximize effectiveness in authorized testing scenarios.
