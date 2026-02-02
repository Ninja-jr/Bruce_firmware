#ifndef BLE_SUITE_H
#define BLE_SUITE_H

#include <NimBLEDevice.h>
#include "fastpair_crypto.h"
#include <WString.h>
#include <vector>
#include <freertos/FreeRTOS.h>
#include <freertos/semphr.h>

#ifndef TFT_WHITE
#define TFT_WHITE 0xFFFF
#endif
#ifndef TFT_BLACK
#define TFT_BLACK 0x0000
#endif
#ifndef TFT_RED
#define TFT_RED 0xF800
#endif
#ifndef TFT_GREEN
#define TFT_GREEN 0x07E0
#endif
#ifndef TFT_BLUE
#define TFT_BLUE 0x001F
#endif
#ifndef TFT_YELLOW
#define TFT_YELLOW 0xFFE0
#endif
#ifndef TFT_CYAN
#define TFT_CYAN 0x07FF
#endif
#ifndef TFT_MAGENTA
#define TFT_MAGENTA 0xF81F
#endif
#ifndef TFT_ORANGE
#define TFT_ORANGE 0xFDA0
#endif
#ifndef TFT_GRAY
#define TFT_GRAY 0x8410
#endif
#ifndef TFT_DARKGREEN
#define TFT_DARKGREEN 0x03E0
#endif

extern volatile int tftWidth;
extern volatile int tftHeight;
class tft_logger;
extern tft_logger tft;
class BruceConfig;
extern BruceConfig bruceConfig;

bool check(int key);

enum {
    BLE_ESC_PRESS = 0,
    BLE_SEL_PRESS = 1,
    BLE_PREV_PRESS = 2,
    BLE_NEXT_PRESS = 3
};

struct CharacteristicInfo {
    String uuid;
    bool canRead;
    bool canWrite;
    bool canNotify;
};

struct DeviceProfile {
    String address;
    bool connected;
    bool hasFastPair;
    bool hasAVRCP;
    bool hasHID;
    bool hasBattery;
    bool hasDeviceInfo;
    std::vector<String> services;
    std::vector<CharacteristicInfo> characteristics;
};

struct HIDDeviceProfile {
    String osType;
    bool supportsBootProtocol;
    bool supportsReportProtocol;
    bool requiresAuthentication;
    bool hasExistingBond;
    uint16_t vendorId;
    uint16_t productId;
    std::vector<String> servicePatterns;
    int connectionBehavior;
    String deviceName;
    int rssi;
    bool isAppleDevice;
    bool isWindowsDevice;
    bool isAndroidDevice;
    bool isLinuxDevice;
    bool isIoTDevice;
    String suggestedAttack;
};

struct HIDConnectionResult {
    bool success;
    String method;
    NimBLEClient* client;
    uint32_t attemptTime;
    int attemptCount;
};

struct DuckyCommand {
    String command;
    String parameter;
    int delay_ms;
};

class BLEAttackManager {
private:
    bool isInAttackMode = false;
    bool wasScanning = false;
public:
    void prepareForConnection();
    void cleanupAfterAttack();
    bool connectToDevice(NimBLEAddress target, NimBLEClient** outClient, bool useExploitHandshake = false);
    DeviceProfile profileDevice(NimBLEAddress target);
};

class HIDExploitEngine {
private:
    HIDDeviceProfile analyzeHIDDevice(NimBLEAddress target, const String& name, int rssi);
    bool tryAppleMagicSpoof(NimBLEAddress target, HIDDeviceProfile profile);
    bool tryWindowsHIDBypass(NimBLEAddress target, HIDDeviceProfile profile);
    bool tryAndroidJustWorks(NimBLEAddress target, HIDDeviceProfile profile);
    bool tryBootProtocolInjection(NimBLEAddress target, HIDDeviceProfile profile);
    bool tryRapidStateConfusion(NimBLEAddress target, HIDDeviceProfile profile);
    bool tryHIDReportPreconnection(NimBLEAddress target, HIDDeviceProfile profile);
    bool tryConnectionParameterAttack(NimBLEAddress target, HIDDeviceProfile profile);
    bool trySecurityModeBypass(NimBLEAddress target, HIDDeviceProfile profile);
    bool tryAddressSpoofingAttack(NimBLEAddress target, HIDDeviceProfile profile);
    bool tryServiceDiscoveryHijack(NimBLEAddress target, HIDDeviceProfile profile);

public:
    HIDConnectionResult forceHIDConnection(NimBLEAddress target, const String& deviceName, int rssi);
    bool executeHIDInjection(NimBLEAddress target, const String& duckyScript);
    bool testHIDVulnerability(NimBLEAddress target);
};

class WhisperPairExploit {
private:
    BLEAttackManager bleManager;
    FastPairCrypto crypto;
    NimBLERemoteCharacteristic* findKBPCharacteristic(NimBLERemoteService* fastpairService);
    bool performRealHandshake(NimBLERemoteCharacteristic* kbpChar, uint8_t* devicePubKey);
    bool sendProtocolAttack(NimBLERemoteCharacteristic* kbpChar, const uint8_t* devicePubKey);
    bool sendStateConfusionAttack(NimBLERemoteCharacteristic* kbpChar);
    bool sendCryptoOverflowAttack(NimBLERemoteCharacteristic* kbpChar);
    bool testForVulnerability(NimBLERemoteCharacteristic* kbpChar);

public:
    bool execute(NimBLEAddress target);
    bool executeSilent(NimBLEAddress target);
    bool executeAdvanced(NimBLEAddress target, int attackType);
};

class AudioAttackService {
public:
    bool findAndAttackAudioServices(NimBLEClient* pClient);
    bool attackAVRCP(NimBLERemoteService* avrcpService);
    bool attackAudioMedia(NimBLERemoteService* mediaService);
    bool attackTelephony(NimBLERemoteService* teleService);
    bool executeAudioAttack(NimBLEAddress target);
    bool injectMediaCommands(NimBLEAddress target);
    bool crashAudioStack(NimBLEAddress target);
};

class DuckyScriptEngine {
public:
    struct HIDKeycode {
        uint8_t modifier;
        uint8_t keycode;
    };
private:
    std::vector<DuckyCommand> commands;
    bool scriptLoaded;
public:
    DuckyScriptEngine();
    HIDKeycode charToKeycode(char c);
    bool parseLine(String line);
    bool loadFromSD(String filename);
    bool loadFromString(String script);
    std::vector<DuckyCommand> getCommands();
    bool isLoaded();
    void clear();
    size_t getCommandCount();
};

class HIDDuckyService {
private:
    DuckyScriptEngine duckyEngine;
    int defaultDelay;
    HIDExploitEngine hidExploit;
    bool sendHIDReport(NimBLERemoteCharacteristic* pChar, uint8_t modifier, uint8_t keycode);
    bool sendString(NimBLERemoteCharacteristic* pChar, const String& str);
    bool sendSpecialKey(NimBLERemoteCharacteristic* pChar, const String& key);
    bool sendComboKey(NimBLERemoteCharacteristic* pChar, const String& combo);
    bool sendGUIKey(NimBLERemoteCharacteristic* pChar, char key);
public:
    HIDDuckyService();
    bool injectDuckyScript(NimBLEAddress target, String script);
    bool injectDuckyScriptFromSD(NimBLEAddress target, String filename);
    bool executeDuckyScript(NimBLEAddress target);
    bool forceInjectDuckyScript(NimBLEAddress target, String script, const String& deviceName, int rssi);
    void setDefaultDelay(int delay_ms);
    size_t getScriptSize();
};

class AuthBypassEngine {
private:
    struct PairedDevice {
        String name;
        String address;
        uint8_t linkKey[16];
        unsigned long bondedAt;
    };
    std::vector<PairedDevice> knownDevices;
public:
    AuthBypassEngine();
    void addKnownDevice(const String& name, const String& address, uint8_t linkKey[16]);
    String getSpoofAddress(const String& targetName);
    bool attemptSpoofConnection(NimBLEAddress target, const String& targetName);
    bool forceRepairing(NimBLEAddress target);
    bool exploitAuthBypass(NimBLEAddress target);
};

class MultiConnectionAttack {
private:
    std::vector<NimBLEClient*> activeConnections;
public:
    MultiConnectionAttack();
    ~MultiConnectionAttack();
    bool connectionFloodSingle(NimBLEAddress target, int timeout);
    bool connectionFlood(std::vector<NimBLEAddress> targets, int attemptsPerTarget = 3);
    bool advertisingSpamSingle(NimBLEAddress target);
    bool advertisingSpam(std::vector<NimBLEAddress> targets);
    bool mitmAttackSingle(NimBLEAddress target);
    bool mitmAttack(std::vector<NimBLEAddress> targets);
    bool nrf24JamAttack(int jamMode = 0);
    bool jamAndConnect(NimBLEAddress target);
    void cleanup();
};

class VulnerabilityScanner {
private:
    struct VulnCheck {
        String name;
        bool (*checkFunction)(NimBLEAddress);
        String description;
    };
    std::vector<VulnCheck> vulnerabilityChecks;
public:
    VulnerabilityScanner();
    void scanDevice(NimBLEAddress target);
    void addCustomCheck(String name, bool (*checkFunc)(NimBLEAddress), String desc);
    void runAllChecks(NimBLEAddress target);
    std::vector<String> getVulnerabilities();
};

class HIDAttackServiceClass {
private:
    HIDExploitEngine hidExploit;
public:
    bool injectKeystrokes(NimBLEAddress target);
    bool forceHIDKeystrokes(NimBLEAddress target, const String& deviceName, int rssi);
};

class PairingAttackServiceClass {
public:
    bool bruteForcePIN(NimBLEAddress target);
};

class DoSAttackServiceClass {
public:
    bool connectionFlood(NimBLEAddress target);
    bool advertisingSpam(NimBLEAddress target);
};

NimBLEClient* attemptConnectionWithStrategies(NimBLEAddress target, String& connectionMethod);
void BleSuiteMenu();
void showAttackMenuWithTarget(NimBLEAddress target);
void executeSelectedAttack(int attackIndex, NimBLEAddress target);
void runWhisperPairAttack(NimBLEAddress target);
void runAdvancedExploit(NimBLEAddress target);
void runAudioStackCrash(NimBLEAddress target);
void runMediaCommandHijack(NimBLEAddress target);
void runHIDInjection(NimBLEAddress target);
void runDuckyScriptAttack(NimBLEAddress target);
void runPINBruteForce(NimBLEAddress target);
void runConnectionFlood(NimBLEAddress target);
void runAdvertisingSpam(NimBLEAddress target);
void runQuickTest(NimBLEAddress target);
void runDeviceProfiling(NimBLEAddress target);
void runWriteAccessTest(NimBLEAddress target);
void runProtocolFuzzer(NimBLEAddress target);
void runJamConnectAttack(NimBLEAddress target);
void runHIDTest(NimBLEAddress target);
void runAudioControlTest(NimBLEAddress target);
void runVulnerabilityScan(NimBLEAddress target);
void runForceHIDInjection(NimBLEAddress target);
void runHIDConnectionExploit(NimBLEAddress target);
void runAdvancedDuckyInjection(NimBLEAddress target);
void runHIDVulnerabilityTest(NimBLEAddress target);
void runMultiTargetAttack();
void executeAudioTest(int testIndex, NimBLEAddress target);
void showAttackProgress(const char* message, uint16_t color = TFT_WHITE);
void showAttackResult(bool success, const char* message = nullptr);
bool confirmAttack(const char* targetName);
String selectTargetFromScan(const char* title);
String selectMultipleTargetsFromScan(const char* title, std::vector<NimBLEAddress>& targets);
String getScriptFromUser();
NimBLEAddress parseAddress(const String& addressInfo);
bool requireSimpleConfirmation(const char* message);
int8_t showAdaptiveMessage(const char* line1, const char* btn1, const char* btn2, const char* btn3, uint16_t color, bool showEscHint = true, bool autoProgress = false);
void showWarningMessage(const char* message);
void showErrorMessage(const char* message);
void showSuccessMessage(const char* message);
void showDeviceInfoScreen(const char* title, const std::vector<String>& lines, uint16_t bgColor, uint16_t textColor);
bool isBLEInitialized();

#endif