#ifndef BROADCAST_ATTACK_H
#define BROADCAST_ATTACK_H

#include <Arduino.h>
#include <vector>
#include "ssid_database.h"

// Broadcast attack configuration
struct BroadcastConfig {
    bool enableBroadcast = false;
    uint32_t broadcastInterval = 300;    // ms between broadcasts
    uint16_t batchSize = 100;            // SSIDs per batch
    bool rotateChannels = true;          // Auto-rotate channels
    uint32_t channelHopInterval = 5000;  // ms between channel hops
    bool respondToProbes = true;         // Launch attacks on probe responses
    uint8_t maxActiveAttacks = 3;        // Max simultaneous attacks
    bool prioritizeResponses = true;     // Focus on SSIDs that get responses
};

// Broadcast statistics
struct BroadcastStats {
    size_t totalBroadcasts = 0;
    size_t totalResponses = 0;
    size_t successfulAttacks = 0;
    std::map<String, size_t> ssidResponseCount;
    unsigned long startTime = 0;
    unsigned long lastResponseTime = 0;
};

class ActiveBroadcastAttack {
private:
    BroadcastConfig config;
    BroadcastStats stats;
    
    size_t currentIndex;
    size_t batchStart;
    unsigned long lastBroadcastTime;
    unsigned long lastChannelHopTime;
    bool isActive;
    uint8_t currentChannel;
    
    std::vector<String> currentBatch;
    std::vector<String> highPrioritySSIDs;
    
public:
    ActiveBroadcastAttack();
    
    // Control methods
    void start();
    void stop();
    void restart();
    bool isActive() const;
    
    // Configuration
    void setConfig(const BroadcastConfig &newConfig);
    BroadcastConfig getConfig() const;
    void setBroadcastInterval(uint32_t interval);
    void setBatchSize(uint16_t size);
    void setChannel(uint8_t channel);
    
    // Operation
    void update();
    void processProbeResponse(const String &ssid, const String &mac);
    
    // Statistics
    BroadcastStats getStats() const;
    size_t getTotalSSIDs() const;
    size_t getCurrentPosition() const;
    float getProgressPercent() const;
    std::vector<std::pair<String, size_t>> getTopResponses(size_t count = 10) const;
    
    // SSID management
    void addHighPrioritySSID(const String &ssid);
    void clearHighPrioritySSIDs();
    
private:
    void loadNextBatch();
    void broadcastSSID(const String &ssid);
    void rotateChannel();
    void sendBeaconFrame(const String &ssid, uint8_t channel);
    void recordResponse(const String &ssid);
    void launchAttackForResponse(const String &ssid, const String &mac);
};

// Global instance (defined in broadcast_attack.cpp)
extern ActiveBroadcastAttack broadcastAttack;

#endif // BROADCAST_ATTACK_H