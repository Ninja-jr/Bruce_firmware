#ifndef KARMA_ATTACK_H
#define KARMA_ATTACK_H

#include <Arduino.h>
#include <vector>
#include <map>
#include <queue>
#include <FS.h>

enum AttackTier {
    TIER_NONE = 0,
    TIER_FAST = 1,
    TIER_MEDIUM = 2,
    TIER_HIGH = 3,
    TIER_CLONE = 4
};

struct BroadcastConfig {
    bool enableBroadcast = false;
    uint32_t broadcastInterval = 150;
    uint16_t batchSize = 100;
    bool rotateChannels = true;
    uint32_t channelHopInterval = 5000;
    bool respondToProbes = true;
    uint8_t maxActiveAttacks = 3;
    bool prioritizeResponses = true;
};

struct BroadcastStats {
    size_t totalBroadcasts = 0;
    size_t totalResponses = 0;
    size_t successfulAttacks = 0;
    std::map<String, size_t> ssidResponseCount;
    unsigned long startTime = 0;
    unsigned long lastResponseTime = 0;
};

typedef struct {
    uint16_t version;
    uint8_t groupCipher;
    uint8_t pairwiseCipher;
    uint8_t akmSuite;
} RSNInfo;

typedef struct {
    String mac;
    String ssid;
    int rssi;
    unsigned long timestamp;
    uint8_t channel;
    uint8_t frame[128];
    uint16_t frame_len;
} ProbeRequest;

typedef struct {
    String mac;
    unsigned long firstSeen;
    unsigned long lastSeen;
    uint32_t probeCount;
    int avgRSSI;
    std::vector<String> probedSSIDs;
    uint8_t favoriteChannel;
    unsigned long lastKarmaAttempt;
    bool isVulnerable;
} ClientBehavior;

typedef struct {
    String ssid;
    String bssid;
    uint8_t channel;
    RSNInfo rsn;
    unsigned long lastActivity;
    unsigned long lastBeacon;
} ActiveNetwork;

typedef struct {
    String ssid;
    uint32_t responsesSent;
    uint32_t successfulConnections;
    unsigned long lastResponse;
} NetworkHistory;

typedef struct {
    String ssid;
    String targetMAC;
    uint8_t channel;
    RSNInfo rsn;
    unsigned long timestamp;
} ProbeResponseTask;

typedef struct {
    String name;
    String filename;
    bool isDefault;
    bool verifyPassword;
} PortalTemplate;

typedef struct {
    String ssid;
    uint8_t channel;
    String targetMAC;
    unsigned long timestamp;
    bool launched;
    String templateName;
    String templateFile;
    bool isDefaultTemplate;
    bool verifyPassword;
    uint8_t priority;
    AttackTier tier;
    uint16_t duration;
    bool isCloneAttack;
    uint32_t probeCount;
} PendingPortal;

typedef struct {
    bool enableAutoKarma;
    bool enableDeauth;
    bool enableSmartHop;
    bool prioritizeVulnerable;
    bool enableAutoPortal;
    uint16_t maxClients;
} KarmaConfig;

typedef struct {
    AttackTier defaultTier;
    bool enableCloneMode;
    bool enableTieredAttack;
    uint8_t priorityThreshold;
    uint8_t cloneThreshold;
    bool enableBeaconing;
    uint16_t highTierDuration;
    uint16_t mediumTierDuration;
    uint16_t fastTierDuration;
    uint32_t cloneDuration;
    uint8_t maxCloneNetworks;
} AttackConfig;

class ActiveBroadcastAttack {
private:
    BroadcastConfig config;
    BroadcastStats stats;
    size_t currentIndex;
    size_t batchStart;
    unsigned long lastBroadcastTime;
    unsigned long lastChannelHopTime;
    bool _active;
    uint8_t currentChannel;
    size_t totalSSIDsInFile;
    size_t ssidsProcessed;
    uint8_t updateCounter;
    std::vector<String> currentBatch;
    std::vector<String> highPrioritySSIDs;

public:
    ActiveBroadcastAttack();
    void start();
    void stop();
    void restart();
    bool isActive() const;
    void setConfig(const BroadcastConfig &newConfig);
    BroadcastConfig getConfig() const;
    void setBroadcastInterval(uint32_t interval);
    void setBatchSize(uint16_t size);
    void setChannel(uint8_t channel);
    void update();
    void processProbeResponse(const String &ssid, const String &mac);
    BroadcastStats getStats() const;
    size_t getTotalSSIDs() const;
    size_t getCurrentPosition() const;
    String getProgressString() const;
    float getProgressPercent() const;
    std::vector<std::pair<String, size_t>> getTopResponses(size_t count = 10) const;
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

class SSIDDatabase {
private:
    static std::vector<String> ssidCache;
    static bool cacheLoaded;
    static String currentFilename;
    static bool useLittleFS;
    static bool loadFromFile();

public:
    static size_t getCount();
    static String getSSID(size_t index);
    static std::vector<String> getAllSSIDs();
    static int findSSID(const String &ssid);
    static String getRandomSSID();
    static void getBatch(size_t startIndex, size_t count, std::vector<String> &result);
    static bool contains(const String &ssid);
    static size_t getAverageLength();
    static size_t getMaxLength();
    static size_t getMinLength();
    static bool setSourceFile(const String &filename, bool useLittleFS = false);
    static bool reload();
    static void clearCache();
    static bool isLoaded();
    static String getSourceFile();
};

void karma_setup();
void clearProbes();
void saveProbesToFile(FS &fs, bool compressed);
void sendProbeResponse(const String &ssid, const String &mac, uint8_t channel);
void sendDeauth(const String &mac, uint8_t channel, bool broadcast);
void launchManualEvilPortal(const String &ssid, uint8_t channel, bool verifyPwd);
void launchTieredEvilPortal(PendingPortal &portal);
std::vector<ProbeRequest> getUniqueProbes();
std::vector<ClientBehavior> getVulnerableClients();
size_t buildEnhancedProbeResponse(uint8_t *buffer, const String &ssid, 
                                 const String &targetMAC, uint8_t channel, 
                                 const RSNInfo &rsn, bool isHidden);
size_t buildBeaconFrame(uint8_t *buffer, const String &ssid, 
                        uint8_t channel, const RSNInfo &rsn);
void generateRandomBSSID(uint8_t *bssid);
void rotateBSSID();
RSNInfo extractRSNInfo(const uint8_t *frame, int len);
void queueProbeResponse(const ProbeRequest &probe, const RSNInfo &rsn);
void processResponseQueue();
void sendBeaconFrames();
void checkForAssociations();
void saveNetworkHistory(FS &fs);
void sendBeaconFrameHelper(const String &ssid, uint8_t channel);
void saveCredentialsToFile(String ssid, String password);
void saveProbesToPCAP(FS &fs);

extern std::map<String, ClientBehavior> clientBehaviors;
extern ProbeRequest probeBuffer[200];
extern uint16_t probeBufferIndex;
extern bool bufferWrapped;
extern KarmaConfig karmaConfig;
extern AttackConfig attackConfig;
extern ActiveBroadcastAttack broadcastAttack;
extern bool screenNeedsRedraw;
extern uint32_t pmkidCaptured;
extern uint32_t assocBlocked;

#endif