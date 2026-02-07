#ifndef KARMA_ATTACK_H
#define KARMA_ATTACK_H

#include <Arduino.h>
#include <vector>
#include <map>
#include <queue>

// Attack tiers for prioritization
enum AttackTier {
    TIER_NONE = 0,
    TIER_FAST = 1,     // Quick opportunistic attacks
    TIER_MEDIUM = 2,   // Standard priority targets
    TIER_HIGH = 3,     // High-value targets
    TIER_CLONE = 4     // Clone network attacks
};

// RSN/WPA2/WPA3 information for encryption mimicry
typedef struct {
    uint16_t version;
    uint8_t groupCipher;
    uint8_t pairwiseCipher;
    uint8_t akmSuite; // 0 = none, 1 = WPA2, 2 = WPA3
} RSNInfo;

// Probe request data structure
typedef struct {
    String mac;
    String ssid;
    int rssi;
    unsigned long timestamp;
    uint8_t channel;
    uint8_t encryption_type;
} ProbeRequest;

// Client behavior tracking
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

// Active network for beaconing
typedef struct {
    String ssid;
    uint8_t channel;
    RSNInfo rsn;
    unsigned long lastActivity;
    unsigned long lastBeacon;
} ActiveNetwork;

// Network history tracking
typedef struct {
    String ssid;
    uint32_t responsesSent;
    uint32_t successfulConnections;
    unsigned long lastResponse;
} NetworkHistory;

// Probe response task for queueing
typedef struct {
    String ssid;
    String targetMAC;
    uint8_t channel;
    RSNInfo rsn;
    unsigned long timestamp;
} ProbeResponseTask;

// Portal template structure
typedef struct {
    String name;
    String filename;
    bool isDefault;
    bool verifyPassword;
} PortalTemplate;

// Pending portal attack
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

// Karma configuration
typedef struct {
    bool enableAutoKarma;
    bool enableDeauth;
    bool enableSmartHop;
    bool prioritizeVulnerable;
    bool enableAutoPortal;
    uint16_t maxClients;
} KarmaConfig;

// Attack strategy configuration
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

// Broadcast attack statistics
struct BroadcastStats {
    unsigned long startTime;
    size_t totalBroadcasts;
    size_t totalResponses;
};

// Broadcast attack class
class BroadcastAttack {
public:
    BroadcastAttack();
    bool isActive();
    void start();
    void stop();
    void update();
    void processProbeResponse(const String& ssid, const String& mac);
    float getProgressPercent();
    void setBroadcastInterval(uint16_t interval);
    size_t getCurrentPosition();
    void restart();
    void clearHighPrioritySSIDs();
    
    BroadcastStats getStats();
    std::vector<std::pair<String, size_t>> getTopResponses(size_t count);
    
private:
    bool active;
    uint16_t broadcastInterval;
    unsigned long startTime;
    size_t currentPos;
    size_t totalBroadcasts;
    size_t totalResponses;
    std::map<String, size_t> responseCounts;
};

// SSID Database class
class SSIDDatabase {
public:
    static size_t getCount();
    static std::vector<String> getSSIDs();
    static std::vector<String> getPopularSSIDs(size_t count);
    static bool loadFromFile(FS &fs, const String &filename);
    static void clear();
    static void addSSID(const String &ssid);
    static void setHighPriority(const String &ssid, bool highPriority);
    static bool autoLoad();
    static bool isDatabaseLoaded();
    
private:
    static std::vector<String> ssids;
    static std::vector<String> highPrioritySSIDs;
    static void createDefaultDatabase();
};

// Function prototypes
void karma_setup();
void enhanced_karma_setup();
void clearProbes();
void saveProbesToFile(FS &fs, bool compressed);
void sendProbeResponse(const String &ssid, const String &mac, uint8_t channel);
void sendDeauth(const String &mac, uint8_t channel, bool broadcast);
void launchManualEvilPortal(const String &ssid, uint8_t channel, bool verifyPwd);
void launchTieredEvilPortal(PendingPortal &portal);
std::vector<ProbeRequest> getUniqueProbes();
std::vector<ClientBehavior> getVulnerableClients();

// Enhanced functions
size_t buildEnhancedProbeResponse(uint8_t *buffer, const String &ssid, 
                                 const String &targetMAC, uint8_t channel, 
                                 const RSNInfo &rsn, bool isHidden = false);
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

// External variables
extern std::map<String, ClientBehavior> clientBehaviors;
extern ProbeRequest probeBuffer[1000];
extern uint16_t probeBufferIndex;
extern bool bufferWrapped;
extern KarmaConfig karmaConfig;
extern AttackConfig attackConfig;
extern BroadcastAttack broadcastAttack;

#endif // KARMA_ATTACK_H