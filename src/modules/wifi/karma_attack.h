#ifndef KARMA_ATTACK_H
#define KARMA_ATTACK_H

#include <Arduino.h>
#include <vector>
#include <set>
#include <map>
#include "FS.h"
#include "esp_wifi_types.h"
#include <freertos/ringbuf.h>

// Forward declaration for FS class
namespace fs {
    class FS;
}

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

// Client behavior tracking
struct ClientBehavior {
    String mac;
    unsigned long firstSeen;
    unsigned long lastSeen;
    uint16_t probeCount;
    int avgRSSI;
    std::vector<String> probedSSIDs;
    uint8_t favoriteChannel;
    unsigned long lastKarmaAttempt;
    bool isVulnerable;
};

// Probe Request Structure
struct ProbeRequest {
    String mac;
    String ssid;
    int rssi;
    unsigned long timestamp;
    uint8_t channel;
    uint8_t encryption_type;
};

// Karma configuration
struct KarmaConfig {
    bool enableAutoKarma = true;
    bool enableDeauth = false;
    bool enableSmartHop = true;
    bool prioritizeVulnerable = true;
    bool enableAutoPortal = false;
    uint16_t maxClients = 100;
};

// Attack configuration
struct AttackConfig {
    AttackTier defaultTier = TIER_HIGH;
    uint32_t cloneDuration = 120000;    // 2 minutes for clone attacks (fixed to uint32_t)
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

//===== FUNCTION DECLARATIONS =====//

// Main sniffer function
void karma_setup();

// Packet processing functions
bool isProbeRequestWithSSID(const wifi_promiscuous_pkt_t *packet);
String extractSSID(const wifi_promiscuous_pkt_t *packet);
String extractMAC(const wifi_promiscuous_pkt_t *packet);
uint8_t extractEncryptionHint(const wifi_promiscuous_pkt_t *packet);

// Data management functions
void saveProbesToFile(fs::FS &fs, bool compressed);
void clearProbes();

// Data retrieval functions
std::vector<ProbeRequest> getUniqueProbes();
std::vector<ClientBehavior> getVulnerableClients();

// Client behavior analysis
void analyzeClientBehavior(const ProbeRequest &probe);
uint8_t calculateAttackPriority(const ClientBehavior &client, const ProbeRequest &probe);

// Attack strategy functions
AttackTier determineAttackTier(uint8_t priority);
uint16_t getPortalDuration(AttackTier tier);
void checkCloneAttackOpportunities();
void checkPendingPortals();
void executeTieredAttackStrategy();

// Portal functions
void loadPortalTemplates();
bool selectPortalTemplate();
void launchTieredEvilPortal(PendingPortal &portal);
void launchManualEvilPortal(const String &ssid, uint8_t channel, bool verifyPwd);

// Network functions
void sendProbeResponse(const String &ssid, const String &mac, uint8_t channel);
void sendDeauth(const String &mac, uint8_t channel, bool broadcast);
void smartChannelHop();
void updateChannelActivity(uint8_t channel);
uint8_t getBestChannel();

// Sniffer callback
void probe_sniffer(void *buf, wifi_promiscuous_pkt_type_t type);

// Utility functions
String generateUniqueFilename(fs::FS &fs, bool compressed);
void initMACCache();
bool isMACInCache(const String &mac);
void addMACToCache(const String &mac);
void updateKarmaDisplay();
void updateSSIDFrequency(const String &ssid);

//===== GLOBAL VARIABLES =====//
// Note: These are defined in karma_attack.cpp
extern ProbeRequest probeBuffer[];
extern uint16_t probeBufferIndex;
extern bool bufferWrapped;
extern std::map<String, ClientBehavior> clientBehaviors;
extern KarmaConfig karmaConfig;
extern AttackConfig attackConfig;
extern std::vector<PortalTemplate> portalTemplates;
extern PortalTemplate selectedTemplate;
extern bool templateSelected;
extern std::map<String, uint16_t> ssidFrequency;
extern std::vector<std::pair<String, uint16_t>> popularSSIDs;
extern std::vector<PendingPortal> pendingPortals;
extern std::vector<PendingPortal> activePortals;
extern uint8_t channelActivity[];
extern uint8_t currentPriorityChannel;
extern unsigned long lastDeauthTime;
extern uint32_t totalProbes;
extern uint32_t uniqueClients;
extern uint32_t karmaResponsesSent;
extern uint32_t deauthPacketsSent;
extern uint32_t autoPortalsLaunched;
extern uint32_t cloneAttacksLaunched;
extern bool redrawNeeded;
extern bool isPortalActive;
extern unsigned long last_time;
extern unsigned long last_ChannelChange;
extern unsigned long lastFrequencyReset;
extern uint8_t channl;
extern bool flOpen;
extern bool is_LittleFS;
extern uint32_t pkt_counter;
extern bool auto_hopping;
extern uint16_t hop_interval;
extern File _probe_file;
extern RingbufHandle_t macRingBuffer;
extern String filen;

#endif // KARMA_ATTACK_H