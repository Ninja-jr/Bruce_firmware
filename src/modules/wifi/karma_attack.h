#ifndef KARMA_ATTACK_H
#define KARMA_ATTACK_H

#include <Arduino.h>
#include <vector>
#include <set>
#include <map>
#include "FS.h"
#include "esp_wifi_types.h"
#include <freertos/ringbuf.h>

namespace fs {
    class FS;
}

enum AttackTier;
struct PortalTemplate;
struct PendingPortal;
struct ClientBehavior;
struct ProbeRequest;
struct KarmaConfig;
struct AttackConfig;

//===== FUNCTION DECLARATIONS =====//

void karma_setup();

bool isProbeRequestWithSSID(const wifi_promiscuous_pkt_t *packet);
String extractSSID(const wifi_promiscuous_pkt_t *packet);
String extractMAC(const wifi_promiscuous_pkt_t *packet);
uint8_t extractEncryptionHint(const wifi_promiscuous_pkt_t *packet);

void saveProbesToFile(fs::FS &fs, bool compressed);
void clearProbes();

std::vector<ProbeRequest> getUniqueProbes();
std::vector<ClientBehavior> getVulnerableClients();

void analyzeClientBehavior(const ProbeRequest &probe);
uint8_t calculateAttackPriority(const ClientBehavior &client, const ProbeRequest &probe);

AttackTier determineAttackTier(uint8_t priority);
uint16_t getPortalDuration(AttackTier tier);
void checkCloneAttackOpportunities();
void checkPendingPortals();
void executeTieredAttackStrategy();

void loadPortalTemplates();
bool selectPortalTemplate();
void launchTieredEvilPortal(PendingPortal &portal);
void launchManualEvilPortal(const String &ssid, uint8_t channel, bool verifyPwd);

void sendProbeResponse(const String &ssid, const String &mac, uint8_t channel);
void sendDeauth(const String &mac, uint8_t channel, bool broadcast);
void smartChannelHop();
void updateChannelActivity(uint8_t channel);
uint8_t getBestChannel();

void probe_sniffer(void *buf, wifi_promiscuous_pkt_type_t type);

String generateUniqueFilename(fs::FS &fs, bool compressed);
void initMACCache();
bool isMACInCache(const String &mac);
void addMACToCache(const String &mac);
void updateKarmaDisplay();
void updateSSIDFrequency(const String &ssid);

//===== GLOBAL VARIABLES =====//

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