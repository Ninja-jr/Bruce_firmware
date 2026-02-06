#include "ssid_database.h"
#include "FS.h"
#include "SD.h"
#include <LittleFS.h>
#include <vector>

std::vector<String> SSIDDatabase::ssidCache;
bool SSIDDatabase::cacheLoaded = false;
String SSIDDatabase::currentFilename = "/ssid_list.txt";
bool SSIDDatabase::useLittleFS = false;

bool SSIDDatabase::setSourceFile(const String &filename, bool useLittleFSMode) {
    currentFilename = filename;
    useLittleFS = useLittleFSMode;
    cacheLoaded = false;
    ssidCache.clear();
    return loadFromFile();
}

bool SSIDDatabase::loadFromFile() {
    if (cacheLoaded && !ssidCache.empty()) return true;
    
    ssidCache.clear();
    
    File file;
    if (useLittleFS) {
        if (!LittleFS.begin()) return false;
        file = LittleFS.open(currentFilename, FILE_READ);
    } else {
        if (!SD.begin()) return false;
        file = SD.open(currentFilename, FILE_READ);
    }
    
    if (!file) return false;
    
    while (file.available()) {
        String line = file.readStringUntil('\n');
        line.trim();
        
        if (line.length() == 0) continue;
        if (line.startsWith("#") || line.startsWith("//")) continue;
        if (line.length() > 32) continue;
        
        ssidCache.push_back(line);
    }
    
    file.close();
    
    if (useLittleFS) {
        LittleFS.end();
    } else {
        SD.end();
    }
    
    cacheLoaded = true;
    return !ssidCache.empty();
}

bool SSIDDatabase::reload() {
    cacheLoaded = false;
    return loadFromFile();
}

void SSIDDatabase::clearCache() {
    ssidCache.clear();
    cacheLoaded = false;
}

bool SSIDDatabase::isLoaded() {
    return cacheLoaded && !ssidCache.empty();
}

String SSIDDatabase::getSourceFile() {
    return currentFilename;
}

size_t SSIDDatabase::getCount() {
    if (!cacheLoaded) loadFromFile();
    return ssidCache.size();
}

String SSIDDatabase::getSSID(size_t index) {
    if (!cacheLoaded) loadFromFile();
    if (index >= ssidCache.size()) return "";
    return ssidCache[index];
}

std::vector<String> SSIDDatabase::getAllSSIDs() {
    if (!cacheLoaded) loadFromFile();
    return ssidCache;
}

int SSIDDatabase::findSSID(const String &ssid) {
    if (!cacheLoaded) loadFromFile();
    for (size_t i = 0; i < ssidCache.size(); i++) {
        if (ssidCache[i] == ssid) return i;
    }
    return -1;
}

String SSIDDatabase::getRandomSSID() {
    if (!cacheLoaded) loadFromFile();
    if (ssidCache.empty()) return "";
    size_t index = random(ssidCache.size());
    return ssidCache[index];
}

void SSIDDatabase::getBatch(size_t startIndex, size_t count, std::vector<String> &result) {
    if (!cacheLoaded) loadFromFile();
    result.clear();
    
    if (startIndex >= ssidCache.size()) return;
    
    size_t endIndex = startIndex + count;
    if (endIndex > ssidCache.size()) endIndex = ssidCache.size();
    
    for (size_t i = startIndex; i < endIndex; i++) {
        result.push_back(ssidCache[i]);
    }
}

bool SSIDDatabase::contains(const String &ssid) {
    return findSSID(ssid) >= 0;
}

size_t SSIDDatabase::getAverageLength() {
    if (!cacheLoaded) loadFromFile();
    if (ssidCache.empty()) return 0;
    
    size_t total = 0;
    for (const auto &ssid : ssidCache) {
        total += ssid.length();
    }
    return total / ssidCache.size();
}

size_t SSIDDatabase::getMaxLength() {
    if (!cacheLoaded) loadFromFile();
    size_t maxLen = 0;
    for (const auto &ssid : ssidCache) {
        size_t len = ssid.length();
        if (len > maxLen) maxLen = len;
    }
    return maxLen;
}

size_t SSIDDatabase::getMinLength() {
    if (!cacheLoaded) loadFromFile();
    if (ssidCache.empty()) return 0;
    
    size_t minLen = 32;
    for (const auto &ssid : ssidCache) {
        size_t len = ssid.length();
        if (len < minLen) minLen = len;
    }
    return minLen;
}