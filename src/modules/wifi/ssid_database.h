#ifndef SSID_DATABASE_H
#define SSID_DATABASE_H

#include <Arduino.h>
#include <vector>

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

#endif // SSID_DATABASE_H