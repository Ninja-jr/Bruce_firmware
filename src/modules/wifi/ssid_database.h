#ifndef SSID_DATABASE_H
#define SSID_DATABASE_H

#include <Arduino.h>
#include <vector>

class SSIDDatabase {
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
};

#endif // SSID_DATABASE_H
