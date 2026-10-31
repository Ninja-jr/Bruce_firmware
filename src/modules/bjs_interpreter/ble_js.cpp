#if !defined(LITE_VERSION) && !defined(DISABLE_INTERPRETER)
#include "ble_js.h"
#include "modules/ble/ble_common.h"
#include <algorithm>
#include <cmath>

static bool rawScanOwned = false;
static bool rawScanPending = false;

JSValue native_bleStopScan(JSContext *, JSValue *, int, JSValue *) {
    if (rawScanOwned && BLEDevice::isInitialized()) {
        NimBLEScan *scan = BLEDevice::getScan();
        scan->stop();
        scan->clearResults();
        BLEDevice::deinit(true);
    }
    rawScanPending = false;
    rawScanOwned = false;
    return JS_UNDEFINED;
}

JSValue native_bleScan(JSContext *ctx, JSValue *this_val, int argc, JSValue *argv) {
    // usage: ble.scan(timeout_seconds)
    // returns: array of objects [{name, address, rssi}, ...]
    bool raw = argc > 1 && JS_ToBool(ctx, argv[1]);
    double seconds = 5;
    int timeout = 5; // legacy seconds
    if (argc > 0 && JS_IsNumber(ctx, argv[0])) {
        JS_ToNumber(ctx, &seconds, argv[0]);
        if (!std::isfinite(seconds)) return JS_ThrowRangeError(ctx, "scan duration must be finite");
        seconds = fmax(0.2, fmin(seconds, 30.0));
        timeout = (int)seconds;
    }
    if (timeout < 1) timeout = 1;
    if (timeout > 30) timeout = 30;

    uint32_t scanMs = raw ? (uint32_t)(fmax(0.2, fmin(seconds, 5.0)) * 1000) : timeout * 1000;
    const bool asynchronous = raw && argc > 2 && JS_ToBool(ctx, argv[2]);
    if (!BLEDevice::isInitialized()) BLEDevice::init("");
    if (raw) rawScanOwned = true;
    NimBLEScan *pScan = BLEDevice::getScan();
    BLEScanResults results;
#if __has_include(<NimBLEExtAdvertising.h>)
    if (asynchronous && rawScanPending) {
        if (pScan->isScanning()) return JS_UNDEFINED;
        results = pScan->getResults();
        rawScanPending = false;
    } else {
#endif
        pScan->setActiveScan(!raw);
        pScan->setInterval(100);
        pScan->setWindow(99);
        pScan->clearResults();
        pScan->setMaxResults(raw ? 64 : 255);
#if __has_include(<NimBLEExtAdvertising.h>)
        if (asynchronous) {
            if (!pScan->start(scanMs, false)) return JS_ThrowInternalError(ctx, "BLE scan failed to start");
            rawScanPending = true;
            return JS_UNDEFINED;
        }
        results = pScan->getResults(scanMs, false);
    }
#else
    results = pScan->start(timeout, false);
#endif
    int count = results.getCount();

    JSGCRef arrayRef;
    JS_PushGCRef(ctx, &arrayRef);
    arrayRef.val = JS_NewArray(ctx, 0);
    for (int i = 0; i < count; i++) {
#if __has_include(<NimBLEExtAdvertising.h>)
        const NimBLEAdvertisedDevice *dev = results.getDevice(i);
#else
        NimBLEAdvertisedDevice dev_obj = results.getDevice(i);
        NimBLEAdvertisedDevice *dev = &dev_obj;
#endif
        JSGCRef objectRef;
        JS_PushGCRef(ctx, &objectRef);
        objectRef.val = JS_NewObject(ctx);
        String name = dev->getName().c_str();
        if (name.isEmpty()) name = "<unknown>";
        {
            JSValue value = JS_NewString(ctx, name.c_str());
            JS_SetPropertyStr(ctx, objectRef.val, "name", value);
        }
        {
            JSValue value = JS_NewString(ctx, dev->getAddress().toString().c_str());
            JS_SetPropertyStr(ctx, objectRef.val, "address", value);
        }
        {
            JSValue value = JS_NewInt32(ctx, dev->getRSSI());
            JS_SetPropertyStr(ctx, objectRef.val, "rssi", value);
        }
        if (raw) {
            if (dev->haveManufacturerData()) {
                const auto mfr = dev->getManufacturerData();
                String mh;
                static const char hd[] = "0123456789abcdef";
                for (size_t j = 0; j < mfr.length() && j < 255; j++) {
                    unsigned char c = mfr[j];
                    mh += hd[c >> 4];
                    mh += hd[c & 15];
                }
                JSValue mv = JS_NewString(ctx, mh.c_str());
                JS_SetPropertyStr(ctx, objectRef.val, "manufacturer", mv);
            }
            const auto &payload = dev->getPayload();
            String hex;
            const size_t size = std::min((size_t)payload.size(), (size_t)255);
            hex.reserve(size * 2);
            static const char digits[] = "0123456789abcdef";
            for (size_t k = 0; k < size; ++k) {
                hex += digits[payload[k] >> 4];
                hex += digits[payload[k] & 15];
            }
            {
                JSValue value = JS_NewString(ctx, hex.c_str());
                JS_SetPropertyStr(ctx, objectRef.val, "payload", value);
            }
            {
                JSValue value = JS_NewInt32(ctx, dev->getAddress().getType());
                JS_SetPropertyStr(ctx, objectRef.val, "addressType", value);
            }
            {
                JSValue value = JS_NewBool(payload.size() > size);
                JS_SetPropertyStr(ctx, objectRef.val, "truncated", value);
            }
        }
        JS_SetPropertyUint32(ctx, arrayRef.val, i, objectRef.val);
        JS_PopGCRef(ctx, &objectRef);
    }

    pScan->clearResults();
    // Raw scans retain the stack until stopScan / interpreter cleanup.
    return JS_PopGCRef(ctx, &arrayRef);
}

JSValue native_bleAdvertise(JSContext *ctx, JSValue *this_val, int argc, JSValue *argv) {
    // usage: ble.advertise(name_string)
    const char *name = "Bruce-App";
    JSCStringBuf name_buf;
    if (argc > 0 && JS_IsString(ctx, argv[0])) { name = JS_ToCString(ctx, argv[0], &name_buf); }

    BLEDevice::init(name);
    NimBLEServer *pServer = BLEDevice::createServer();
    pServer->getAdvertising()->start();

    return JS_NewBool(true);
}

JSValue native_bleStopAdvertise(JSContext *ctx, JSValue *this_val, int argc, JSValue *argv) {
    NimBLEDevice::getAdvertising()->stop();
    BLEDevice::deinit();
    return JS_UNDEFINED;
}

// ---------------------------------------------------------------------------
// GATT client: connect to a peripheral and read/write its characteristics.
//
//   ble.connect(nameOrAddress, timeoutSec?) -> bool
//       Scans and connects to the first device whose name starts with
//       nameOrAddress (case-insensitive) or whose MAC equals it.
//   ble.isConnected() -> bool
//   ble.read(serviceUUID, charUUID) -> Uint8Array | null
//   ble.write(serviceUUID, charUUID, Uint8Array|string, withResponse?) -> bool
//   ble.disconnect()
// ---------------------------------------------------------------------------
#if __has_include(<NimBLEExtAdvertising.h>)
static NimBLEClient *jsBleClient = nullptr;

static bool jsBleIsConnected() { return jsBleClient != nullptr && jsBleClient->isConnected(); }

JSValue native_bleConnect(JSContext *ctx, JSValue *this_val, int argc, JSValue *argv) {
    if (argc < 1 || !JS_IsString(ctx, argv[0])) {
        return JS_ThrowTypeError(ctx, "ble.connect: arg0 must be a device name prefix or MAC address");
    }
    JSCStringBuf target_buf;
    const char *target_c = JS_ToCString(ctx, argv[0], &target_buf);
    String target = target_c ? target_c : "";
    int timeout = 5;
    if (argc > 1 && JS_IsNumber(ctx, argv[1])) JS_ToInt32(ctx, &timeout, argv[1]);
    if (timeout < 1) timeout = 1;
    if (timeout > 30) timeout = 30;

    if (jsBleIsConnected()) jsBleClient->disconnect();

    BLEDevice::init("");
    NimBLEScan *pScan = NimBLEDevice::getScan();
    pScan->setActiveScan(true);
    pScan->setInterval(100);
    pScan->setWindow(99);
    NimBLEScanResults results = pScan->getResults(timeout * 1000, false);

    const NimBLEAdvertisedDevice *found = nullptr;
    for (int i = 0; i < results.getCount(); i++) {
        const NimBLEAdvertisedDevice *dev = results.getDevice(i);
        String name = dev->getName().c_str();
        String addr = dev->getAddress().toString().c_str();
        if ((name.length() >= target.length() &&
             strncasecmp(name.c_str(), target.c_str(), target.length()) == 0) ||
            addr.equalsIgnoreCase(target)) {
            found = dev;
            break;
        }
    }

    bool ok = false;
    if (found != nullptr) {
        if (jsBleClient == nullptr) jsBleClient = NimBLEDevice::createClient();
        jsBleClient->setConnectTimeout(timeout * 1000);
        ok = jsBleClient->connect(found);
    }
    pScan->clearResults();
    return JS_NewBool(ok);
}

JSValue native_bleIsConnected(JSContext *ctx, JSValue *this_val, int argc, JSValue *argv) {
    return JS_NewBool(jsBleIsConnected());
}

static NimBLERemoteCharacteristic *jsBleGetChr(JSContext *ctx, int argc, JSValue *argv) {
    if (!jsBleIsConnected() || argc < 2 || !JS_IsString(ctx, argv[0]) || !JS_IsString(ctx, argv[1])) {
        return nullptr;
    }
    JSCStringBuf svc_buf, chr_buf;
    const char *svc_c = JS_ToCString(ctx, argv[0], &svc_buf);
    std::string svc_uuid = svc_c ? svc_c : "";
    const char *chr_c = JS_ToCString(ctx, argv[1], &chr_buf);
    std::string chr_uuid = chr_c ? chr_c : "";

    NimBLERemoteService *svc = jsBleClient->getService(NimBLEUUID(svc_uuid));
    if (svc == nullptr) return nullptr;
    return svc->getCharacteristic(NimBLEUUID(chr_uuid));
}

JSValue native_bleRead(JSContext *ctx, JSValue *this_val, int argc, JSValue *argv) {
    NimBLERemoteCharacteristic *chr = jsBleGetChr(ctx, argc, argv);
    if (chr == nullptr || !chr->canRead()) return JS_NULL;
    NimBLEAttValue val = chr->readValue();
    return JS_NewUint8ArrayCopy(ctx, val.data(), val.size());
}

JSValue native_bleWrite(JSContext *ctx, JSValue *this_val, int argc, JSValue *argv) {
    NimBLERemoteCharacteristic *chr = jsBleGetChr(ctx, argc, argv);
    if (chr == nullptr || argc < 3) return JS_NewBool(false);

    const uint8_t *buf = nullptr;
    size_t len = 0;
    JSCStringBuf str_buf;
    if (JS_IsString(ctx, argv[2])) {
        buf = (const uint8_t *)JS_ToCStringLen(ctx, &len, argv[2], &str_buf);
    } else if (JS_IsTypedArray(ctx, argv[2])) {
        buf = (const uint8_t *)JS_GetTypedArrayBuffer(ctx, &len, argv[2]);
    } else {
        return JS_ThrowTypeError(ctx, "ble.write: arg2 must be Uint8Array or string");
    }
    if (buf == nullptr) return JS_NewBool(false);

    bool response = chr->canWrite();
    if (argc > 3) response = JS_ToBool(ctx, argv[3]);
    return JS_NewBool(chr->writeValue(buf, len, response));
}

JSValue native_bleDisconnect(JSContext *ctx, JSValue *this_val, int argc, JSValue *argv) {
    if (jsBleIsConnected()) jsBleClient->disconnect();
    return JS_UNDEFINED;
}
#else
static JSValue jsBleGattUnsupported(JSContext *ctx) {
    return JS_ThrowInternalError(ctx, "ble GATT client requires NimBLE-Arduino 2.x");
}
JSValue native_bleConnect(JSContext *ctx, JSValue *this_val, int argc, JSValue *argv) {
    return jsBleGattUnsupported(ctx);
}
JSValue native_bleIsConnected(JSContext *ctx, JSValue *this_val, int argc, JSValue *argv) {
    return JS_NewBool(false);
}
JSValue native_bleRead(JSContext *ctx, JSValue *this_val, int argc, JSValue *argv) {
    return jsBleGattUnsupported(ctx);
}
JSValue native_bleWrite(JSContext *ctx, JSValue *this_val, int argc, JSValue *argv) {
    return jsBleGattUnsupported(ctx);
}
JSValue native_bleDisconnect(JSContext *ctx, JSValue *this_val, int argc, JSValue *argv) {
    return JS_UNDEFINED;
}
#endif

#endif
