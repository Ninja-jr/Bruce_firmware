#include "webInterface.h"
#include "core/display.h"
#include "core/mykeyboard.h"
#include "core/passwords.h"
#include "core/sd_functions.h"
#include "core/serialcmds.h"
#include "core/settings.h"
#include "core/utils.h"
#include "core/wifi/wifi_common.h"
#include "esp_task_wdt.h"
#include "webFiles.h"
#include <MD5Builder.h>
#include <esp_heap_caps.h>
#include <globals.h>

#if defined(CONFIG_IDF_TARGET_ESP32) && !defined(BOARD_HAS_PSRAM)
#define MOUNT_SD_CARD setupSdCard()
#define UNMOUNT_SD_CARD closeSdCard()
#else
#define MOUNT_SD_CARD
#define UNMOUNT_SD_CARD
#endif

File uploadFile;
FS _webFS = LittleFS;
const int default_webserverporthttp = 80;
IPAddress AP_GATEWAY(172, 0, 0, 1);
AsyncWebServer *server = nullptr;
const char *host = "bruce";
String uploadFolder = "";
static bool mdnsRunning = false;
static bool forceScreenLogging = false;

String generateToken(int length = 24) {
    String token = "";
    const char charset[] = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    for (int i = 0; i < length; i++) { token += charset[random(0, sizeof(charset) - 1)]; }
    return token;
}

void stopWebUi() {
    forceScreenLogging = false;
    tft.setLogging(false);
    isWebUIActive = false;
    server->end();
    server->~AsyncWebServer();
    free(server);
    server = nullptr;
    if (mdnsRunning) {
        MDNS.end();
        mdnsRunning = false;
    }
}

void loopOptionsWebUi() {
    if (isWebUIActive) {
        bool opt = WiFi.getMode() - 1;
        options = {
            {"Stop WebUI", stopWebUi},
            {"WebUi screen", lambdaHelper(startWebUi, opt)}
        };
        addOptionToMainMenu();
        loopOptions(options);
        return;
    }
    options = {
        {"my Network", lambdaHelper(startWebUi, false)},
        {"AP mode",    lambdaHelper(startWebUi, true) },
    };
    loopOptions(options);
}

String humanReadableSize(uint64_t bytes) {
    if (bytes < 1024) return String(bytes) + " B";
    else if (bytes < (1024 * 1024)) return String(bytes / 1024.0) + " kB";
    else if (bytes < (1024 * 1024 * 1024)) return String(bytes / 1024.0 / 1024.0) + " MB";
    else return String(bytes / 1024.0 / 1024.0 / 1024.0) + " GB";
}

String listFiles(FS &fs, String folder) {
    String returnText = "pa:" + folder + ":0\n";
    MOUNT_SD_CARD;
    _webFS = fs;
    File root = fs.open(folder);
    uploadFolder = folder;
    while (true) {
        bool isDir;
        String fullPath = root.getNextFileName(&isDir);
        String nameOnly = fullPath.substring(fullPath.lastIndexOf("/") + 1);
        if (fullPath == "") { break; }
        if (esp_get_free_heap_size() > (String("Fo:" + nameOnly + ":0\n").length()) + 1024) {
            if (isDir) {
                returnText += "Fo:" + nameOnly + ":0\n";
            } else {
                File file = fs.open(fullPath);
                if (file) {
                    returnText += "Fi:" + nameOnly + ":" + humanReadableSize(file.size()) + "\n";
                    file.close();
                }
            }
        } else break;
        esp_task_wdt_reset();
    }
    root.close();
    UNMOUNT_SD_CARD;
    return returnText;
}

bool checkUserWebAuth(AsyncWebServerRequest *request, bool onFailureReturnLoginPage = false) {
    if (request->hasHeader("Cookie")) {
        const AsyncWebHeader *cookie = request->getHeader("Cookie");
        String c = cookie->value();
        int idx = c.indexOf("BRUCESESSION=");
        if (idx != -1) {
            int start = idx + 13;
            int end = c.indexOf(';', start);
            if (end == -1) end = c.length();
            String token = c.substring(start, end);
            if (bruceConfig.isValidWebUISession(token)) { return true; }
        }
    }
    if (onFailureReturnLoginPage) {
        serveWebUIFile(request, "login.html", "text/html", true, login_html, login_html_size);
    } else {
        request->send(401, "text/plain", "Unauthorized");
    }
    return false;
}

void createDirRecursive(String path, FS fs) {
    String currentPath = "";
    int startIndex = 0;
    while (startIndex < path.length()) {
        int endIndex = path.indexOf("/", startIndex);
        if (endIndex == -1) endIndex = path.length();
        currentPath += path.substring(startIndex, endIndex);
        if (currentPath.length() > 0) {
            if (!fs.exists(currentPath)) {
                fs.mkdir(currentPath);
            }
        }
        if (endIndex < path.length()) { currentPath += "/"; }
        startIndex = endIndex + 1;
    }
}

void handleUpload(
    AsyncWebServerRequest *request, String filename, size_t index, uint8_t *data, size_t len, bool final
) {
    if (checkUserWebAuth(request)) {
        if (uploadFolder == "/") uploadFolder = "";
        if (!index) {
            if (request->hasArg("password")) filename = filename + ".enc";
            String relativePath = filename;
            String fullPath = uploadFolder + "/" + relativePath;
            String dirPath = fullPath.substring(0, fullPath.lastIndexOf("/"));
            if (dirPath.length() > 0) { createDirRecursive(dirPath, _webFS); }
            MOUNT_SD_CARD;
        RETRY:
            request->_tempFile = _webFS.open(uploadFolder + "/" + filename, "w");
            if (!request->_tempFile) {
                goto RETRY;
            }
        }
        if (len) {
            if (request->hasArg("password")) {
                static int chunck_no = 0;
                if (chunck_no != 0) {
                    request->send(404, "text/html", "file is too big");
                    return;
                } else chunck_no += 1;
                String enc_password = request->arg("password");
                String plaintext = String((char *)data).substring(0, len);
                String cyphertxt = encryptString(plaintext, enc_password);
                if (cyphertxt == "") { return; }
                if (request->_tempFile)
                    request->_tempFile.write((const uint8_t *)cyphertxt.c_str(), cyphertxt.length());
            } else {
                if (request->_tempFile) request->_tempFile.write(data, len);
            }
        }
        if (final) {
            if (request->_tempFile) request->_tempFile.close();
            UNMOUNT_SD_CARD;
        }
    }
}

void notFound(AsyncWebServerRequest *request) { request->send(404, "text/plain", "Nothing in here Sharky"); }

void drawWebUiScreen(bool mode_ap) {
    tft.fillScreen(bruceConfig.bgColor);
    tft.drawRoundRect(5, 5, tftWidth - 10, tftHeight - 10, 5, ALCOLOR);
    if (mode_ap) {
        setTftDisplay(0, 0, bruceConfig.bgColor, FM);
        tft.drawCentreString("BruceNet/brucenet", tftWidth / 2, 7, 1);
    }
    setTftDisplay(0, 0, ALCOLOR, FM);
    tft.drawCentreString("BRUCE WebUI", tftWidth / 2, 27, 1);
    String txt;
    if (!mode_ap) txt = WiFi.localIP().toString();
    else txt = WiFi.softAPIP().toString();
    tft.setTextColor(bruceConfig.priColor);
    tft.drawCentreString("http://bruce.local", tftWidth / 2, 45, 1);
    setTftDisplay(7, 67);
    tft.setTextSize(FM);
    tft.print("IP: ");
    tft.println(txt);
    tft.setCursor(7, tft.getCursorY());
    tft.println("Usr: " + String(bruceConfig.webUI.user));
    tft.setCursor(7, tft.getCursorY());
    tft.println("Pwd: " + String(bruceConfig.webUI.pwd));
    tft.setCursor(7, tft.getCursorY());
    tft.setTextColor(TFT_RED);
    tft.setTextSize(FP);
    tft.drawCentreString("press Esc to stop", tftWidth / 2, tftHeight - 2 * LH * FP, 1);
#if defined(HAS_TOUCH)
    TouchFooter();
#endif
}

String color565ToWebHex(uint16_t color565) {
    uint8_t r = (color565 >> 11) & 0x1F;
    uint8_t g = (color565 >> 5) & 0x3F;
    uint8_t b = color565 & 0x1F;
    r = (r << 3) | (r >> 2);
    g = (g << 2) | (g >> 4);
    b = (b << 3) | (b >> 2);
    char hex[8];
    snprintf(hex, sizeof(hex), "#%02X%02X%02X", r, g, b);
    return String(hex);
}

void serveWebUIFile(AsyncWebServerRequest *request, String filename, const char *contentType) {
    serveWebUIFile(request, filename, contentType, false, nullptr, 0);
}
void serveWebUIFile(
    AsyncWebServerRequest *request, String filename, const char *contentType, bool gzip,
    const uint8_t *originaFile, uint32_t originalFileSize
) {
    AsyncWebServerResponse *response = nullptr;
    FS *fs = NULL;
    if (setupSdCard()) {
        if (SD.exists("/BruceWebUI/" + filename)) fs = &SD;
    } else if (LittleFS.exists("/BruceWebUI/" + filename)) {
        fs = &LittleFS;
    }
    if (fs) {
        response = request->beginResponse(*fs, "/BruceWebUI/" + filename, contentType);
    } else {
        if (filename == "theme.css") {
            String css = ":root{--color:" + color565ToWebHex(bruceConfig.priColor) +
                         ";--sec-color:" + color565ToWebHex(bruceConfig.secColor) +
                         ";--background:" + color565ToWebHex(bruceConfig.bgColor) + ";}";
            AsyncWebServerResponse *themeResponse = request->beginResponse(200, "text/css", css);
            request->send(themeResponse);
            return;
        }
        response = request->beginResponse(200, String(contentType), originaFile, originalFileSize);
        if (gzip) {
            if (!response->addHeader("Content-Encoding", "gzip")) Serial.println("Failed to add gzip header");
        }
    }
    request->send(response);
}

static bool startMdnsResponder() {
    constexpr size_t kMinInternalHeap = 20 * 1024;
    size_t freeInternalHeap = heap_caps_get_free_size(MALLOC_CAP_INTERNAL);
    if (freeInternalHeap < kMinInternalHeap) {
        Serial.printf(
            "Skipping mDNS responder. Only %lu bytes of internal heap available (need %lu).\n",
            static_cast<unsigned long>(freeInternalHeap),
            static_cast<unsigned long>(kMinInternalHeap)
        );
        return false;
    }
    if (!MDNS.begin(host)) {
        Serial.println("Error setting up MDNS responder!");
        return false;
    }
    return true;
}

void configureWebServer() {
    mdnsRunning = startMdnsResponder();
    DefaultHeaders::Instance().addHeader("Access-Control-Allow-Origin", "*");
    server->onNotFound(notFound);

    server->on("/", HTTP_GET, [](AsyncWebServerRequest *request) {
#ifndef HAS_SCREEN
        const char* headless_landing = R"=====(
<!DOCTYPE html>
<html>
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Bruce - Headless Mode</title>
<style>
body {
    margin: 0;
    background: #000;
    color: #0f0;
    font-family: monospace;
    display: flex;
    justify-content: center;
    align-items: center;
    min-height: 100vh;
}
.container {
    text-align: center;
    padding: 30px;
    border: 2px solid #0f0;
    border-radius: 10px;
    background: #111;
    max-width: 500px;
    width: 90%;
}
h1 {
    margin-top: 0;
    color: #0f0;
}
.options {
    display: flex;
    flex-direction: column;
    gap: 15px;
    margin: 30px 0;
}
.btn {
    background: #111;
    border: 2px solid #0f0;
    color: #0f0;
    padding: 15px;
    font-size: 18px;
    cursor: pointer;
    border-radius: 5px;
    text-decoration: none;
    display: block;
    transition: all 0.2s;
}
.btn:hover {
    background: #0f0;
    color: #000;
}
.login-form {
    margin-top: 30px;
    padding-top: 20px;
    border-top: 1px solid #333;
}
input {
    background: #111;
    border: 1px solid #0f0;
    color: #0f0;
    padding: 10px;
    margin: 8px;
    width: 80%;
    max-width: 250px;
    font-family: monospace;
}
.login-btn {
    background: #0f0;
    color: #000;
    border: none;
    padding: 10px 25px;
    cursor: pointer;
    font-weight: bold;
    font-family: monospace;
    margin-top: 10px;
}
.info {
    font-size: 12px;
    color: #888;
    margin-top: 25px;
    line-height: 1.4;
}
</style>
</head>
<body>
<div class="container">
    <h1>🦈 Bruce - Headless Mode</h1>
    <p>No display detected. Select an interface:</p>
    <div class="options">)=====";
        
        String landing_page = String(headless_landing);
        
#ifdef LITE_VERSION
        landing_page += R"=====(<a href="/webui" class="btn">🔧 WebUI</a>)=====";
#else
        landing_page += R"=====(<a href="/navigator" class="btn">🎮 Remote Navigator</a>
        <a href="/webui" class="btn">🔧 WebUI</a>)=====";
#endif
        
        landing_page += R"=====(
    </div>
    <div class="login-form">
        <p>Or login directly:</p>
        <form action="/login" method="POST">
            <input type="text" name="username" placeholder="Username" required><br>
            <input type="password" name="password" placeholder="Password" required><br>
            <button type="submit" class="login-btn">Login</button>
        </form>
    </div>
    <div class="info">
        <p>IP: )=====";
        
        if (WiFi.getMode() == WIFI_MODE_AP || WiFi.getMode() == WIFI_MODE_APSTA) {
            landing_page += WiFi.softAPIP().toString();
            landing_page += R"=====(<br>SSID: )=====";
            landing_page += WiFi.softAPSSID();
        } else {
            landing_page += WiFi.localIP().toString();
        }
        landing_page += R"=====(<br><small>Running in headless mode</small></p>
    </div>
</div>
</body>
</html>
        )=====";
        
        request->send(200, "text/html", landing_page);
        return;
#endif
        
        if (!checkUserWebAuth(request, true)) {
            return;
        }
        
#ifdef LITE_VERSION
        AsyncWebServerResponse *response = request->beginResponse(302);
        response->addHeader("Location", "/webui");
        request->send(response);
        return;
#endif
        
        const char* choice_page = R"=====(
<!DOCTYPE html>
<html>
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Bruce - Interface Selection</title>
<style>
body {
    margin: 0;
    background: #000;
    color: #0f0;
    font-family: monospace;
    display: flex;
    justify-content: center;
    align-items: center;
    min-height: 100vh;
}
.container {
    text-align: center;
    padding: 30px;
    border: 2px solid #0f0;
    border-radius: 10px;
    background: #111;
    max-width: 500px;
    width: 90%;
}
h1 {
    margin-top: 0;
    color: #0f0;
}
.options {
    display: flex;
    flex-direction: column;
    gap: 15px;
    margin: 30px 0;
}
.btn {
    background: #111;
    border: 2px solid #0f0;
    color: #0f0;
    padding: 20px;
    font-size: 18px;
    cursor: pointer;
    border-radius: 5px;
    text-decoration: none;
    display: block;
    transition: all 0.2s;
}
.btn:hover {
    background: #0f0;
    color: #000;
}
.info {
    font-size: 12px;
    color: #888;
    margin-top: 25px;
    line-height: 1.4;
}
.logout {
    margin-top: 20px;
}
.logout-btn {
    background: #111;
    border: 1px solid #f00;
    color: #f00;
    padding: 8px 15px;
    cursor: pointer;
    text-decoration: none;
    font-size: 14px;
}
.logout-btn:hover {
    background: #f00;
    color: #000;
}
</style>
</head>
<body>
<div class="container">
    <h1>🦈 Bruce Interface</h1>
    <p>Select an interface:</p>
    <div class="options">
        <a href="/webui" class="btn">🔧 WebUI</a>
        <a href="/navigator" class="btn">🎮 Remote Navigator</a>
    </div>
    <div class="info">
        <p>IP: )=====";
        
        String page = String(choice_page);
        if (WiFi.getMode() == WIFI_MODE_AP || WiFi.getMode() == WIFI_MODE_APSTA) {
            page += WiFi.softAPIP().toString();
            page += R"=====(<br>SSID: )=====";
            page += WiFi.softAPSSID();
        } else {
            page += WiFi.localIP().toString();
        }
        page += R"=====(<br>Device: )=====";
#ifndef HAS_SCREEN
        page += "Headless Mode";
#else
        page += "With Display";
#endif
        page += R"=====(</p>
    </div>
    <div class="logout">
        <a href="/logout" class="logout-btn">Logout</a>
    </div>
</div>
</body>
</html>
        )=====";
        
        request->send(200, "text/html", page);
    });

    server->on("/webui", HTTP_GET, [](AsyncWebServerRequest *request) {
        if (!checkUserWebAuth(request, false)) {
            AsyncWebServerResponse *response = request->beginResponse(302);
            response->addHeader("Location", "/");
            request->send(response);
            return;
        }
        serveWebUIFile(request, "index.html", "text/html", true, index_html, index_html_size);
    });

    server->on("/login", HTTP_POST, [](AsyncWebServerRequest *request) {
        if (request->hasParam("username", true) && request->hasParam("password", true)) {
            String username = request->getParam("username", true)->value();
            String password = request->getParam("password", true)->value();

            if (username == bruceConfig.webUI.user && password == bruceConfig.webUI.pwd) {
                String token = generateToken();
                AsyncWebServerResponse *response = request->beginResponse(302);
                response->addHeader("Location", "/");
                response->addHeader("Set-Cookie", "BRUCESESSION=" + token + "; Path=/; HttpOnly");
                request->send(response);
                MOUNT_SD_CARD;
                bruceConfig.addWebUISession(token);
                UNMOUNT_SD_CARD;
                return;
            }
        }
        AsyncWebServerResponse *response = request->beginResponse(302);
        response->addHeader("Location", "/?failed");
        request->send(response);
    });

    server->on("/logout", HTTP_GET, [](AsyncWebServerRequest *request) {
        if (request->hasHeader("Cookie")) {
            const AsyncWebHeader *cookie = request->getHeader("Cookie");
            String c = cookie->value();
            int idx = c.indexOf("BRUCESESSION=");
            if (idx != -1) {
                int start = idx + 13;
                int end = c.indexOf(';', start);
                if (end == -1) end = c.length();
                String token = c.substring(start, end);
                bruceConfig.removeWebUISession(token);
            }
        }
        AsyncWebServerResponse *response = request->beginResponse(302);
        response->addHeader("Location", "/?loggedout");
        response->addHeader("Set-Cookie", "BRUCESESSION=0; Path=/; Expires=Thu, 01 Jan 1970 00:00:00 GMT");
        request->send(response);
    });

    server->on("/theme.css", HTTP_GET, [](AsyncWebServerRequest *request) {
        serveWebUIFile(request, "theme.css", "text/css");
    });
    server->on("/index.css", HTTP_GET, [](AsyncWebServerRequest *request) {
        serveWebUIFile(request, "index.css", "text/css", true, index_css, index_css_size);
    });
    server->on("/index.js", HTTP_GET, [](AsyncWebServerRequest *request) {
        serveWebUIFile(request, "index.js", "text/javascript", true, index_js, index_js_size);
    });

#ifndef LITE_VERSION
    server->on("/navigator", HTTP_GET, [](AsyncWebServerRequest *request) {
        if (!checkUserWebAuth(request, false)) {
            AsyncWebServerResponse *response = request->beginResponse(302);
            response->addHeader("Location", "/");
            request->send(response);
            return;
        }
        
        forceScreenLogging = true;
        tft.setLogging(true);
        drawMainBorder(true);
        
        const char* navigator_html = R"=====(
<!DOCTYPE html>
<html>
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Bruce Navigator</title>
<style>
body { margin:0; background:#000; color:#0f0; font-family:monospace; }
.header { background:#111; padding:10px; display:flex; justify-content:space-between; align-items:center; border-bottom:1px solid #0f0; flex-wrap:wrap; }
.header-left { font-size:18px; }
.header-right { display:flex; gap:5px; flex-wrap:wrap; justify-content:flex-end; }
.screen-container { position:relative; padding:20px; text-align:center; }
#display { border:1px solid #0f0; max-width:100%; background:#000; }
#status-overlay { position:absolute; top:20px; left:20px; right:20px; height:20px; color:#0f0; font-size:12px; display:flex; justify-content:space-between; }
#menu-icons { position:absolute; top:40px; left:20px; display:flex; flex-direction:column; gap:5px; }
.controls { display:grid; grid-template-columns:repeat(3, 1fr); gap:10px; padding:20px; }
.nav-btn { background:#111; border:1px solid #0f0; color:#0f0; padding:20px; font-size:18px; cursor:pointer; transition:all 0.2s; }
.nav-btn:hover { background:#0f0; color:#000; }
.small-btn { padding:12px; font-size:14px; }
.ok-btn { border-radius:50%; }
.nav-menu { display:flex; gap:10px; padding:10px 20px; background:#111; border-top:1px solid #0f0; flex-wrap:wrap; }
.menu-btn { background:#111; border:1px solid #0f0; color:#0f0; padding:8px 12px; cursor:pointer; text-decoration:none; font-size:13px; }
.menu-btn:hover { background:#0f0; color:#000; }
.status-bar { padding:5px 10px; background:#111; border-top:1px solid #0f0; font-size:12px; color:#888; }
.icon-img { width:32px; height:32px; image-rendering:pixelated; }
</style>
</head>
<body>
<div class="header">
    <div class="header-left">🦈 Bruce Navigator</div>
    <div class="header-right">
        <a href="/" class="menu-btn">Switch</a>
        <a href="/logout" class="menu-btn">Logout</a>
    </div>
</div>
<div class="screen-container">
    <div id="status-overlay">
        <span id="time">--:--</span>
        <span id="battery">100%</span>
        <span id="wifi-status">WiFi: --</span>
    </div>
    <div id="menu-icons"></div>
    <canvas id="display" width="320" height="240"></canvas>
</div>
<div class="controls">
    <div></div>
    <button class="nav-btn" data-cmd="nav up">↑</button>
    <div></div>
    <button class="nav-btn" data-cmd="nav prev">←</button>
    <button class="nav-btn ok-btn" data-cmd="nav sel">OK</button>
    <button class="nav-btn" data-cmd="nav next">→</button>
    <div></div>
    <button class="nav-btn" data-cmd="nav down">↓</button>
    <div></div>
    <button class="nav-btn small-btn" data-cmd="nav esc">Back</button>
    <button class="nav-btn small-btn" data-cmd="nav menu" style="order:2;">Menu</button>
    <div></div>
</div>
<div class="nav-menu">
    <button class="menu-btn" onclick="refreshScreen()">🔄 Refresh</button>
    <button class="menu-btn" onclick="forceRedraw()">🖼️ Force Redraw</button>
    <button class="menu-btn" onclick="toggleAutoRefresh()">⏱️ Auto: <span id="autoRefreshStatus">Off</span></button>
    <button class="menu-btn" onclick="loadThemeIcons()">🎨 Load Icons</button>
</div>
<div class="status-bar" id="status">Status: Loading...</div>
<script>
const canvas = document.getElementById('display');
const ctx = canvas.getContext('2d');
let autoRefreshInterval = null;
let autoRefreshEnabled = false;
let currentTheme = null;
let menuIcons = {};

async function sendCommand(cmd) {
    try {
        const form = new FormData();
        form.append('cmnd', cmd);
        const response = await fetch('/cm', { method: 'POST', body: form });
        if (!response.ok) throw new Error(`Command failed: ${response.status}`);
        document.getElementById('status').textContent = `Status: Sent "${cmd}"`;
        setTimeout(updateScreen, 200);
    } catch (error) {
        console.error('Command failed:', error);
        document.getElementById('status').textContent = `Status: Error - ${error.message}`;
    }
}

async function updateScreen() {
    try {
        document.getElementById('status').textContent = 'Status: Updating...';
        
        await fetch('/forceredraw');
        
        const screenResponse = await fetch('/getscreen', {
            method: 'GET',
            headers: { 'Cache-Control': 'no-cache' }
        });
        
        if (!screenResponse.ok) throw new Error(`Screen: HTTP ${screenResponse.status}`);
        
        const buffer = await screenResponse.arrayBuffer();
        if (buffer.byteLength === 0) {
            drawPlaceholder("No screen data");
            return;
        }
        
        renderTFT(new Uint8Array(buffer));
        
        await updateStatus();
        
        document.getElementById('status').textContent = 'Status: Updated';
    } catch (error) {
        console.error('Update failed:', error);
        drawError(error.message);
        document.getElementById('status').textContent = `Status: Error - ${error.message}`;
    }
}

async function updateStatus() {
    try {
        const response = await fetch('/statusdata');
        if (!response.ok) return;
        
        const data = await response.json();
        
        if (data.time) {
            document.getElementById('time').textContent = data.time;
        }
        
        let batteryText = `${data.battery || 100}%`;
        if (data.charging) batteryText += " ⚡";
        document.getElementById('battery').textContent = batteryText;
        
        let wifiText = "WiFi: ";
        if (data.wifi) {
            wifiText += data.ssid ? data.ssid.substring(0, 10) : "Connected";
        } else {
            wifiText += "Off";
        }
        document.getElementById('wifi-status').textContent = wifiText;
        
    } catch (error) {
        console.error('Status update failed:', error);
    }
}

async function loadThemeIcons() {
    try {
        document.getElementById('status').textContent = 'Status: Loading theme...';
        
        const themeResponse = await fetch('/themeinfo');
        if (!themeResponse.ok) return;
        
        const themeData = await themeResponse.json();
        currentTheme = themeData;
        
        if (themeData.currentMenu) {
            const iconResponse = await fetch(`/menuicon?menu=${encodeURIComponent(themeData.currentMenu)}`);
            if (iconResponse.ok) {
                const blob = await iconResponse.blob();
                const img = new Image();
                img.onload = () => {
                    const iconContainer = document.getElementById('menu-icons');
                    iconContainer.innerHTML = '';
                    const imgElem = document.createElement('img');
                    imgElem.src = img.src;
                    imgElem.className = 'icon-img';
                    imgElem.title = themeData.currentMenu;
                    iconContainer.appendChild(imgElem);
                };
                img.src = URL.createObjectURL(blob);
            }
        }
        
        document.getElementById('status').textContent = 'Status: Theme loaded';
    } catch (error) {
        console.error('Theme load failed:', error);
    }
}

async function forceRedraw() {
    document.getElementById('status').textContent = 'Status: Forcing redraw...';
    await fetch('/forceredraw');
    setTimeout(updateScreen, 300);
}

function refreshScreen() {
    updateScreen();
}

function toggleAutoRefresh() {
    autoRefreshEnabled = !autoRefreshEnabled;
    const status = document.getElementById('autoRefreshStatus');
    if (autoRefreshEnabled) {
        status.textContent = '2s';
        autoRefreshInterval = setInterval(updateScreen, 2000);
    } else {
        status.textContent = 'Off';
        clearInterval(autoRefreshInterval);
        autoRefreshInterval = null;
    }
}

function color565toCSS(color565) {
    const r = ((color565 >> 11) & 0x1F) * 255 / 31;
    const g = ((color565 >> 5) & 0x3F) * 255 / 63;
    const b = (color565 & 0x1F) * 255 / 31;
    return `rgb(${r},${g},${b})`;
}

function renderTFT(data) {
    if (!data || data.length === 0) {
        drawPlaceholder("No data");
        return;
    }
    
    let offset = 0;
    ctx.clearRect(0, 0, canvas.width, canvas.height);
    
    while (offset < data.length) {
        if (data[offset] !== 0xAA) {
            console.warn('Invalid packet at offset', offset);
            break;
        }
        
        if (offset + 2 >= data.length) break;
        const size = data[offset + 1];
        const fn = data[offset + 2];
        
        if (offset + size > data.length) break;
        
        const packet = data.slice(offset, offset + size);
        offset += size;
        processCommand(fn, packet);
    }
}

function processCommand(fn, data) {
    let idx = 3;
    function readByte() { return data[idx++]; }
    function readShort() {
        const value = (data[idx] << 8) | data[idx + 1];
        idx += 2;
        return value;
    }
    function readString(len) {
        const str = new TextDecoder().decode(data.slice(idx, idx + len));
        idx += len;
        return str;
    }
    ctx.lineWidth = 1;
    switch (fn) {
        case 99:
            const w = readShort();
            const h = readShort();
            canvas.width = w;
            canvas.height = h;
            break;
        case 0:
            const bgColor = readShort();
            ctx.fillStyle = color565toCSS(bgColor);
            ctx.fillRect(0, 0, canvas.width, canvas.height);
            break;
        case 1:
            const x1 = readShort();
            const y1 = readShort();
            const w1 = readShort();
            const h1 = readShort();
            const rectColor = readShort();
            ctx.strokeStyle = color565toCSS(rectColor);
            ctx.strokeRect(x1, y1, w1, h1);
            break;
        case 2:
            const x2 = readShort();
            const y2 = readShort();
            const w2 = readShort();
            const h2 = readShort();
            const fillColor = readShort();
            ctx.fillStyle = color565toCSS(fillColor);
            ctx.fillRect(x2, y2, w2, h2);
            break;
        case 14:
        case 15:
        case 16:
            const x3 = readShort();
            const y3 = readShort();
            const size = readShort();
            const fg = readShort();
            const bg = readShort();
            const text = readString(data.length - idx);
            
            ctx.fillStyle = color565toCSS(bg);
            const fw = size === 3 ? 13.5 : size === 2 ? 9 : 4.5;
            let offset = 0;
            if (fn === 15) offset = text.length * fw;
            if (fn === 14) offset = text.length * fw / 2;
            ctx.fillRect(x3 - offset, y3, text.length * fw, size * 8);
            
            ctx.fillStyle = color565toCSS(fg);
            ctx.font = `${size * 8}px monospace`;
            ctx.textBaseline = 'top';
            if (fn === 14) ctx.textAlign = 'center';
            else if (fn === 15) ctx.textAlign = 'right';
            else ctx.textAlign = 'left';
            ctx.fillText(text, x3, y3);
            break;
    }
}

function drawError(message) {
    ctx.fillStyle = '#000';
    ctx.fillRect(0, 0, canvas.width, canvas.height);
    ctx.fillStyle = '#f00';
    ctx.font = '12px monospace';
    ctx.textAlign = 'center';
    ctx.fillText('Screen Update Failed', canvas.width/2, canvas.height/2 - 20);
    ctx.fillText(message.substring(0, 40), canvas.width/2, canvas.height/2);
    ctx.fillText('Try refreshing manually', canvas.width/2, canvas.height/2 + 20);
}

function drawPlaceholder(message) {
    const gradient = ctx.createLinearGradient(0, 0, canvas.width, canvas.height);
    gradient.addColorStop(0, '#111');
    gradient.addColorStop(1, '#222');
    ctx.fillStyle = gradient;
    ctx.fillRect(0, 0, canvas.width, canvas.height);
    ctx.fillStyle = '#0f0';
    ctx.font = 'bold 48px monospace';
    ctx.textAlign = 'center';
    ctx.fillText('🦈', canvas.width/2, canvas.height/2 - 40);
    ctx.font = '16px monospace';
    ctx.fillText('BRUCE NAVIGATOR', canvas.width/2, canvas.height/2);
    ctx.font = '12px monospace';
    ctx.fillText(message, canvas.width/2, canvas.height/2 + 25);
    ctx.fillText('Navigate to refresh', canvas.width/2, canvas.height/2 + 45);
}

document.addEventListener('DOMContentLoaded', function() {
    updateScreen();
    loadThemeIcons();
    updateStatus();
    
    setTimeout(() => {
        sendCommand('nav menu');
        setTimeout(() => {
            sendCommand('nav esc');
            setTimeout(() => {
                updateScreen();
                loadThemeIcons();
            }, 500);
        }, 300);
    }, 1000);
});

document.querySelectorAll('.nav-btn').forEach(btn => {
    btn.addEventListener('click', () => {
        sendCommand(btn.dataset.cmd);
    });
});

document.addEventListener('keydown', (e) => {
    const keyMap = {
        'ArrowUp': 'nav up', 'ArrowDown': 'nav down',
        'ArrowLeft': 'nav prev', 'ArrowRight': 'nav next',
        'Enter': 'nav sel', 'Escape': 'nav esc',
        'Backspace': 'nav esc', 'm': 'nav menu', 'M': 'nav menu'
    };
    if (keyMap[e.key]) {
        e.preventDefault();
        sendCommand(keyMap[e.key]);
    }
    if (e.key === 'r' || e.key === 'R') {
        e.preventDefault();
        refreshScreen();
    }
    if (e.key === 'f' || e.key === 'F') {
        e.preventDefault();
        forceRedraw();
    }
    if (e.key === 't' || e.key === 'T') {
        e.preventDefault();
        loadThemeIcons();
    }
});
</script>
</body>
</html>
)=====";
        
        request->send(200, "text/html", navigator_html);
    });
#endif

    server->on("/themeinfo", HTTP_GET, [](AsyncWebServerRequest *request) {
        if (checkUserWebAuth(request)) {
            JsonDocument doc;
            doc["theme"] = bruceConfig.themePath;
            doc["themeFS"] = bruceConfig.theme.fs;
            
            String json;
            serializeJson(doc, json);
            request->send(200, "application/json", json);
        }
    });

    server->on("/menuicon", HTTP_GET, [](AsyncWebServerRequest *request) {
        if (checkUserWebAuth(request) && request->hasArg("menu")) {
            String menuName = request->arg("menu");
            FS *fs = bruceConfig.themeFS();
            
            String imagePath;
            if (menuName == "Bluetooth") imagePath = bruceConfig.getThemeItemImg(bruceConfig.theme.paths.ble);
            else if (menuName == "WiFi") imagePath = bruceConfig.getThemeItemImg(bruceConfig.theme.paths.wifi);
            else if (menuName == "Files") imagePath = bruceConfig.getThemeItemImg(bruceConfig.theme.paths.file);
            
            if (!imagePath.isEmpty() && fs->exists(imagePath)) {
                request->send(*fs, imagePath, "image/png");
            } else {
                request->send(404, "text/plain", "Icon not found");
            }
        }
    });

    server->on("/statusdata", HTTP_GET, [](AsyncWebServerRequest *request) {
        if (checkUserWebAuth(request)) {
            JsonDocument doc;
            
            doc["battery"] = 100;
            doc["charging"] = false;
            
            doc["wifi"] = WiFi.status() == WL_CONNECTED;
            if (WiFi.getMode() == WIFI_MODE_AP || WiFi.getMode() == WIFI_MODE_APSTA) {
                doc["wifiMode"] = "AP";
                doc["ssid"] = WiFi.softAPSSID();
            } else {
                doc["wifiMode"] = "STA";
                doc["ssid"] = WiFi.SSID();
            }
            
            doc["ble"] = BLEConnected;
            doc["time"] = "12:00";
            
            doc["width"] = tftWidth;
            doc["height"] = tftHeight;
            doc["logging"] = tft.getLogging();
            
            String json;
            serializeJson(doc, json);
            request->send(200, "application/json", json);
        }
    });

    server->on("/forceredraw", HTTP_GET, [](AsyncWebServerRequest *request) {
        if (checkUserWebAuth(request)) {
            drawMainBorder(true);
            drawStatusBar();
            request->send(200, "text/plain", "Screen redrawn");
        }
    });

    server->on("/screenstatus", HTTP_GET, [](AsyncWebServerRequest *request) {
        if (checkUserWebAuth(request)) {
            String status = "Screen logging: ";
            status += tft.getLogging() ? "active" : "inactive";
            status += "\nHeap: ";
            status += String(esp_get_free_heap_size());
            status += "\nWebUI active: ";
            status += isWebUIActive ? "yes" : "no";
            status += "\nForce logging: ";
            status += forceScreenLogging ? "yes" : "no";
            request->send(200, "text/plain", status);
        }
    });

    server->on("/systeminfo", HTTP_GET, [](AsyncWebServerRequest *request) {
        if (checkUserWebAuth(request)) {
            char response_body[300];
            MOUNT_SD_CARD;
            uint64_t LittleFSTotalBytes = LittleFS.totalBytes();
            uint64_t LittleFSUsedBytes = LittleFS.usedBytes();
            uint64_t SDTotalBytes = SD.totalBytes();
            uint64_t SDUsedBytes = SD.usedBytes();
            UNMOUNT_SD_CARD;
            sprintf(
                response_body,
                "{\"%s\":\"%s\",\"SD\":{\"%s\":\"%s\",\"%s\":\"%s\",\"%s\":\"%s\"},"
                "\"LittleFS\":{\"%s\":\"%s\",\"%s\":\"%s\",\"%s\":\"%s\"}}",
                "BRUCE_VERSION",
                BRUCE_VERSION,
                "free",
                humanReadableSize(SDTotalBytes - SDUsedBytes).c_str(),
                "used",
                humanReadableSize(SDUsedBytes).c_str(),
                "total",
                humanReadableSize(SDTotalBytes).c_str(),
                "free",
                humanReadableSize(LittleFSTotalBytes - LittleFSUsedBytes).c_str(),
                "used",
                humanReadableSize(LittleFSUsedBytes).c_str(),
                "total",
                humanReadableSize(LittleFSTotalBytes).c_str()
            );
            request->send(200, "application/json", response_body);
        }
    });

    server->on("/getscreen", HTTP_GET, [](AsyncWebServerRequest *request) {
        if (checkUserWebAuth(request)) {
            static uint8_t *screenBinBuffer = nullptr;
            static size_t screenBinBufferSize = 0;

            if (!screenBinBuffer) {
                size_t desiredSize = MAX_LOG_ENTRIES * MAX_LOG_SIZE;
                if (psramFound()) screenBinBuffer = static_cast<uint8_t *>(ps_malloc(desiredSize));
                if (!screenBinBuffer) screenBinBuffer = static_cast<uint8_t *>(malloc(desiredSize));
                if (!screenBinBuffer) {
                    request->send(503, "text/plain", "Insufficient memory for screen buffer");
                    return;
                }
                screenBinBufferSize = desiredSize;
            }

            size_t binSize = 0;
            tft.getBinLog(screenBinBuffer, binSize);
            if (binSize > screenBinBufferSize) {
                request->send(500, "text/plain", "Screen buffer overflow");
                return;
            }
            request->send(200, "application/octet-stream", (const uint8_t *)screenBinBuffer, binSize);
        }
    });

    server->on("/rename", HTTP_POST, [](AsyncWebServerRequest *request) {
        if (checkUserWebAuth(request)) {
            if (request->hasArg("fileName") && request->hasArg("filePath")) {
                String fs = request->arg("fs").c_str();
                String fileName = request->arg("fileName").c_str();
                String filePath = request->arg("filePath").c_str();
                String filePath2 = filePath.substring(0, filePath.lastIndexOf('/') + 1) + fileName;
                if (fs == "SD") {
                    MOUNT_SD_CARD;
                    if (SD.rename(filePath, filePath2))
                        request->send(200, "text/plain", filePath + " renamed to " + filePath2);
                    else request->send(200, "text/plain", "Fail renaming file.");
                    UNMOUNT_SD_CARD;
                } else {
                    if (LittleFS.rename(filePath, filePath2))
                        request->send(200, "text/plain", filePath + " renamed to " + filePath2);
                    else request->send(200, "text/plain", "Fail renaming file.");
                }
            }
        }
    });

    server->on("/cm", HTTP_POST, [](AsyncWebServerRequest *request) {
        if (!checkUserWebAuth(request)) { return; }
        if (request->hasArg("cmnd")) {
            String cmnd = request->arg("cmnd");
            
            if (cmnd == "refresh screen" || cmnd == "redraw") {
                drawMainBorder(true);
                request->send(200, "text/plain", "Screen refreshed");
                return;
            }
            
            if (cmnd.startsWith("nav")) {
                if (cmnd.startsWith("nav menu")) {
                    returnToMenu = true;
                    AnyKeyPress = true;
                    SerialCmdPress = true;
                    
                    drawMainBorder(true);
                    drawStatusBar();
                    
                    request->send(200, "text/plain", "command " + cmnd + " success");
                    return;
                }
                
                volatile bool *var = &SelPress;
                if (cmnd.startsWith("nav sel")) var = &SelPress;
                else if (cmnd.startsWith("nav esc")) var = &EscPress;
                else if (cmnd.startsWith("nav up")) var = &UpPress;
                else if (cmnd.startsWith("nav down")) var = &DownPress;
                else if (cmnd.startsWith("nav next")) var = &NextPress;
                else if (cmnd.startsWith("nav prev")) var = &PrevPress;
                else if (cmnd.startsWith("nav nextpage")) var = &NextPagePress;
                else if (cmnd.startsWith("nav prevpage")) var = &PrevPagePress;
                
                request->send(200, "text/plain", "command " + cmnd + " success");
                int time;
                if (cmnd.endsWith("0")) time = cmnd.substring(cmnd.lastIndexOf(' ')).toInt();
                else time = 10;
                auto tmp = millis() + time;
                while (tmp > millis()) {
                    AnyKeyPress = true;
                    SerialCmdPress = true;
                    *var = true;
                    if (!LongPress) vTaskDelay(pdMS_TO_TICKS(190));
                    else vTaskDelay(pdMS_TO_TICKS(50));
                }
            } else {
                MOUNT_SD_CARD;
                if (parseSerialCommand(cmnd, false)) {
                    request->send(200, "text/plain", "command " + cmnd + " queued");
                } else {
                    request->send(400, "text/plain", "command failed, check the serial log for details");
                }
                UNMOUNT_SD_CARD;
            }
        } else {
            request->send(400, "text/plain", "http request missing required arg: cmnd");
        }
    });

    server->on("/reboot", HTTP_GET, [](AsyncWebServerRequest *request) {
        if (checkUserWebAuth(request)) { ESP.restart(); }
    });

    server->on("/listfiles", HTTP_GET, [](AsyncWebServerRequest *request) {
        if (checkUserWebAuth(request)) {
            String folder = "/";
            if (request->hasArg("folder")) { folder = request->arg("folder"); }
            if (strcmp(request->arg("fs").c_str(), "SD") == 0) {
                MOUNT_SD_CARD;
                request->send(200, "text/plain", listFiles(SD, folder));
                UNMOUNT_SD_CARD;
            } else {
                request->send(200, "text/plain", listFiles(LittleFS, folder));
            }
        }
    });

    server->on("/file", HTTP_GET, [](AsyncWebServerRequest *request) {
        if (checkUserWebAuth(request)) {
            if (request->hasArg("name") && request->hasArg("action")) {
                String fileName = request->arg("name").c_str();
                String fileAction = request->arg("action").c_str();
                String fileSys = request->arg("fs").c_str();
                bool useSD = false;
                if (fileSys == "SD") useSD = true;

                FS *fs;
                if (useSD) {
                    MOUNT_SD_CARD;
                    request->onDisconnect([]() { UNMOUNT_SD_CARD; });
                    fs = &SD;
                } else fs = &LittleFS;

                Serial.printf("\nfilename: %s\n", fileName.c_str());
                Serial.printf("fileAction: %s\n", fileAction.c_str());

                if (!fs->exists(fileName)) {
                    if (strcmp(fileAction.c_str(), "create") == 0) {
                        if (fs->mkdir(fileName)) {
                            request->send(200, "text/plain", "Created new folder: " + String(fileName));
                        } else {
                            request->send(200, "text/plain", "FAIL creating folder: " + String(fileName));
                        }
                    } else if (strcmp(fileAction.c_str(), "createfile") == 0) {
                        File newFile = fs->open(fileName, FILE_WRITE, true);
                        if (newFile) {
                            newFile.close();
                            request->send(200, "text/plain", "Created new file: " + String(fileName));
                        } else {
                            request->send(200, "text/plain", "FAIL creating file: " + String(fileName));
                        }
                    } else request->send(400, "text/plain", "ERROR: file does not exist");

                } else {
                    if (strcmp(fileAction.c_str(), "download") == 0) {
                        request->send(*fs, fileName, "application/octet-stream", true);
                    } else if (strcmp(fileAction.c_str(), "image") == 0) {
                        String extension = fileName.substring(fileName.lastIndexOf('.') + 1);
                        if (extension == "jpg") extension = "jpeg";
                        request->send(*fs, fileName, "image/" + extension);
                    } else if (strcmp(fileAction.c_str(), "delete") == 0) {
                        if (deleteFromSd(*fs, fileName)) {
                            request->send(200, "text/plain", "Deleted : " + String(fileName));
                        } else {
                            request->send(200, "text/plain", "FAIL deleting: " + String(fileName));
                        }
                    } else if (strcmp(fileAction.c_str(), "create") == 0) {
                        if (fs->mkdir(fileName)) {
                            request->send(200, "text/plain", "Created new folder: " + String(fileName));
                        } else {
                            request->send(200, "text/plain", "FAIL creating folder: " + String(fileName));
                        }
                    } else if (strcmp(fileAction.c_str(), "createfile") == 0) {
                        File newFile = fs->open(fileName, FILE_WRITE, true);
                        if (newFile) {
                            newFile.close();
                            request->send(200, "text/plain", "Created new file: " + String(fileName));
                        } else {
                            request->send(200, "text/plain", "FAIL creating file: " + String(fileName));
                        }

                    } else if (strcmp(fileAction.c_str(), "edit") == 0) {
                        File editFile = fs->open(fileName, FILE_READ);
                        if (editFile) {
                            String fileContent = editFile.readString();
                            request->send(200, "text/plain", fileContent);
                            editFile.close();
                        } else {
                            request->send(500, "text/plain", "Failed to open file for reading");
                        }

                    } else {
                        request->send(400, "text/plain", "ERROR: invalid action param supplied");
                    }
                }
            } else {
                request->send(400, "text/plain", "ERROR: name and action params required");
            }
        }
    });

    server->on("/edit", HTTP_POST, [](AsyncWebServerRequest *request) {
        if (checkUserWebAuth(request)) {
            if (request->hasArg("name") && request->hasArg("content") && request->hasArg("fs")) {
                String fileName = request->arg("name");
                String fileContent = request->arg("content");
                bool useSD = false;

                if (strcmp(request->arg("fs").c_str(), "SD") == 0) { useSD = true; }

                fs::FS *fs = useSD ? (fs::FS *)&SD : (fs::FS *)&LittleFS;
                String fsType = useSD ? "SD" : "LittleFS";

                if (useSD) {
                    if (!setupSdCard()) {
                        request->onDisconnect([]() { UNMOUNT_SD_CARD; });
                        request->send(500, "text/plain", "Failed to initialize file system: " + fsType);
                        return;
                    }
                }

                File editFile = fs->open(fileName, FILE_WRITE);
                if (editFile) {
                    if (editFile.write((const uint8_t *)fileContent.c_str(), fileContent.length())) {
                        request->send(200, "text/plain", "File edited: " + fileName);
                    } else {
                        request->send(500, "text/plain", "Failed to write to file: " + fileName);
                    }
                    editFile.close();
                } else {
                    request->send(500, "text/plain", "Failed to open file for writing: " + fileName);
                }

            } else {
                request->send(400, "text/plain", "ERROR: name, content, and fs parameters required");
            }
        }
    });

    server->on(
        "/upload",
        HTTP_POST,
        [](AsyncWebServerRequest *request) { request->send(200, "text/plain", "File upload completed"); },
        handleUpload
    );

    server->on("/wifi", HTTP_GET, [](AsyncWebServerRequest *request) {
        if (checkUserWebAuth(request)) {
            if (request->hasArg("usr") && request->hasArg("pwd")) {
                const char *usr = request->arg("usr").c_str();
                const char *pwd = request->arg("pwd").c_str();
                MOUNT_SD_CARD;
                bruceConfig.setWebUICreds(usr, pwd);
                UNMOUNT_SD_CARD;
                request->send(
                    200, "text/plain", "User: " + String(usr) + " configured with password: " + String(pwd)
                );
            }
        }
    });
    server->begin();
    Serial.println("Webserver started");
}

void startWebUi(bool mode_ap) {
    UNMOUNT_SD_CARD;
    bool keepWifiConnected = false;
    if (WiFi.status() != WL_CONNECTED) {
        if (mode_ap) wifiConnectMenu(WIFI_AP);
        else wifiConnectMenu(WIFI_STA);
    } else {
        keepWifiConnected = true;
    }

    if (!server) {
        options.clear();

        Serial.println("Configuring Webserver ...");
        if (psramFound()) server = (AsyncWebServer *)ps_malloc(sizeof(AsyncWebServer));
        else server = (AsyncWebServer *)malloc(sizeof(AsyncWebServer));

        new (server) AsyncWebServer(default_webserverporthttp);

        forceScreenLogging = true;
        
        configureWebServer();

        isWebUIActive = true;
    }
    
    tft.setLogging(true);
    
    drawWebUiScreen(mode_ap);
    
#ifdef HAS_SCREEN
    while (!check(EscPress)) {
        vTaskDelay(pdMS_TO_TICKS(70));
    }

    bool closeServer = false;

    options.clear();
    options.emplace_back("Run in background", []() {});
    options.emplace_back("Exit", [&closeServer]() { closeServer = true; });

    loopOptions(options);

    if (closeServer) {
        stopWebUi();
        vTaskDelay(pdMS_TO_TICKS(100));
        if (!keepWifiConnected) { wifiDisconnect(); }
    }
#endif
}
