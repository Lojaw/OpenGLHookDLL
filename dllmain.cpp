#include "pch.h"
#include <windows.h>
#include <gl/GL.h>
#include <gl/GLU.h>

#include "thread"
#include "chrono"

#include "Windows.h"
#include <fstream>
#include <unordered_set>
#include <mutex>
#include <sstream>

std::unordered_set<std::string> logCache;
std::mutex logMutex;

void logMessage(const std::string& message) {
    std::lock_guard<std::mutex> lock(logMutex);

    // Überprüfen, ob die Nachricht bereits geloggt wurde
    if (logCache.find(message) != logCache.end()) {
        return; // Bereits geloggt, nichts zu tun
    }

    // Nachricht in die Datei schreiben
    std::ofstream logFile("C:\\Users\\jpsch\\Desktop\\C++\\OpenGLHookDLL\\loggingopengldll.txt", std::ios::app);
    if (logFile.is_open()) {
        logFile << message << std::endl;
        logFile.close();
    }

    // Nachricht zum Cache hinzufügen
    logCache.insert(message);
}

void clearLogFile() {
    std::lock_guard<std::mutex> lock(logMutex);
    std::ofstream logFile("C:\\Users\\jpsch\\Desktop\\C++\\OpenGLHookDLL\\loggingopengldll.txt", std::ios::trunc);
    logFile.close();
    logCache.clear();
}

// Prototyp für die SwapBuffers-Funktion
typedef BOOL(WINAPI *PFNSWAPBUFFERS)(HDC hdc);
PFNSWAPBUFFERS originalSwapBuffers = nullptr;

// Hook-Funktion mit der gleichen Signatur wie SwapBuffers
BOOL WINAPI hookedSwapBuffers(HDC hdc) {
    // Benutzerdefinierter Code vor dem Aufruf der Originalfunktion
    // Zum Beispiel: Logging, Frame-Manipulation, etc.

    // Benutzerdefinierter Code vor dem Aufruf der Originalfunktion
    logMessage("SwapBuffers hook called");

    // Aufruf der originalen SwapBuffers-Funktion
    return originalSwapBuffers(hdc);
}

// Prototyp für die glBegin-Funktion
typedef void (APIENTRY* PFNGLBEGIN)(GLenum mode);
PFNGLBEGIN originalGlBegin = nullptr;

// Hook-Funktion mit der gleichen Signatur wie glBegin
void APIENTRY hookedGlBegin(GLenum mode) {
    // Benutzerdefinierter Code vor dem Aufruf der Originalfunktion
    logMessage("glBegin hook called");

    // Aufruf der originalen glBegin-Funktion
    originalGlBegin(mode);
}

void logPointer(const std::string& message, const void* ptr) {
    std::ostringstream stream;
    stream << message << ": " << std::hex << ptr;
    logMessage(stream.str());
}

void SetHook() {
    originalGlBegin = (PFNGLBEGIN)wglGetProcAddress("glBegin");
    if (originalGlBegin == NULL) {
        logMessage("Failed to get address of glBegin using wglGetProcAddress");
        HMODULE hMod = GetModuleHandle(L"opengl32.dll");
        originalGlBegin = (PFNGLBEGIN)GetProcAddress(hMod, "glBegin");
        if (originalGlBegin == NULL) {
            logMessage("Failed to get address of glBegin using GetProcAddress");
            return;
        }
        else {
            logPointer("Successfully hooked glBegin using GetProcAddress, address", originalGlBegin);
        }
    }
    else {
        logPointer("Successfully hooked glBegin using wglGetProcAddress, address", originalGlBegin);
    }

    // Hook setzen (IAT-Hooking oder andere Techniken)
    // ...
}

// DLL-Einstiegspunkt
BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved) {
    switch (ul_reason_for_call) {
    case DLL_PROCESS_ATTACH:
        clearLogFile();
        logMessage("DLL attached");
        // Deaktivieren Sie Thread-Benachrichtigungen für DLL_LOAD und DLL_UNLOAD
        DisableThreadLibraryCalls(hModule);
        // Setzen des Hooks
        SetHook();
        break;
    case DLL_PROCESS_DETACH:
        logMessage("DLL detached");
        // Entfernen des Hooks und Aufräumen
        // ...
        break;
    }
    return TRUE;
}