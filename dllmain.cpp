#include "pch.h"
#include <windows.h>
#include <gl/GL.h>
#include <gl/GLU.h>

#include "thread"
#include "chrono"

#include "Windows.h"
#include "memoryapi.h"
#include <fstream>
#include <unordered_set>
#include <mutex>
#include <sstream>

std::unordered_set<std::string> logCache;
std::mutex logMutex;

void logMessage(const std::string& message) {
    std::lock_guard<std::mutex> lock(logMutex);

    // �berpr�fen, ob die Nachricht bereits geloggt wurde
    if (logCache.find(message) != logCache.end()) {
        return; // Bereits geloggt, nichts zu tun
    }

    // Nachricht in die Datei schreiben
    std::ofstream logFile("C:\\Users\\jpsch\\Desktop\\C++\\OpenGLHookDLL\\loggingopengldll.txt", std::ios::app);
    if (logFile.is_open()) {
        logFile << message << std::endl;
        logFile.close();
    }

    // Nachricht zum Cache hinzuf�gen
    logCache.insert(message);
}

void clearLogFile() {
    std::lock_guard<std::mutex> lock(logMutex);
    std::ofstream logFile("C:\\Users\\jpsch\\Desktop\\C++\\OpenGLHookDLL\\loggingopengldll.txt", std::ios::trunc);
    logFile.close();
    logCache.clear();
}

// Prototyp f�r die SwapBuffers-Funktion
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

// Prototyp f�r die glBegin-Funktion
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

void SetHook2() {
    // Versuch, die Adresse �ber wglGetProcAddress zu erhalten
    originalSwapBuffers = (PFNSWAPBUFFERS)GetProcAddress(GetModuleHandle(L"gdi32.dll"), "SwapBuffers");

    if (originalSwapBuffers == NULL) {
        logMessage("Failed to get address of SwapBuffers using wglGetProcAddress");

        // Fallback: Versuchen Sie es mit GetProcAddress, falls erforderlich
        HMODULE hGdiMod = GetModuleHandle(L"gdi32.dll");
        if (hGdiMod != NULL) {
            originalSwapBuffers = (PFNSWAPBUFFERS)GetProcAddress(hGdiMod, "SwapBuffers");
            if (originalSwapBuffers != NULL) {
                logPointer("Successfully hooked SwapBuffers using GetProcAddress from gdi32.dll, address", originalSwapBuffers);
            }
            else {
                logMessage("Failed to get address of SwapBuffers using GetProcAddress from gdi32.dll");
            }
        }
        else {
            logMessage("Failed to get handle to gdi32.dll");
        }
    }
    else {
        logPointer("Successfully hooked SwapBuffers using wglGetProcAddress, address", originalSwapBuffers);
    }

    // Hook setzen (IAT-Hooking oder andere Techniken)
    // ...
}

BOOL WINAPI mySwapBuffers(HDC hdc) {
    // Benutzerdefinierter Code
    return originalSwapBuffers(hdc);
}



// DLL-Einstiegspunkt
BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved) {
    switch (ul_reason_for_call) {
    case DLL_PROCESS_ATTACH:
        clearLogFile();
        logMessage("DLL attached");
        // Deaktivieren Sie Thread-Benachrichtigungen f�r DLL_LOAD und DLL_UNLOAD
        DisableThreadLibraryCalls(hModule);
        // Setzen des Hooks
        SetHook();
        SetHook2();
        break;
    case DLL_PROCESS_DETACH:
        logMessage("DLL detached");
        // Entfernen des Hooks und Aufr�umen
        // ...
        break;
    }
    return TRUE;
}