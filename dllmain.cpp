#include "pch.h"
#include <windows.h>
#include <gl/GL.h>
#include <gl/GLU.h>

#include <thread>
#include <chrono>

#include <fstream>
#include <unordered_set>
#include <mutex>
#include <sstream>

#include <thread>

#pragma comment(lib, "opengl32.lib")
#pragma comment(lib, "glu32.lib")

std::thread hookCheckThread;
bool hookCheckRunning = false;

std::unordered_set<std::string> logCache;
std::mutex logMutex;

void logMessage(const std::string& message) {
    std::lock_guard<std::mutex> lock(logMutex);
    std::ofstream logFile("C:\\Users\\jpsch\\Desktop\\C++\\OpenGLHookDLL\\loggingopengldll.txt", std::ios::app);
    if (logFile.is_open()) {
        logFile << message << std::endl;
        logFile.close();
    }
    logCache.insert(message);
}

void clearLogFile() {
    std::lock_guard<std::mutex> lock(logMutex);
    std::ofstream logFile("C:\\Users\\jpsch\\Desktop\\C++\\OpenGLHookDLL\\loggingopengldll.txt", std::ios::trunc);
    logFile.close();
    logCache.clear();
}

typedef BOOL(WINAPI* PFNSWAPBUFFERS)(HDC hdc);

typedef void (APIENTRY* PFNGLDRAWELEMENTS)(GLenum mode, GLsizei count, GLenum type, const void* indices);
typedef void (APIENTRY* PFNGLDRAWARRAYS)(GLenum mode, GLint first, GLsizei count);

PFNSWAPBUFFERS originalSwapBuffers = nullptr;

typedef void (APIENTRY* PFNGLCLEAR)(GLbitfield mask);
PFNGLCLEAR originalGlClear = nullptr;
PFNGLDRAWELEMENTS originalGlDrawElements = nullptr;
PFNGLDRAWARRAYS originalGlDrawArrays = nullptr;

#define HOOK_LENGTH 5
BYTE originalSwapBuffersBytes[HOOK_LENGTH] = { 0 };
BYTE originalGlClearBytes[HOOK_LENGTH] = { 0 };
BYTE originalGlDrawElementsBytes[HOOK_LENGTH] = { 0 };
BYTE originalGlDrawArraysBytes[HOOK_LENGTH] = { 0 };

BOOL WINAPI mySwapBuffers(HDC hdc) {
    logMessage("mySwapBuffers called. (1)");
    GLenum error = glGetError();
    if (error != GL_NO_ERROR) {
        logMessage("OpenGL error before mySwapBuffers: " + std::to_string(error));
    }
    else {
        logMessage("mySwapBuffers called. (2)");
    }
    logMessage("mySwapBuffers called. (3)");
    return originalSwapBuffers(hdc);
}

// Unsere gehookte Version von glClear
void APIENTRY myGlClear(GLbitfield mask) {
    // Protokollieren Sie den OpenGL-Zustand vor dem Aufruf von glClear
    GLenum error = glGetError();
    if (error != GL_NO_ERROR) {
        logMessage("OpenGL error before myGlClear: " + std::to_string(error));
    }
    else {
        // Protokollieren Sie den Aufruf von glClear mit dem mask-Wert
        std::ostringstream stream;
        stream << "myGlClear called with mask: " << std::hex << mask;
        logMessage(stream.str());
    }

    // Rufen Sie die ursprüngliche glClear Funktion auf
    originalGlClear(mask);
}

// Unsere gehookten Versionen von glDrawElements und glDrawArrays
void APIENTRY myGlDrawElements(GLenum mode, GLsizei count, GLenum type, const void* indices) {
    logMessage("myGlDrawElements called.");
    originalGlDrawElements(mode, count, type, indices);
}

void APIENTRY myGlDrawArrays(GLenum mode, GLint first, GLsizei count) {
    logMessage("myGlDrawArrays called.");
    originalGlDrawArrays(mode, first, count);
}

void HookFunction(PVOID* originalFunction, PVOID hookFunction, BYTE* originalBytes) {
    logMessage("Attempting to hook function.");
    DWORD oldProtect;
    if (VirtualProtect(originalFunction, HOOK_LENGTH, PAGE_EXECUTE_READWRITE, &oldProtect)) {
        logMessage("Memory protection changed.");
        memcpy(originalBytes, originalFunction, HOOK_LENGTH);
        DWORD offset = (DWORD)hookFunction - (DWORD)originalFunction - HOOK_LENGTH;
        BYTE jmp[HOOK_LENGTH] = { 0xE9 };
        *(DWORD*)(jmp + 1) = offset;
        memcpy(originalFunction, jmp, HOOK_LENGTH);
        if (VirtualProtect(originalFunction, HOOK_LENGTH, oldProtect, &oldProtect)) {
            logMessage("Function hooked successfully.");
        }
        else {
            logMessage("Failed to restore memory protection after hooking.");
        }
    }
    else {
        logMessage("Failed to change memory protection for hooking.");
    }
}

void destroyHook(PVOID* originalFunction, BYTE* originalBytes) {
    DWORD oldProtect;
    if (VirtualProtect(originalFunction, HOOK_LENGTH, PAGE_EXECUTE_READWRITE, &oldProtect)) {
        memcpy(originalFunction, originalBytes, HOOK_LENGTH);
        VirtualProtect(originalFunction, HOOK_LENGTH, oldProtect, &oldProtect);
        logMessage("Hook destroyed and original function restored.");
    }
    else {
        logMessage("Failed to change memory protection for destroying hook.");
    }
}

void SetInlineHook() {
    originalSwapBuffers = (PFNSWAPBUFFERS)GetProcAddress(GetModuleHandle(L"gdi32.dll"), "SwapBuffers");
    if (originalSwapBuffers == nullptr) {
        logMessage("Failed to get address of SwapBuffers.");
        return;
    }
    logMessage("Original SwapBuffers address obtained.");
    HookFunction((PVOID*)&originalSwapBuffers, mySwapBuffers, originalSwapBuffersBytes);

    originalGlClear = (PFNGLCLEAR)wglGetProcAddress("glClear");
    if (originalGlClear == nullptr) {
        HMODULE hModOpenGL = GetModuleHandle(L"opengl32.dll");
        if (hModOpenGL != nullptr) {
            originalGlClear = (PFNGLCLEAR)GetProcAddress(hModOpenGL, "glClear");
            if (originalGlClear == nullptr) {
                logMessage("Failed to get address of glClear using GetProcAddress.");
                return;
            }
            else {
                logMessage("Original glClear address obtained using GetProcAddress.");
            }
        }
        else {
            logMessage("Failed to get handle to opengl32.dll.");
            return;
        }
    }
    else {
        logMessage("Original glClear address obtained using wglGetProcAddress.");
    }
    HookFunction((PVOID*)&originalGlClear, myGlClear, originalGlClearBytes);


    originalGlDrawElements = (PFNGLDRAWELEMENTS)wglGetProcAddress("glDrawElements");
    if (originalGlDrawElements == nullptr) {
        logMessage("Failed to get address of glDrawElements.");
        return;
    }
    logMessage("Original glDrawElements address obtained.");
    HookFunction((PVOID*)&originalGlDrawElements, myGlDrawElements, originalGlDrawElementsBytes);

    originalGlDrawArrays = (PFNGLDRAWARRAYS)wglGetProcAddress("glDrawArrays");
    if (originalGlDrawArrays == nullptr) {
        logMessage("Failed to get address of glDrawArrays.");
        return;
    }
    logMessage("Original glDrawArrays address obtained.");
    HookFunction((PVOID*)&originalGlDrawArrays, myGlDrawArrays, originalGlDrawArraysBytes);

}

void ContinuousHookCheck() {
    logMessage("ContinuousHookCheck thread started.");
    SYSTEM_INFO si;
    GetSystemInfo(&si);
    DWORD pageSize = si.dwPageSize;

    while (hookCheckRunning) {
        if (originalSwapBuffers != nullptr) {
            DWORD oldProtect;
            LPVOID pageAlignedAddress = (LPVOID)((ULONG_PTR)originalSwapBuffers & ~(pageSize - 1));

            if (VirtualProtect(pageAlignedAddress, pageSize, PAGE_EXECUTE_READWRITE, &oldProtect)) {
                BYTE currentBytes[HOOK_LENGTH];
                memcpy(currentBytes, originalSwapBuffers, HOOK_LENGTH);

                if (memcmp(currentBytes, originalSwapBuffersBytes, HOOK_LENGTH) != 0) {
                    logMessage("Hook on SwapBuffers is gone, re-hooking...");
                    HookFunction((PVOID*)&originalSwapBuffers, mySwapBuffers, originalSwapBuffersBytes);
                }

                VirtualProtect(pageAlignedAddress, pageSize, oldProtect, &oldProtect);
            }
            else {
                DWORD error = GetLastError();
                std::ostringstream ss;
                ss << "Failed to change memory protection for reading. Error: " << error;
                logMessage(ss.str());
            }
        }
        else {
            logMessage("originalSwapBuffers is null, attempting to hook...");
            originalSwapBuffers = (PFNSWAPBUFFERS)GetProcAddress(GetModuleHandle(L"gdi32.dll"), "SwapBuffers");
            if (originalSwapBuffers != nullptr) {
                HookFunction((PVOID*)&originalSwapBuffers, mySwapBuffers, originalSwapBuffersBytes);
            }
            else {
                logMessage("Failed to get address of SwapBuffers.");
            }
        }
        std::this_thread::sleep_for(std::chrono::seconds(1)); // Check every second
    }
    logMessage("ContinuousHookCheck thread ended.");
}

// DLL-Einstiegspunkt
BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved) {
    switch (ul_reason_for_call) {
    case DLL_PROCESS_ATTACH:
        clearLogFile();
        logMessage("DLL_PROCESS_ATTACH: DLL attached.");
        DisableThreadLibraryCalls(hModule);
        // Setzen Sie hier Ihren initialen Hook
        hookCheckRunning = true;
        hookCheckThread = std::thread(ContinuousHookCheck);
        break;
    case DLL_PROCESS_DETACH:
        hookCheckRunning = false;
        if (hookCheckThread.joinable()) {
            hookCheckThread.join();
        }
        logMessage("DLL_PROCESS_DETACH: DLL detached.");
        // Entfernen Sie hier Ihren Hook
        break;
    }
    return TRUE;
}