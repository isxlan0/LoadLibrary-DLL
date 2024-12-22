#include <windows.h>
#include <shlobj.h>
#include <shlwapi.h>
#include <iostream>
#include <fstream>
#include "cJSON\cJSON.h"

#pragma comment(lib, "shlwapi.lib")

std::string Getthecleanprogram() {
    char path[MAX_PATH];
    GetModuleFileNameA(nullptr, path, MAX_PATH);
    PathRemoveExtensionA(path);
    return std::string(path);
}

std::string SelectFile(const char* filter, const char* title) {
    char filePath[MAX_PATH] = { 0 };
    OPENFILENAMEA ofn = { 0 };
    ofn.lStructSize = sizeof(ofn);
    ofn.hwndOwner = nullptr;
    ofn.lpstrFilter = filter;
    ofn.lpstrFile = filePath;
    ofn.nMaxFile = MAX_PATH;
    ofn.Flags = OFN_FILEMUSTEXIST | OFN_PATHMUSTEXIST;
    ofn.lpstrTitle = title;

    if (GetOpenFileNameA(&ofn)) {
        return std::string(filePath);
    }
    return "";
}

bool Checkifafileexists(const std::string& path) {
    return PathFileExistsA(path.c_str()) == TRUE;
}

bool JSONparsing(const std::string& jsonFilePath, std::string& dllPath, std::string& processPath) {
    std::ifstream file(jsonFilePath);
    if (!file.is_open()) {
        return false;
    }

    std::string content((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());
    file.close();

    cJSON* root = cJSON_Parse(content.c_str());
    if (!root) {
        return false;
    }

    cJSON* dllNode = cJSON_GetObjectItem(root, "dll_path");
    cJSON* processNode = cJSON_GetObjectItem(root, "process_path");

    if (!dllNode || !processNode || !cJSON_IsString(dllNode) || !cJSON_IsString(processNode)) {
        cJSON_Delete(root);
        return false;
    }

    dllPath = dllNode->valuestring;
    processPath = processNode->valuestring;

    cJSON_Delete(root);
    return Checkifafileexists(dllPath) && Checkifafileexists(processPath);
}

bool JSONparsingwrite(const std::string& jsonFilePath, const std::string& dllPath, const std::string& processPath) {
    cJSON* root = cJSON_CreateObject();
    cJSON_AddStringToObject(root, "dll_path", dllPath.c_str());
    cJSON_AddStringToObject(root, "process_path", processPath.c_str());

    char* jsonString = cJSON_Print(root);
    std::ofstream file(jsonFilePath);
    if (!file.is_open()) {
        free(jsonString);
        cJSON_Delete(root);
        return false;
    }

    file << jsonString;
    file.close();

    free(jsonString);
    cJSON_Delete(root);
    return true;
}

void createSuspendedProcessAndInject(const std::string& processPath, const std::string& dllPath) {
    STARTUPINFOA si = { sizeof(STARTUPINFOA) };
    PROCESS_INFORMATION pi = { 0 };

    if (!CreateProcessA(processPath.c_str(), nullptr, nullptr, nullptr, FALSE, CREATE_SUSPENDED, nullptr, nullptr, &si, &pi)) {
        std::cerr << "Failed to create process." << std::endl;
        return;
    }

    LPVOID remoteMemory = VirtualAllocEx(pi.hProcess, nullptr, dllPath.size() + 1, MEM_COMMIT, PAGE_READWRITE);
    if (!remoteMemory) {
        std::cerr << "Failed to allocate memory in target process." << std::endl;
        TerminateProcess(pi.hProcess, 0);
        CloseHandle(pi.hThread);
        CloseHandle(pi.hProcess);
        return;
    }

    if (!WriteProcessMemory(pi.hProcess, remoteMemory, dllPath.c_str(), dllPath.size() + 1, nullptr)) {
        std::cerr << "Failed to write DLL path to target process." << std::endl;
        TerminateProcess(pi.hProcess, 0);
        CloseHandle(pi.hThread);
        CloseHandle(pi.hProcess);
        return;
    }

    HANDLE thread = CreateRemoteThread(pi.hProcess, nullptr, 0, (LPTHREAD_START_ROUTINE)LoadLibraryA, remoteMemory, 0, nullptr);
    if (!thread) {
        std::cerr << "Failed to create remote thread in target process." << std::endl;
        TerminateProcess(pi.hProcess, 0);
        CloseHandle(pi.hThread);
        CloseHandle(pi.hProcess);
        return;
    }

    ResumeThread(pi.hThread);
    CloseHandle(thread);
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
}

int main() {
    std::string programName = Getthecleanprogram();
    std::string jsonFilePath = programName + ".json";

    std::string dllPath, processPath;
    if (!JSONparsing(jsonFilePath, dllPath, processPath)) {
        std::cout << "Select DLL file:" << std::endl;
        dllPath = SelectFile("Dynamic Link Library (*.dll)\0*.dll\0", "Select the Dynamic Link Library to load");
        if (dllPath.empty() || !Checkifafileexists(dllPath)) {
            std::cerr << "Invalid DLL file." << std::endl;
            return 1;
        }

        std::cout << "Select process executable:" << std::endl;
        processPath = SelectFile("Executable Files (*.exe)\0*.exe\0", "Select Executable Files to load");
        if (processPath.empty() || !Checkifafileexists(processPath)) {
            std::cerr << "Invalid process executable." << std::endl;
            return 1;
        }

        if (!JSONparsingwrite(jsonFilePath, dllPath, processPath)) {
            std::cerr << "Failed to write JSON file." << std::endl;
            return 1;
        }
    }

    createSuspendedProcessAndInject(processPath, dllPath);
    std::cout << "Process started and DLL injected successfully." << std::endl;
    return 0;
}
