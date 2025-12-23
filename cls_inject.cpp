// NetHookInject.cpp : This file contains the 'main' function. Program execution begins and ends there.
//

#include <iostream>
#include <windows.h>
#include <stdio.h>
#include <tchar.h>
#include <psapi.h>

#include <fstream>

#include <vector>
using namespace std;

const char* MCC_PROC_STR = "mcc-win64-shipping.exe";
const char* MCC_ALT_PROC_STR = "MCC-Win64-Shipping.exe";
const char* INJECTED_MODULE_NAME = "NetHook.dll";
const char* INJECTED_MODULE_PATH = "D:\\Projects\\VS\\NetHookInject\\x64\\Release\\NetHook.dll";

#include <string>

HANDLE find_process(const char* target_process, HMODULE* previous_injection) {

    DWORD proc_id_array[1024], cbNeeded;
    if (!EnumProcesses(proc_id_array, sizeof(proc_id_array), &cbNeeded)) {
        cout << "[INIT] couldn't find target process: failed to enumerate.\n";
        return 0;
    }

    HANDLE process_id;
    DWORD processes_count = cbNeeded / sizeof(DWORD);
    for (DWORD i = 0; i < processes_count; i++) {
        if (!proc_id_array[i]) continue;

        //process_id = OpenProcess(PROCESS_VM_OPERATION | PROCESS_QUERY_INFORMATION | PROCESS_VM_READ | PROCESS_VM_WRITE, FALSE, proc_id_array[i]);
        process_id = OpenProcess(PROCESS_ALL_ACCESS, FALSE, proc_id_array[i]);
        if (!process_id) continue;

        HMODULE modules_array[256];
        DWORD mods_buffersize_used;
        if (EnumProcessModules(process_id, modules_array, sizeof(modules_array), &mods_buffersize_used)) {

            // if current process matches target process by name
            char process_name[MAX_PATH];
            GetModuleBaseNameA(process_id, modules_array[0], process_name, sizeof(process_name));
            if (strcmp(process_name, target_process)) continue;

            // iterate through the rest of the modules to see if ours is already injected
            int modules_count = mods_buffersize_used / sizeof(HMODULE);
            for (int j = 1; j < modules_count; j++) {
                GetModuleBaseNameA(process_id, modules_array[j], process_name, sizeof(process_name));
                if (!strcmp(process_name, INJECTED_MODULE_NAME))
                    *previous_injection = modules_array[j];
            }
            return process_id;
        }

        CloseHandle(process_id);
    }
    return 0;
}

HMODULE inject_dll(HANDLE process_id, const char* dll_path, const char* dll_name) {

    LPVOID path_str_ptr = VirtualAllocEx(process_id, 0, strlen(dll_path) + 1, MEM_COMMIT, PAGE_READWRITE);
    if (!path_str_ptr) {
        cout << "[INIT] could not allocate path string memory.\n";
        return 0;}

    if (!WriteProcessMemory(process_id, path_str_ptr, dll_path, strlen(dll_path) + 1, NULL)) {
        cout << "[INIT] could not write to path string memory.\n";
        VirtualFreeEx(process_id, path_str_ptr, 0, MEM_RELEASE);
        return 0;}

    HANDLE hThread = CreateRemoteThread(process_id, NULL, 0, (LPTHREAD_START_ROUTINE)GetProcAddress(GetModuleHandleA("kernel32.dll"), "LoadLibraryA"), path_str_ptr, 0, NULL);
    if (!hThread) {
        cout << "[INIT] could not create remote thread.\n";
        VirtualFreeEx(process_id, path_str_ptr, 0, MEM_RELEASE);
        return 0;}

    WaitForSingleObject(hThread, INFINITE);
    VirtualFreeEx(process_id, path_str_ptr, 0, MEM_RELEASE);
    CloseHandle(hThread);

    // then we get the module 
    HMODULE modules_array[256];
    DWORD mods_buffersize_used;
    if (!EnumProcessModules(process_id, modules_array, sizeof(modules_array), &mods_buffersize_used)) {
        cout << "[INIT] could not iterate modules.\n";
        return 0;}

    // if current process matches target process by name
    char process_name[MAX_PATH];
    // iterate through modules to find matching
    int modules_count = mods_buffersize_used / sizeof(HMODULE);

    HMODULE hooked_dll = 0; // invalid pointer becuase its memory belongs to the other process
    for (int j = 1; j < modules_count; j++) {
        GetModuleBaseNameA(process_id, modules_array[j], process_name, sizeof(process_name));
        if (!strcmp(process_name, dll_name))
            hooked_dll = modules_array[j];}

    if (hooked_dll) return hooked_dll;
    cout << "[INIT] could not find our module via iteration.\n";
    return 0;
}

int main() {
    std::cout << "[INIT] Hello World!\n";
    while (true) {
        HANDLE proc_id;
        HMODULE previous_injection;
        while (true) {
            previous_injection = 0;
            proc_id = find_process(MCC_PROC_STR, &previous_injection);
            if (proc_id) break;
            proc_id = find_process(MCC_ALT_PROC_STR, &previous_injection);
            if (proc_id) break;

            Sleep(500);
            cout << "[INIT] could not find process.\n";
        }

        // return if already injected
        if (previous_injection) {
            cout << "[INIT] dll already injected.\n";
            return -1;}

        // inject
        if (!inject_dll(proc_id, INJECTED_MODULE_PATH, INJECTED_MODULE_NAME)) {
            cout << "[INIT] dll injection failed.\n";
            return -1;}

        cout << "[INIT] dll injection failed.\n";
        return 0;
    }
}
