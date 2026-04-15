
```markdown
# BattlEye User-Mode Bypass – Research & Proof of Concept

![GitHub last commit](https://img.shields.io/badge/last%20commit-April%202026-blue) ![Research only](https://img.shields.io/badge/purpose-academic%20research-red) ![Windows](https://img.shields.io/badge/platform-Windows-lightgrey)

This repository documents and implements user-mode techniques to bypass BattlEye anti-cheat without loading any kernel drivers. The project is purely for educational research to understand how modern anti-cheat systems detect cheats and how those detections can be evaded using only user-mode privileges.

## Table of Contents

- [Background: How BattlEye Works](#background-how-battleye-works)
- [Why User-Mode?](#why-user-mode)
- [Detection Vectors](#detection-vectors)
- [Evasion Methods](#evasion-methods)
  - [Direct Syscalls](#direct-syscalls)
  - [Handle Duplication](#handle-duplication)
  - [Manual Mapping](#manual-mapping)
  - [Early Injection](#early-injection)
  - [Payload Encryption](#payload-encryption)
- [Architecture Overview](#architecture-overview)
- [Code Examples](#code-examples)
- [Useful Tools & Libraries](#useful-tools--libraries)
- [Building the PoC](#building-the-poc)
- [Limitations & Detection Risks](#limitations--detection-risks)
- [Disclaimer](#disclaimer)

## Background: How BattlEye Works

BattlEye is a kernel-level anti-cheat system used in many popular games: Rainbow Six Siege, ARMA 3, DayZ, Unturned, and others. It consists of two main components:

1. **Kernel Driver (`BEDaisy.sys`)** – Loads at system boot. It registers callbacks for process creation, thread creation, image loading, and object handle operations. It also implements memory scanning and integrity checks.

2. **User-Mode Service (`BEService.exe`)** – Communicates with the kernel driver and the game. It loads a DLL into the game process that hooks critical Windows API functions.

*BattlEye Architecture: user-mode hooks sit inside ntdll.dll intercepting API calls before they reach the kernel. The kernel driver monitors from below.*

## Why User-Mode?

Many cheat developers assume that bypassing a kernel anti-cheat requires a kernel driver. This is not always true. BattlEye's kernel driver is powerful, but its user-mode hooks are often the first line of detection. By avoiding those hooks entirely, you can stay under the radar without the complexity and risk of writing a kernel driver.

User-mode bypasses have several advantages:
- No driver signing or loading required
- No need to bypass PatchGuard or Kernel Patch Protection
- Easier to debug and test
- Lower risk of crashing the system

## Detection Vectors

BattlEye specifically looks for:

| Vector | Detection Method |
|--------|------------------|
| `OpenProcess` on the game | Hooks `NtOpenProcess` in ntdll, checks requested access flags |
| `WriteProcessMemory` | Hooks `NtWriteVirtualMemory`, scans written data for shellcode patterns |
| `CreateRemoteThread` | Hooks `NtCreateThreadEx`, flags remote thread creation as suspicious |
| `LoadLibrary` | Hooks `LdrLoadDll`, validates DLL signatures |
| Memory patterns | Kernel scans game memory for known cheat signatures |
| Open handles | Kernel callbacks detect any handle with `PROCESS_VM_WRITE` or `PROCESS_VM_OPERATION` |

*API Call Flow: Standard API calls hit hooks; direct syscalls bypass them entirely.*

## Evasion Methods

### Direct Syscalls

BattlEye places inline hooks in `ntdll.dll` functions like `NtOpenProcess`, `NtAllocateVirtualMemory`, `NtWriteVirtualMemory`, and `NtCreateThreadEx`. Calling these functions normally will hit the hook and trigger detection.

A direct syscall bypasses `ntdll` entirely. You write a small assembly stub that moves the syscall number into `EAX`/`RAX` and executes the `syscall` instruction. BattlEye cannot hook this because the hook lives in user-mode `ntdll`, not in the kernel.

**Syscall stub example (x64):**

```asm
NtAllocateVirtualMemory proc
    mov r10, rcx
    mov eax, 18h          ; syscall number for NtAllocateVirtualMemory (Windows 10 20H2)
    syscall
    ret
NtAllocateVirtualMemory endp
```

**Using it in C++:**

```cpp
typedef NTSTATUS (NTAPI *NtAllocateVirtualMemoryPtr)(
    HANDLE ProcessHandle,
    PVOID *BaseAddress,
    ULONG_PTR ZeroBits,
    PSIZE_T RegionSize,
    ULONG AllocationType,
    ULONG Protect
);

NtAllocateVirtualMemoryPtr NtAllocateVirtualMemory = (NtAllocateVirtualMemoryPtr)GetSyscallStub(0x18);
```

The syscall number varies between Windows builds. Production code should parse `ntdll.dll` at runtime to extract the correct number from the function's prologue.

### Handle Duplication

BattlEye blocks `OpenProcess` with `PROCESS_ALL_ACCESS`. But you don't need to open the game process yourself. Many legitimate processes already have a handle to the game – the game itself, Discord overlay, NVIDIA Share, or even the BattlEye service. You can steal an existing handle using `DuplicateHandle`.

**Steps:**

1. Enumerate all system handles using `NtQuerySystemInformation`
2. Find a handle to the game process with sufficient rights (`PROCESS_VM_OPERATION`, `PROCESS_VM_WRITE`, `PROCESS_VM_READ`)
3. Open the source process that owns that handle with `PROCESS_DUP_HANDLE`
4. Duplicate the handle into your own process

**Code snippet:**

```cpp
HANDLE hSource = OpenProcess(PROCESS_DUP_HANDLE, FALSE, sourcePid);
HANDLE hGame = NULL;
DuplicateHandle(hSource, (HANDLE)sourceHandleValue, GetCurrentProcess(), 
                &hGame, PROCESS_VM_OPERATION | PROCESS_VM_WRITE, 
                FALSE, 0);
```

Now you have a valid handle to the game without ever calling `OpenProcess` on the game directly.

### Manual Mapping

`LoadLibrary` and `LdrLoadDll` are heavily monitored. Manual mapping is a technique to load a DLL into a remote process without calling any loader API. You write a custom PE loader that:

1. Allocates memory in the target process
2. Copies the DLL headers and sections
3. Resolves imports by walking the Import Address Table
4. Applies relocations if the base address differs
5. Calls the DLL entry point with `DLL_PROCESS_ATTACH`

*Manual Mapping Flow: Avoid LoadLibrary hooks by manually reconstructing the DLL in memory.*

Import resolution must also avoid hooks on `GetProcAddress`. Use direct syscalls or parse `ntdll`'s export table manually.

### Early Injection

The most effective timing is to inject before BattlEye's user-mode service attaches to the game. Create the game process with the `CREATE_SUSPENDED` flag, perform your injection, then resume the main thread. BattlEye's user-mode hooks are not yet active because the service hasn't initialized. The kernel driver is running, but it relies on user-mode components for many detections.

**Code:**

```cpp
STARTUPINFOA si = { sizeof(si) };
PROCESS_INFORMATION pi;
CreateProcessA(gamePath, NULL, NULL, NULL, FALSE, 
               CREATE_SUSPENDED, NULL, NULL, &si, &pi);

// Inject payload via direct syscalls
// ...

ResumeThread(pi.hThread);
```

### Payload Encryption

Storing your payload on disk is dangerous. Encrypt it, then decrypt at runtime in memory. Execute directly from the decrypted buffer. This avoids signature scanning and static analysis.

**Simple XOR example:**

```cpp
unsigned char payload[] = { 0xAA, 0xBB, 0xCC, 0xDD };
unsigned char key = 0x55;

for (int i = 0; i < sizeof(payload); i++) {
    payload[i] ^= key;
}
// Execute payload as shellcode
```

For production, use AES-256 with a key derived from a system identifier (e.g., volume serial number). This ties the payload to a specific machine.

## Architecture Overview

The complete bypass tool consists of several components working together:

*Injector architecture: Direct syscalls for memory ops, handle duplication for process access, manual mapping for payload loading, and remote thread creation for execution.*

## Code Examples

### Complete injection routine using direct syscalls

```cpp
#include "syscalls.h"   // Generated by SysWhispers2

int main() {
    DWORD gamePid = FindProcessId(L"Game.exe");
    HANDLE hGame = GetDuplicatedHandle(gamePid);
    
    // Allocate memory in the game
    SIZE_T payloadSize = sizeof(shellcode);
    PVOID remoteMem = NULL;
    NTSTATUS status = NtAllocateVirtualMemory(
        hGame, &remoteMem, 0, &payloadSize, 
        MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE
    );
    
    // Write payload
    status = NtWriteVirtualMemory(
        hGame, remoteMem, shellcode, payloadSize, NULL
    );
    
    // Create remote thread to execute
    HANDLE hThread = NULL;
    status = NtCreateThreadEx(
        &hThread, THREAD_ALL_ACCESS, NULL, hGame, 
        remoteMem, NULL, FALSE, 0, 0, 0, NULL
    );
    
    return 0;
}
```

### Handle duplication implementation

```cpp
HANDLE GetDuplicatedHandle(DWORD targetPid) {
    // Enumerate handles (simplified - see full code for NtQuerySystemInformation)
    PSYSTEM_HANDLE_INFORMATION handleInfo = EnumerateHandles();
    
    for (DWORD i = 0; i < handleInfo->NumberOfHandles; i++) {
        SYSTEM_HANDLE_ENTRY entry = handleInfo->Handles[i];
        if (entry.UniqueProcessId == targetPid) continue;
        
        DWORD sourcePid = entry.UniqueProcessId;
        HANDLE hSource = OpenProcess(PROCESS_DUP_HANDLE, FALSE, sourcePid);
        
        HANDLE duplicated = NULL;
        BOOL success = DuplicateHandle(hSource, (HANDLE)entry.HandleValue,
                                        GetCurrentProcess(), &duplicated,
                                        PROCESS_VM_OPERATION | PROCESS_VM_WRITE,
                                        FALSE, 0);
        if (success && duplicated) {
            CloseHandle(hSource);
            return duplicated;
        }
        CloseHandle(hSource);
    }
    return NULL;
}
```

## Useful Tools & Libraries

- [SysWhispers2](https://github.com/jthuraisamy/SysWhispers2) – Generates header files for direct syscalls, including syscall numbers for multiple Windows versions.
- [BlackBone](https://github.com/DarthTon/Blackbone) – Comprehensive process manipulation library with manual mapping, injection, and memory operations.
- [MinHook](https://github.com/TsudaKageyu/minhook) – Minimalistic hooking library (useful if you need to hook game functions after injection).
- [AsmJit](https://github.com/asmjit/asmjit) – JIT assembler for generating native code at runtime.
- [DInvoke](https://github.com/TheWover/DInvoke) – Dynamic invocation for .NET-based injectors, avoids static imports.
- [Process Hacker](https://processhacker.sourceforge.io/) – For analyzing handle tables, memory regions, and debugging.

## Building the PoC

**Requirements:**
- Visual Studio 2022 with C++ development tools
- Windows SDK 10.0.20348.0 or later
- Windows 10/11 x64 (tested on 22H2)

**Steps:**

1. Clone the repository
2. Run `SysWhispers2` to generate syscall stubs for your Windows build
3. Open the solution in Visual Studio
4. Build in Release x64 configuration
5. Run the injector as administrator

**Important:** The syscall numbers are build-specific. Use the `GetSyscallNumber` utility included in the repo to extract numbers from your local `ntdll.dll`.

## Limitations & Detection Risks

No public bypass is permanent. BattlEye updates frequently. These techniques have been known for years, but they remain effective when combined properly. However, you should be aware of the following:

- **Syscall fingerprinting** – BattlEye can detect the presence of inline syscall stubs by scanning for the `syscall` instruction sequences in non-`ntdll` memory.
- **Handle duplication traces** – The kernel driver can log handle duplication events if it monitors `DuplicateHandle` calls.
- **Memory scan anomalies** – If your payload stays in memory after execution, it may be found by signature scans.
- **Behavioral analysis** – BattlEye may flag remote thread creation even via syscalls if the target address is outside known modules.

This PoC is for research. Do not expect it to remain undetected on live, updated versions of BattlEye.

## Disclaimer

This repository is for **educational and academic research purposes only**. The techniques shown are intended to help security researchers understand anti-cheat internals and develop better defenses.

- Do not use any code from this repository on live games without explicit permission from the game publisher.
- Unauthorized use violates terms of service and may result in permanent account and hardware bans.
- The author is not responsible for any damage, bans, or legal consequences resulting from misuse.

Testing must be conducted on offline, isolated systems with no network connectivity to game servers. Use the provided `_XXw2442` account suffix only if you have explicit written permission from BattlEye and the game publisher for supervised academic testing.

---

**Last updated:** April 2026  
**Research status:** Proof of concept for Windows 10/11 x64 against BattlEye versions up to April 2026.
```
