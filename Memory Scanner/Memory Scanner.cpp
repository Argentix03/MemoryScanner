//  Memscan - A memory scanner
//  
//  Where was I: 
//  Finished making a WPM loop and for 'freeze' and it works well on small program. wanted to see if it works on elden ring and whats the right timing.
//  for now its set for 16ms which should be around 60 fps so im expecting 50/50 battle with the GUI when testing on the UI address for xp.
//  was gonna implement a singlular wpm that will support all data sizes so it doesnt cause memory corruption for overwriting bigger than intened values.
//  and use that also for option 'write to address' in the UI.

#include <Windows.h>
#include <Psapi.h>
#include <stdio.h>
#include <Shlwapi.h>
#include "memscan.h"
#include <conio.h>
#include <winternl.h>
#include <unordered_set>  // fkin tired of linked lists
#pragma comment(lib, "Shlwapi.lib")

// globals

// flag used to discard unwritable memory (not that we technically cant write to it but that its probably not a value in the game we care about changing)
// literal strings and resources may be here, code. might seperate this later to a choice of RO/RW/X etc.
bool writable_only;
bool debug;
int memblock_counter = 0;
int shortcut_counter = 0;
long long int matchCounter = 0;
Node* g_savedMatches;
HOTKEY* shortcuts[5];
HANDLE hotkeysReadyEvent;
HANDLE freezeEvent;
HANDLE unfreezeEvent;
CRITICAL_SECTION cs;
CRITICAL_SECTION csFreezer;

// add commit type (mapped/image/private)
// Convert MEMORY_BASIC_INFORMATION.Protect into comfy string representation.
// Return a pointer to a newly allocated string (that will probably never be freed).
char* getStringProtection(DWORD protection)
{
    // Constants defined as DWORD in winnt.h, more information can be found at:
    // https://learn.microsoft.com/en-us/windows/win32/memory/memory-protection-constants
    char buf[70];
    char* protection_string = (char*)calloc(sizeof(char), sizeof(buf));
    DWORD protection_extra;
    if (!protection) {
        strcpy_s(buf, "No query permission");
        strcpy_s(protection_string, sizeof(buf), buf);
        return protection_string;
    }

    strcpy_s(buf, "");
    protection_extra = protection;
    protection &= 0xff;
    if (protection == PAGE_EXECUTE) // 0x10
        strcat_s(buf, "X");
    else if (protection == PAGE_EXECUTE_READ) // 0x20
        strcat_s(buf, "RX");
    else if (protection == PAGE_EXECUTE_READWRITE) // 0x40
        strcat_s(buf, "RWX");
    else if (protection == PAGE_EXECUTE_WRITECOPY) // 0x80
        strcat_s(buf, "WCX");
    else if (protection == PAGE_NOACCESS) // 0x01
        strcat_s(buf, "NA");
    else if (protection == PAGE_READONLY) // 0x02
        strcat_s(buf, "R");
    else if (protection == PAGE_READWRITE) // 0x04
        strcat_s(buf, "RW");
    else if (protection == PAGE_WRITECOPY) // 0x08
        strcat_s(buf, "WC");
    else if (protection == PAGE_TARGETS_INVALID) // 0x40000000 (CFG Stuff)
        strcat_s(buf, "CFG Stuff");
    else if (protection == PAGE_TARGETS_NO_UPDATE) // 0x40000000 (CFG Stuff)
        strcat_s(buf, "CFG Stuff");

    // Extra protections
    if (protection_extra & PAGE_GUARD) // 0x100
        strcat_s(buf, "+G");
    else if (protection_extra & PAGE_NOCACHE) //0x200
        strcat_s(buf, "+NOCACHE");
    else if (protection_extra & PAGE_WRITECOMBINE) // 0x400
        strcat_s(buf, "+WRITECOMBINE");

    strcpy_s(protection_string, sizeof(buf), buf);
    return protection_string;
}

// Convert MEMORY_BASIC_INFORMATION.State into comfy string representation.
// Return a pointer to a newly allocated string.
char* getStringState(const DWORD state)
{
    char buf[50];
    char* memory_state = (char*)calloc(sizeof(char), sizeof(buf));
    strcpy_s(buf, "");
    if (state == MEM_COMMIT) // 0x1000
        strcat_s(buf, "MEM_COMMIT");
    else if (state == MEM_FREE) // 0x10000
        strcat_s(buf, "MEM_FREE");
    else if (state == MEM_RESERVE) // 0x2000
        strcat_s(buf, "MEM_RESERVE");

    strcpy_s(memory_state, sizeof(buf), buf);
    return memory_state;
}

// Convert MEMORY_BASIC_INFORMATION.Type into comfy string representation.
// Return a pointer to a newly allocated string.
char* getStringType(DWORD memType)
{
    char buf[50];
    char* memory_type = (char*)calloc(sizeof(char), sizeof(buf));
    strcpy_s(buf, "");
    if (memType == MEM_PRIVATE) // 0x20000
        strcat_s(buf, "Private");
    else if (memType == MEM_MAPPED) // 0x40000
        strcat_s(buf, "Mapped");
    else if (memType == MEM_IMAGE) // 0x1000000
        strcat_s(buf, "Image");

    strcpy_s(memory_type, sizeof(buf), buf);
    return memory_type;
}

// Convert Region start address into comfy string representation of what its used for.
// Return a pointer to a newly allocated string (might be empty if nothing was found).
WCHAR* getStringUse(MBLOCK* mb)
{   
    if (mb->mbi.Type == MEM_IMAGE) {
        WCHAR* modulePath = (WCHAR*)calloc(sizeof(WCHAR), MAX_PATH);
        DWORD dwSize = MAX_PATH;
        GetModuleFileNameEx(mb->hProc, (HMODULE)mb->mbi.AllocationBase, modulePath, dwSize);  // if doesnt work well maybe can try mbi.allocationBase

        return modulePath;
    }

    return (WCHAR*)L"";
}

// Creates a new memblock 
// Return a pointer to a newly allocated memblock
MBLOCK* createMemBlock(HANDLE hProc, MEMORY_BASIC_INFORMATION meminfo)
{
    MBLOCK* mb = (MBLOCK*)malloc(sizeof(MBLOCK));
    if (mb) {
        ++memblock_counter;
        mb->id = memblock_counter;
        mb->addr = meminfo.BaseAddress;
        mb->hProc = hProc;
        mb->size = meminfo.RegionSize;
        mb->buffer = malloc(meminfo.RegionSize);
        // actually insert data to the buffer
        mb->mbi = meminfo;

        // insert region data into memblock's buffer
        SIZE_T bytesRead;
        if (!ReadProcessMemory(hProc, meminfo.BaseAddress, mb->buffer, meminfo.RegionSize, &bytesRead)) {
            if (GetLastError() != 299)
                printf("Error ReadProcessMemory: %d\n%ls\n", GetLastError(), getLastErrorStr());
        }
    }

    return mb;
}


void printMemblockBuffer(int memblock_id, MBLOCK* memlist)
{
    printf("Printing memory block: %d\n", memblock_id);
    BYTE membyte;
    MBLOCK* mb = memlist;

    while (mb) {
        if (mb->id == memblock_id)
            printBuffer(mb);
        mb = mb->next;
    }

    return;
}

void searchWideChar(MBLOCK* memlist, const WCHAR pattern[], int pattern_len, Node* matches)
{
    printf("searching for pattern: %ws\n", pattern);
    MBLOCK* mb = memlist;
    while (mb) {
        long long int membyte = (long long int) mb->buffer;
        long long int finalAddr = ((long long int)mb->buffer) + mb->size;
        while (membyte <= finalAddr) {
            if (matchPatternWideChar(membyte, pattern, pattern_len)) {
                printf("Memblock id: %d\n", mb->id);
                printf("Memblock address: 0x%llx\n", membyte);
                printf("content: %ws\n", (WCHAR *) membyte);

                MATCH* newMatch = (MATCH *) malloc(sizeof(MATCH));
                const long long int offset = membyte - (long long int) (mb->buffer);
                const long long int remote_address = (long long int) mb->addr + offset;
                newMatch->address = (PVOID) remote_address;
                newMatch->memblock_id = mb->id;
                newMatch->memblock = mb;
                insertMatch(newMatch, matches);
            }

            ++membyte;
        }

        mb = mb->next;
    }

    return;
}

// Find matches for a value. filters through all memblock of a given memlist to fill in a given matches list. 
// Sequential filters (indicated by a NULL memlist) filters a given matches list against target process memory.
Node* filterAddresses(MBLOCK* memlist, uintptr_t value, HUNTING_TYPE dataType, int data_len, Node* matches)
{
    bool matched = 0;

    //if (memlist)
    //    printf("searching for value: ");
    //else
    //    printf("filtering matches for value: ");
    //printValue(dataType, value);
    //putchar('\n');

    // filter on given matches
    if (!memlist) {
        Node* head = matches;
        Node* curr = head;
        Node* tmp;
        int size = getSizeForType(dataType);
        uintptr_t remote_value;
        while (curr != nullptr) {
            MATCH* match = curr->match;
            if (!ReadProcessMemory(match->memblock->hProc, match->address, &remote_value, size, NULL)) {
                if (!(GetLastError() == 299))
                    printf("Error reading updated value of match: %p\nError id: %d\nError msg: %ls\n", match->address, GetLastError(), getLastErrorStr());
            }

            switch (dataType)
            {
                // maybe can use memcmp() instead of casting to types?
            // This would not work for float!
            case type_byte:
                matched = (BYTE)remote_value == (BYTE)value; // 1 Byte unsigned
                break;
            case type_char:
                matched = (char)remote_value == (char)value; // 1 Byte signed
                break;
            case type_float:
                matched = (float)remote_value == (float)value; // 4 Byte floating point
                break;
            case type_double:
                matched = (double)remote_value == (double)value; // 8 Byte floating point
                break;
            case type_short:
                matched = (short)remote_value == (short)value; // 2 Byte signed
                break;
            case type_int:
                matched = (int)remote_value == (int)value; // 4 Byte signed
                break;
            case type_long_long_int:
                matched = (long long int)remote_value == (long long int)value; // 8 Byte signed
                break;
            case type_pointer:
                matched = (uintptr_t)remote_value == (uintptr_t)value; // 8 Byte signed
                break;
            }

            curr = curr->next;
            if (!matched) {
                matches = removeMatch(match, matches);
            }
        }
    }
    // search all scan results and add to given matches
    else {
        MBLOCK* mb = memlist;
        HUNTING_TYPE type;
        while (mb) {
            long long int membyte = (long long int) mb->buffer;
            long long int finalAddr = ((long long int)mb->buffer) + mb->size;

            while (membyte <= finalAddr) {
                switch (dataType)
                {
                    // This would not work for float!
                case type_byte:
                    matched = (*((BYTE*)membyte) == (BYTE)value); // 1 Byte unsigned
                    type = type_byte;
                    break;
                case type_char:
                    matched = (*((char*)membyte) == (char)value); // 1 Byte signed
                    type = type_char;
                    break;
                case type_float:
                    matched = (*((float*)membyte) == (float)value); // 4 Byte floating point
                    type = type_float;
                    break;
                case type_double:
                    matched = (*((double*)membyte) == (double)value); // 8 Byte floating point
                    type = type_double;
                    break;
                case type_short:
                    matched = (*((short*)membyte) == (short)value); // 2 Byte signed
                    type = type_short;
                    break;
                case type_int:
                    matched = (*((int*)membyte) == (int)value); // 4 Byte signed
                    type = type_int;
                    break;
                case type_long_long_int:
                    matched = (*((long long int*)membyte) == (long long int)value); // 8 Byte signed
                    type = type_long_long_int;
                    break;
                case type_pointer:
                    matched = (*((uintptr_t*)membyte) == (uintptr_t)value); // 8 Byte signed
                    type = type_pointer;
                    break;
                }
                if (matched) {
                    MATCH* newMatch = (MATCH*)malloc(sizeof(MATCH));
                    long long int offset = membyte - (long long int) (mb->buffer);
                    long long int remote_address = (long long int) mb->addr + offset;
                    const bool isStatic = StrCmpW(L"", getStringUse(mb));
                    long long id = matchCounter++;
                    newMatch->id;
                    newMatch->address = (PVOID)remote_address;
                    newMatch->memblock_id = mb->id;
                    newMatch->memblock = mb;
                    newMatch->isStatic = isStatic;
                    newMatch->type = type;
                    newMatch->pointTotype = type_null;
                    newMatch->freeze = nullptr;
                    matches = insertMatch(newMatch, matches);
                }

                ++membyte;
            }

            mb = mb->next;
        }
    }

    return matches;
}

bool matchValue(long long int addr, int value, int pattern_len)
{
    int matching = 0;
    --pattern_len;
    for (int i = 0; i <= pattern_len; ++i) {
        if (*((int*)addr + i) != value)
            return false;
        else
            matching++;
    }

    return true;
}

void printValue(int dataType, uintptr_t value)
{
    switch (dataType)
    {
    case type_byte:
        printf("%02x", (BYTE) value);
        break;
    case type_char:    
        printf("%c", (char) value);
        break;
    case type_float:
    case type_double:
        printf("%f", (double)value);
        break;
    case type_short:
        printf("%hd", (short)value);
        break;
    case type_int:
        printf("%d", (int)value);
        break;
    case type_long_long_int:
        printf("%lli", (long long int)value);
        break;
    case type_pointer:
        printf("0x%p", (uintptr_t)value);
        break;
    }
}

// basically matches wide strings
bool matchPatternWideChar(long long int addr, const WCHAR pattern[], int pattern_len)
{
    int matching = 0;
    for (int i = 0; i <= pattern_len; ++i) {
        if (*((WCHAR*)addr + i) != pattern[i])
            return false;
        else
            matching++;
    }

    return true;
}

// print hexdump of a single memblock's buffer
void printBuffer(MBLOCK* mb)
{
    printf("Memblock id: %d\nBuffer:\n", mb->id);
    long long int membyte = (long long int) mb->buffer;
    long long int finalAddr = ((long long int)mb->buffer) + mb->size;
    while (membyte <= finalAddr) {
        printf("%02x ", *(BYTE *)membyte);
        ++membyte;
    }
    printf("\n");

    return;
}

// free blocks.
void freeMemBlock(const MBLOCK* mb)
{
    if (!mb)
        return;

    if (mb->buffer) {
        free(mb->buffer);
    }
}

// starts a scan. scans through a full process' (committed) memory.
// returns memlist - first member of the linked-list of memblocks created in the scan.
MBLOCK* startScan(int pid)
{
    MBLOCK* memlist = NULL;
    MEMORY_BASIC_INFORMATION mbi;
    PVOID addr = 0;
    memblock_counter = 0; // reset the memblock counter as no more than 1 scan at a time is supported for now
    // Reason it is not PROCESS_ALL_ACCESS because i like to learn about memory access in windows from access denied errors
    DWORD dwDesiredAccess = PROCESS_VM_READ | PROCESS_QUERY_INFORMATION | PROCESS_SUSPEND_RESUME | PROCESS_VM_WRITE;

    HANDLE hProc = OpenProcess(dwDesiredAccess, false, pid);
    if (!hProc) {
        printf("Error open process handle: %d\n%ws\n", GetLastError(), getLastErrorStr());
        return nullptr;
    }

    do {
        // query a memory region and 
        VirtualQueryEx(hProc, addr, &mbi, sizeof(mbi));
        if (debug)
            printf("VirtualQuery: %p\n", addr);

        // skip if memory not committed or writable flag set and memory isn't writable
        const bool mem_committed = mbi.State & MEM_COMMIT;
        const bool mem_writable = mbi.Protect & WRITEABLE_MEM;
        if (mem_committed && (!writable_only || mem_writable)) {
            // save info to memblock and add memblock to the list
            MBLOCK* memblock = createMemBlock(hProc, mbi);
            if (!memblock) {
                printf("Error creating memblock: %d\n%ws\n", GetLastError(), getLastErrorStr());
                return memlist;
            }
            memblock->next = memlist;
            memlist = memblock;
        }
        else {
            if (debug) {
                if (!mem_committed)
                    printf("Skipping uncommitted memory: %p\n", addr);
                if (!mem_writable)
                    printf("Skipping unwritable memory: %p\n", addr);
            }
        }

        // move on to the next region
        addr = (BYTE*)(mbi.BaseAddress) + mbi.RegionSize;
    } while (VirtualQueryEx(hProc, addr, &mbi, sizeof(mbi)));

    return memlist;
}

// free all memblocks in a memlist 
void closeScan(MBLOCK* memlist)
{
    // Free all memblocks
    do {
	    const MBLOCK* mb = memlist;
        freeMemBlock(mb);
        if (!memlist->next)
            CloseHandle(memlist->hProc);  // same handle for the whole memlist
    } while (memlist = memlist->next);

    // Unfreeze all frozen matches
    Node* curr = g_savedMatches;
    while (curr) {
        unfreezeAddress(curr->match);
        curr = curr->next;
    }

    return;
}

// print all memblocks in a memlist including metadata
void printScan(MBLOCK* memlist)
{
    MBLOCK* mb = memlist;
    printf("%-4s\t%-18s\t%16s\t%-20s\t%-14s\t%s\n","ID", "Address", "Size","Type:State","Permissions", "Use");
    printf("---------------------------------------------------------------------------------------------------\n");

    while (mb) {
        printMemblock(mb, FALSE);
        mb = mb->next;
    }

    return;
}

void printMemblock(MBLOCK* mb, const bool print_memory)
{
	const unsigned long int size_kb = mb->size >> 10;
	const PVOID addr = mb->addr;
    const char* mem_state = getStringState(mb->mbi.State);
    const char* mem_type = getStringType(mb->mbi.Type);
    const char* mem_protect = getStringProtection(mb->mbi.Protect);
    const WCHAR* mem_use = getStringUse(mb);
    printf("%-4d\t", mb->id);
    printf("0x%-18p\t\t", addr);
    printf("%5lu KB\t", size_kb);
    printf("%-7s: %-5s\t", mem_type, mem_state);
    printf("%-14s\t", mem_protect);
    printf("%ls\n", mem_use);

    if (print_memory)
        printBuffer(mb);

    return;
}

// This one is insanely good...
WCHAR* getLastErrorStr()
{
    WCHAR* buf = (WCHAR*) malloc(sizeof(WCHAR) * 256);
    FormatMessageW(
        FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
        nullptr, GetLastError(), MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
        buf, 256, nullptr
    );

    return buf;
}

int main(int argc, char** argv)
{
    writable_only = false;
    debug = false;
    for (int i = 1; i < argc; ++i) {
        if (!strcmp(argv[i], "-writable_mem"))
            writable_only = true;
        else if(!strcmp(argv[i], "-debug"))
            debug = true;
    }

    // listener and handler for shortcuts 
    InitializeCriticalSection(&cs);
    HANDLE hThread = CreateThread(
	    nullptr,            // default security attributes
        0,                  // use default stack size  
        shortcutHandler,    // thread function name
        shortcuts,          // argument to thread function 
        0,                  // use default creation flags
        nullptr
    );

    // main UI loop - plan is to eventually seperate code into a library and a UI application
    // but for now its way easier to test everything and come up with ideas for what is nice to have
    // by using the UI so no point in seperating them yet
    mainMenuUI();

    return 0;
}

void mainMenuUI()
{
    int userChoice;
    while (true) {
        printf(
            "\nEnter your choice:\n"
            "1: New Scan\n"
            "2: Quit\n"
        );
        scanf_s("%d", &userChoice);

        switch (userChoice)
        {
        case 1:
        {
            const int result = newScanUI();
            if (!result) {
                printf("newScanUI return fail status. maybe run as admin\n");
                continue; // back to loop
            }
            break;
        }
        case 2:
            exit(0);
        default:;
        }
    }
}

void printUsageAndExit()
{
    printf("Usage: memscan.exe <-pid PID> [-writable_mem] [-debug]\n");
    printf("Example: memscan.exe -pid 1785 -writable_mem -debug\n");
    exit(1);
}

// takes pointer to allocated struct with address and action
DWORD WINAPI freezeHandler(LPVOID lpFreezeRequest)
{
    // How fast to spam WPM
    int msWait = 16;  // 60 FPS
    FreezeRequest* fr = (FreezeRequest*)lpFreezeRequest;
    DWORD waitResult;
    
    // Loop spam WPM breaks on unfreeze signal
    while (true) {

        // Override address with value
        // Functionilize this for a single write and make sure to handle all data types!!
        uintptr_t value = fr->value;  // for now this corrupts the stack when written on a small stack variable (with the size of uintptr_t)
        if (!WriteProcessMemory(fr->hProc, (LPVOID) fr->address, &value, sizeof(value), nullptr)) {
            // this is VERY spammy but it shows me where i forgot to close handles or something about memory permissions changing
            printf("Error writing value 0x%x to address: %lp\nError id: %lu\nError msg: %ls\n", fr->value, fr->address, GetLastError(), getLastErrorStr());
        }

        // Check for unfreeze (also count as the sleep to throttle some WPM spam)
        waitResult = WaitForSingleObject(fr->unfreeze_event, msWait);
        if (waitResult == WAIT_TIMEOUT)
            continue;
        else if (waitResult == WAIT_OBJECT_0) // Unfreeze was signled
            break; 
        else {
            printf("Unexpected results from WaitForSingleObject: 0x%x\nError id: %d\nError msg: %ls\n", waitResult, GetLastError(), getLastErrorStr());
            break;
        }
    }

    return 1;
}

DWORD WINAPI shortcutHandler(LPVOID lpParam)
{
    MSG msg;
    HOTKEY* shortcut;
    bool toggle = true;
    WaitForSingleObject(hotkeysReadyEvent, INFINITE);
    while (true) {
        // check if shortcuts needs setting/resetting
        for (int i = 0; i < shortcut_counter; i++) {
            if (shortcuts[i]->reset) {
                EnterCriticalSection(&cs);
                shortcut = shortcuts[i];
                DWORD MODS = MOD_NOREPEAT;
                if (shortcut->CTRL)
                    MODS |= MOD_CONTROL;
                if (shortcut->ALT)
                    MODS |= MOD_ALT;
                if (shortcut->SHIFT)
                    MODS |= MOD_SHIFT;
                const BOOL result = RegisterHotKey(nullptr, i, MODS, shortcut->keyId);
                shortcut->reset = false;
                if(FAILED(result))
                    printf("Error registering hotkey: %d\n%ws\n", GetLastError(), getLastErrorStr());
                else
                    printf("Registered hotkey %s %s %s %c (0x%02x)\n", 
                        shortcut->CTRL ? "CTRL +" : "",
                        shortcut->ALT ? "ALT +" : "",
                        shortcut->SHIFT ? "SHIFT +" : "",
                        shortcut->keyId,
                        shortcut->keyId
                    );
                LeaveCriticalSection(&cs);
            }      
        }

        // handle hotkey press
        if (PeekMessage(&msg, nullptr, 0, 0, 0)) {
            if (msg.message == WM_HOTKEY) {
                GetMessage(&msg, nullptr, 0, 0);
                shortcut = shortcuts[msg.wParam];
                switch (shortcut->type)
                {
                case shortcut_suspend:
                    suspendTarget(shortcut->hProc, toggle);
                    toggle = !toggle;
                    break;
                case 2:
                    break;
                case 3:
                    break;
                case 4:
                    break;
                case 5:
                    break;
                }
            }
        }
    }
}

bool suspendTarget(const HANDLE hProc, const bool toggle)
{
    // Import NtSuspendProcess/NtResumeProcess from ntdll.dll to suspend/resume all threads at once.
    typedef LONG(NTAPI* pNtSuspendProcess)(HANDLE ProcessHandle);
    typedef LONG(NTAPI* pNtResumeProcess)(HANDLE ProcessHandle);
    const pNtSuspendProcess NtSuspendProcess = (pNtSuspendProcess) GetProcAddress(GetModuleHandle(L"ntdll.dll"), "NtSuspendProcess");
    const pNtResumeProcess NtResumeProcess = (pNtResumeProcess) GetProcAddress(GetModuleHandle(L"ntdll.dll"), "NtResumeProcess");
    if (NtSuspendProcess && NtResumeProcess) {
        HRESULT result;
        if (toggle)
            result = NtSuspendProcess(hProc);
        else
            result = NtResumeProcess(hProc);

        if (!NT_SUCCESS(result)) {
            printf("Error suspend or resume process: %d\n%ws\n", GetLastError(), getLastErrorStr());
            return false;
        }
    }
    else {
        printf("Error getting addresses for suspend/resume from ndtll: %d\n%ws\n", GetLastError(), getLastErrorStr());
        return false;
    }

    return true;
}

bool newScanUI()
{
    int pid;
    printf("Enter PID: ");
    scanf_s("%d", &pid);
    printf("Starting scan\n");
    MBLOCK* scanData = startScan(pid);

    if (!scanData) {
        // implement more logic here. eg. insufficient permission to get handle, tell user to run as admin etc.
        printf("Scan failed\n");
        return false;
    }

    WCHAR imageName[MAX_PATH];
    WCHAR imagePath[MAX_PATH];
    constexpr DWORD dwSize = sizeof(imagePath);
    GetModuleFileNameEx(scanData->hProc, nullptr, imagePath, dwSize);
    WCHAR* processName = PathFindFileName(imagePath);
    printf("Process: %ls\n", processName);
    printf("Image path: %ls\n", imagePath);

    printScan(scanData);

    int userChoice;
    while (true) {
        printf(
            "\nEnter your choice:\n"
            "1: Filter for addresses\n"
            "2: Print scan data\n"
            "3: Print scan data (debug)\n"
            "4: Configure shortcuts\n"
            "5: View saved addresses\n"
            "6: Quit scan\n"
        );
        scanf_s("%d", &userChoice);

        switch (userChoice)
        {
        case 1:
            filterResultsUI(scanData);
            break;
        case 2:
            printScan(scanData);
            break;
        case 3:
        {
            int memblock_id = 0;
            do {
                printf("Found %d memory blocks. Choose memory block to print (1-%d)\n", memblock_counter, memblock_counter);
                scanf_s("%d", &memblock_id);
            } while (!(userChoice <= memblock_counter && userChoice >= 1));

            MBLOCK* mb = scanData;
            while (mb) {
                if (mb->id == memblock_id)
                    printMemblock(mb, TRUE);
                mb = mb->next;
            }
        }
            break;
        case 4:
            configureHotkeyUI(scanData);
            break;
        case 5:
            savedMatchesUI(scanData);
            break;
        case 6:
            closeScan(scanData);  
            return true; //back to main menu
            break;
        default:
            printf("Invalid choice\n");
        }
    }
}

void savedMatchesUI(MBLOCK* scanData)
{
    printf("Saved addresses: %d\n", countMatches(g_savedMatches));
    printMatches(g_savedMatches);
    
    int userChoice;
    while (true) {
        printf(
            "\nEnter your choice:\n"
            "1: Write value to address\n"
            "2: Freeze/Unfreeze address\n"
            "3: Generate pointermap for address\n"
            "4: Trace address\n"
            "5: Print saved addresses\n"
            "6: Back\n"
        );
        scanf_s("%d", &userChoice);
    
        switch (userChoice)
        {
        case 1:
            writeAddressUI();
            break;
        case 2:
            freezeAddressUI();
            break;
        case 3:
            pointermapUI(scanData);
            break;
        case 4:
            printf(NOT_IMPLEMENTED);
            break;
        case 5:
            printf("Saved addresses: %d\n", countMatches(g_savedMatches));
            printMatches(g_savedMatches);
            break;
        case 6:
            return;
            break;
        default:
            printf("Invalid choice\n");
        }
    }

    return;
}

void writeAddressUI()
{
    // select match
    int matchChoice;
    printf("Select address (number): ");
    scanf_s("%d", &matchChoice);
    MATCH* match = getMatchByPrintOrder(g_savedMatches, matchChoice);
    FreezeRequest* fr;
    uintptr_t value;

    value = getUserInputForTypeUI(match->type);
    if (!writeAddress(match, value)) {
        printf("Failed writing to address. Memory region info:\n");
        printMemblock(match->memblock, false);
    }
        
    return;
}

bool writeAddress(MATCH* match, uintptr_t value)
{
    SIZE_T lpNumberOfBytesWritten;
    if (WriteProcessMemory(match->memblock->hProc, match->address, &value, getSizeForType(match->type), &lpNumberOfBytesWritten))
        return true;
    else {
        printf("Error writing value 0x%x (%d) for match: %p\nError id: %lu\nError msg: %ls\n", value, value, match->address, GetLastError(), getLastErrorStr());
        printf("number of bytes written: %d\n", lpNumberOfBytesWritten);
        return false;
    }
}

void freezeAddressUI()
{
    // select match
    int matchChoice;
    printf("Select address (number): ");
    scanf_s("%d", &matchChoice);
    MATCH* match = getMatchByPrintOrder(g_savedMatches, matchChoice);
    FreezeRequest* fr;
    uintptr_t value;

    int userChoice;
    while (true) {
        printf(
            "\nEnter your choice:\n"
            "1: Freeze address\n"
            "2: Unfreeze address\n"
        );
        scanf_s("%d", &userChoice);

        switch (userChoice)
        {
        case 1:
            // check if match is already frozen
            if (match->freeze) {
                printf("Address is already frozen\n");
            }
            else {
                // freeze match
                fr = freezeAddress(match, getUserInputForTypeUI(match->type));
                match->freeze = fr;
                printf("Address frozen\n");
            }
            return;
        case 2:
            if(!match->freeze)
                printf("Address was not frozen");
            else {
                unfreezeAddress(match);
                printf("Address unfrozen\n");
            }
            return;
        default:
            printf("Invalid choice\n");
        }
    }

    return;
}

FreezeRequest* freezeAddress(const MATCH* match, uintptr_t value)
{
    // create freezer thread (which also does the deallocation)
    FreezeRequest* fr = (FreezeRequest*)malloc(sizeof(FreezeRequest));
    fr->action = action_freeze;
    fr->address = (uintptr_t) match->address;
    fr->value = value;
    fr->hProc = match->memblock->hProc;
    fr->unfreeze_event = CreateEvent(NULL, false, false, NULL);

    // Start the thread
    HANDLE hThread = CreateThread(
        nullptr,            // default security attributes
        0,                  // use default stack size  
        freezeHandler,      // thread function name
        (LPVOID)fr,         // argument to thread function 
        0,                  // use default creation flags
        nullptr
    );

    // return the FreezeRequest which can be used to unfreeze
    return fr; 
}

// Signals freeze handler thread to stop spamming wpm
bool unfreezeAddress(MATCH* match)
{
    if (!match->freeze) {
        return false;
    }
    else if (!SetEvent(match->freeze->unfreeze_event))
    {
        printf("SetEvent failed (%d)\n", GetLastError());
        return false;
    }
    
    // change state of match to not frozen and free FreezeRequest
    free(match->freeze);
    match->freeze = nullptr;

    return true;
}

void pointermapUI(MBLOCK* scanData)
{
    int matchChoice;
    int recurseLevel = 3;  // reminder to play around with higher recurse levels
    printf("Select address (number): ");
    scanf_s("%d", &matchChoice);
    const MATCH* match = getMatchByPrintOrder(g_savedMatches, matchChoice);
    PointerMap* pointermap = nullptr;
    std::unordered_set<uintptr_t> visitedAddresses;
    pointermap = pointermapScan(scanData, match, recurseLevel, nullptr, nullptr, visitedAddresses);
    visitedAddresses.clear();
    if(!pointermap->pathHead)
        printf("No results for pointermap.\n");
    else
        printPointermap(pointermap);

    return;
}

void printPointermap(PointerMap* pointermap)
{
    int count = 0;
    int offset = 0;
    PointerPath* path;
    PointerMap* tmp;

    // Simple print
    printf("\n==Simple print==\n");
    tmp = pointermap;
    while (tmp) {
        count++;
        offset = 0;
        path = tmp->pathHead;
        printf("%d:\tAddress: ", count);
        while (path) {
            if (offset != 0)
                printf("[+ 0x%x] ", offset);
            printf("%p -> ", path->match->address);

            offset = path->offset;

            if (!path->next) {
                if (offset != 0)
                    printf("[+ 0x%x] ", offset);
                printf("(target)\n");
            }

            path = path->next;
        }

        tmp = tmp->next;
    }

    // Informatic print
    printf("\n==Informatic print==\n");
    count = 1;
    tmp = pointermap;
    while (tmp) {
        path = tmp->pathHead;
        printf("\n==%d==\n", count++);

        while (path) {
            printMatch(path->match);
            printInsights(path->match);
            if (path->next) {
                if (offset != 0)
                    printf("    |\n     --> [+ 0x%x] = (0x%p)\n", path->offset, path->next->match->address);
            }
            else {
                int size = sizeof(uintptr_t);
                uintptr_t remote_value;
                if (!ReadProcessMemory(path->match->memblock->hProc, path->match->address, &remote_value, size, nullptr)) {
                    if (GetLastError() != 299)
                        printf("Error reading updated value of match: %p\nError id: %lu\nError msg: %ls\n", path->match->address, GetLastError(), getLastErrorStr());
                }
                if (offset != 0) {
                    printf("    [+ 0x%x] = (0x%p)\n", path->offset, remote_value + path->offset);
                }
                    
                printf("\t\t^^ target ^^\n");
            }
                
            path = path->next;
        }

        tmp = tmp->next;
    }

    return;
}


// Return a pointermap containing all pointer paths found. Empty pointermap if no results.
// Pointermap returned is a pointer to the head node in a linked-list of PointerMap each containing the head node to a linked-list of PointerPath
PointerMap* pointermapScan(MBLOCK* scanData, const MATCH* match, int recurseLevel, PointerPath* pathNode, PointerMap* pointermap, std::unordered_set<uintptr_t> visitedAddresses)
{
    // scan down till pointer found and consider it to be base of some struct/object and stop there
    if (recurseLevel <= 0)
        return pointermap;

    // create a new pointermap if one was not created yet
    if (!pointermap) {
        pointermap = (PointerMap*)malloc(sizeof(PointerMap));
        pointermap->pathHead = nullptr;
        pointermap->next = nullptr;
    }
    
    static int counter = 1;  // counter
    int guessSize = 100;
    Node* matches = nullptr;
    uintptr_t address = (uintptr_t) match->address;
    int offset = 0;
    bool foundMatch = false; 
    for (offset = 0; offset < guessSize; offset++) {
        // keep going down untill find a match
        matches = filterAddresses(scanData, (uintptr_t)address, type_pointer, 1, matches);
        address--;
        int matchCount = countMatches(matches);
        if (matchCount <= 0)
            continue;
        else {
            foundMatch = true;
            // Treat this as the beginning of a struct and stop here (wrong assumption but works decently)
            //printf("Matches found: %d\n", matchCount);
            //printMatches(matches);

            // PointerPath add
            
            // Recurse one level down for match

            Node* tmpMatches = matches;
            while (tmpMatches) {
                match = tmpMatches->match;

                // Check if the match is already in the current path to avoid infinite loops
                bool matchInPath = false;
                PointerPath* path = pathNode;
                while (path) {
                    if (path->match->address == match->address) {
                        matchInPath = true;
                        break;
                    }
                    path = path->next;
                }

                // Check if the match address has been visited before to avoid revisiting
                bool addressVisited = false;
                if (visitedAddresses.find((uintptr_t) match->address) != visitedAddresses.end())
                    addressVisited = true;

                // Add match to pointer path and scan for it too (unless its already in path causing a loop)
                if (!matchInPath && !addressVisited) {
                    // Store the visited address
                    visitedAddresses.insert((uintptr_t) match->address);

                    // Allocate new PointerPath node and add to pathnode given in the function
                    PointerPath* newPathNode = (PointerPath*)malloc(sizeof(PointerPath));
                    newPathNode->match = match;
                    newPathNode->offset = offset;
                    newPathNode->next = pathNode;
                    if (!pointermap->pathHead) {
                        pointermap->pathHead = newPathNode;

                        // Simple-print the path
                        PointerPath* path = newPathNode;
                        printf("%d:\tAddress: ", counter++, path->match->address);
                        while (path) {
                            if (offset != 0)
                                printf("[+ 0x%x] ", offset);
                            printf("%p -> ", path->match->address);

                            offset = path->offset;

                            if (!path->next) {
                                if (offset != 0)
                                    printf("[+ 0x%x] ", offset);
                                printf("(target)\n");
                            }

                            path = path->next;
                        }
                    }
                    else {
                        // Allocate new pointermap node and add infront
                        PointerMap* tmp = (PointerMap*)malloc(sizeof(PointerMap));
                        tmp->pathHead = newPathNode;
                        tmp->next = pointermap;
                        pointermap = tmp;

                        // Simple-print the path
                        PointerPath* path = tmp->pathHead;
                        printf("%d:\tAddress: ", counter++, path->match->address);
                        while (path) {
                            if (offset != 0)
                                printf("[+ 0x%x] ", offset);
                            printf("%p -> ", path->match->address);

                            offset = path->offset;

                            if (!path->next) {
                                if (offset != 0)
                                    printf("[+ 0x%x] ", offset);
                                printf("(target)\n");
                            }

                            path = path->next;
                        }
                    } // End: adding pointer path node to pointermap

                    // recursively scan for that path node aswell
                    pointermap = pointermapScan(scanData, match, recurseLevel - 1, newPathNode, pointermap, visitedAddresses);
                } // End: if (match not in path already)

                tmpMatches = tmpMatches->next;
            } // End: while(matches)
        } // End: if found matches
    } // End: offset loop

    return pointermap;
}

void configureHotkeyUI(MBLOCK* scanData)
{
    int keyId;
    int userChoice;
    bool keyReady;
    bool SHIFT = false;
    bool ALT = false;
    bool CTRL = false;
    HOTKEY* shortcut;
    while (true) {
        printf(
            "Choose a shortcut to configure:\n"
            "1: Suspend target process\n"
            "2: Go back\n"
        );
        scanf_s("%d", &userChoice);

        switch (userChoice)
        {
        case 1:
            printf("Enter a key: ");
            Sleep(500);
            keyReady = false;
            while (!keyReady) {
                for (keyId = 8; keyId <= 190; keyId++) {
                    //printf("KeyId: %d 0x%02x\n", keyId);
                    if (GetAsyncKeyState(keyId) & 0x8000) {
                        if (keyId == 190 || keyId == 110)
                            printf(".");
                        else if (keyId == 8) {
                            printf("[BACKSPACE]");
                            keyReady = true;
                        }
                        else if (keyId == 13) {
                            printf("[ENTER]");
                            keyReady = true;
                        }
                        else if (keyId == 32) {
                            printf("[SPACE]");
                            keyReady = true;
                        }
                        else if (keyId == VK_TAB) {
                            printf("[TAB]");
                            keyReady = true;
                        }
                        else if (keyId == VK_SHIFT) {
                            if(!SHIFT)
                                printf("[SHIFT] + ");
                            SHIFT = true;
                            keyReady = false;
                        }
                        //else if (keyId == VK_LSHIFT) {
                        //    printf("[L SHIFT] + ");
                        //    vk[vkLen++] = VK_LSHIFT;
                        //    keyReady = false;
                        //}
                        //else if (keyId == VK_RSHIFT) {
                        //    printf("[R SHIFT] + ");
                        //    vk[vkLen++] = VK_RSHIFT;
                        //    keyReady = false;
                        //}
                        else if (keyId == VK_CONTROL) {
                            if (!CTRL)
                                printf("[CONTROL] + ");
                            CTRL = true;
                            keyReady = false;
                        }
                        //else if (keyId == VK_LCONTROL) {
                        //    printf("[L CONTROL] + ");
                        //    vk[vkLen++] = VK_LCONTROL;
                        //    keyReady = false;
                        //}
                        //else if (keyId == VK_RCONTROL) {
                        //    printf("[R CONTROL] + ");
                        //    vk[vkLen++] = VK_RCONTROL;
                        //    keyReady = false;
                        //}
                        else if (keyId == VK_MENU) {
                            if (!ALT)
                                printf("[ALT] + ");
                            ALT = true;
                            keyReady = false;
                        }
                        //else if (keyId == VK_LMENU) {
                        //    printf("[L ALT] + ");
                        //    keyReady = false;
                        //}
                        //else if (keyId == VK_RMENU) {
                        //    printf("[R ALT] + ");
                        //    keyReady = false;
                        //}
                        else if (keyId == VK_ESCAPE) {
                            printf("[ESCAPE]");
                            keyReady = true;
                        }
                        else if (keyId == VK_END) {
                            printf("[END]");
                            keyReady = true;
                        }
                        else if (keyId == VK_HOME) {
                            printf("[HOME]");
                            keyReady = true;
                        }
                        else if (keyId == VK_LEFT) {
                            printf("[LEFT]");
                            keyReady = true;
                        }
                        else if (keyId == VK_UP) {
                            printf("[UP]");
                            keyReady = true;
                        }
                        else if (keyId == VK_RIGHT) {
                            printf("[RIGHT]");
                            keyReady = true;
                        }
                        else if (keyId == VK_DOWN) {
                            printf("[DOWN]");
                            keyReady = true;
                        }
                        else if (keyId != VK_LSHIFT && keyId != VK_RSHIFT && keyId != VK_LCONTROL && keyId != VK_RCONTROL && keyId != VK_LMENU && keyId != VK_RMENU) {
                            keyReady = true;
                            printf("%c\n", keyId);
                            break;
                        }  
                    }
                }
            }
            configureHotkey(keyId, CTRL, ALT, SHIFT, shortcut_suspend, scanData->hProc);
            return;
        case 2:
            return;
        default:
            printf("Invalid choice\n");
        }
    }
}

void configureHotkey(int keyId, bool CTRL, bool ALT, bool SHIFT, SHORTCUT_TYPE type, HANDLE hProc)
{
    HOTKEY* shortcut = (HOTKEY*)malloc(sizeof(HOTKEY));

    shortcut->hotkeyId = shortcut_counter;
    shortcut->keyId = keyId;
    shortcut->type = type;
    shortcut->hProc = hProc;
    shortcut->CTRL = CTRL ? true : false;
    shortcut->ALT = ALT ? true : false;
    shortcut->SHIFT = SHIFT ? true : false;

    shortcut->reset = true; // make sure this one is last because my lazy code is not thread-safe (variable changed by other thread)
    EnterCriticalSection(&cs);
    shortcuts[shortcut_counter++] = shortcut;  // and this one kicks the check loop on in the other thread
    LeaveCriticalSection(&cs);
    Sleep(500);
    SetEvent(hotkeysReadyEvent);  // and this one kicks the thread on first time
    printf("Registered hotkey %s %s %s %c (0x%02x)\n", CTRL ? "CTRL + " : "", ALT ? "ALT + " : "", SHIFT ? "SHIFT + " : "", keyId, keyId);

    return;
}

void filterResultsUI(MBLOCK* scanData)
{
    int userChoice;
    HUNTING_TYPE dataType;

    while (true) {
        printf(
            "Choose a data type:\n"
            "1: Byte (1 Byte unsigned)\n"
            "2: Char (1 Byte signed)\n"
            "3: Short (2 Byte signed)\n"
            "4: Int (4 Byte signed)\n"
            "5: Float (4 Byte floating point)\n"
            "6: Double (8 Byte floating point)\n"
            "7: Long Int (8 Byte signed)\n"
            "8: Pointer (64 bit)\n"
            "9: Go back\n"
        );
        scanf_s("%d", &userChoice);

        switch (userChoice)
        {
        case 1:
            scanUI(scanData, type_byte);
            return;
        case 2:
            scanUI(scanData, type_char);
            return;
        case 3:
            scanUI(scanData, type_short);
            return;
        case 4:
            scanUI(scanData, type_int);
            return;
        case 5:
        case 6:
            printf(NOT_IMPLEMENTED); // floating comparisons not yet implemented (using == atm)
            return;
        case 7:
            scanUI(scanData, type_long_long_int);
            return;
        case 8:
            scanUI(scanData, type_pointer);
            return;
        case 9:
            return;
        default:
            printf("Invalid choice\n");
        }
    }
}

int countMatches(const Node* matches)
{
    int counter = 0;
    const Node* match = matches;
    while (match) {
        counter++;
        match = match->next;
    }

    return counter;
}

void saveMatches(Node* matches)
{
    MATCH* match;
    while (matches) {
        match = matches->match;
        g_savedMatches = insertMatch(match, g_savedMatches);

        matches = matches->next;
    }

    return;
}

void scanUI(MBLOCK* scanData, HUNTING_TYPE type)
{
    uintptr_t value;
    char repeat;
    int matchCount = 0;
    Node* matches = nullptr;

    value = getUserInputForTypeUI(type);   
    matches = filterAddresses(scanData, value, type, 1, matches);
    printMatches(matches);

    printf("Next Filter? (y/n): ");
    scanf_s(" %c", &repeat);
    while (repeat == 'y') {
        value = getUserInputForTypeUI(type);
        matches = filterAddresses(nullptr, value, type, 1, matches);
        matchCount = countMatches(matches);
        printf("Matches found: %d\n", matchCount);
        if (matchCount <= 20)
            printMatches(matches);
        printf("Filter more? (y/n): ");
        scanf_s(" %c", &repeat);
    }

    char choice;
    printf("Save matches? (y/n): ");
    scanf_s(" %c", &choice);
    if (choice == 'y')
        saveMatches(matches);

    return;
}

uintptr_t getUserInputForTypeUI(HUNTING_TYPE type)
{
    uintptr_t value = 0;
    switch (type)
    {
    case type_byte:
        printf("Enter value (hex): ");
        scanf_s("%x", &value);
        break;
    case type_char:
        printf("Enter value (single character): ");
        scanf_s(" %c", &value);
        break;
    case type_short:
    case type_int:
        printf("Enter value: ");
        scanf_s("%d", &value);
        break;
    case type_float:
    case type_double:
        printf(NOT_IMPLEMENTED);
        break;
    case type_long_long_int:
        printf("Enter value: ");
        scanf_s("%lld", &value);
        break;
    case type_pointer:
        printf("Enter value (hex): ");
        scanf_s("%llx", &value);
        break;
    default:
        printf("stfu what is this type how did it get here\n");
    }

    return value;
}

// sorts by address. even though its mostly used in a sequential manner by a linear low to high memory region mapping so it comes sorted anyway.
Node* insertMatch(MATCH* newMatch, Node* matches) {
    Node* head = matches;
    Node* newNode = new Node;
    newNode->match = newMatch;
    newNode->next = nullptr;

    if (head == nullptr || newMatch->address < head->match->address) {
        newNode->next = head;
        head = newNode;
        matches = head;
        return head;
    }

    Node* curr = head;
    while (curr->next != nullptr && curr->next->match->address < newMatch->address) {
        curr = curr->next;
    }

    newNode->next = curr->next;
    curr->next = newNode;
    matches = head;
    return head;
}

Node* removeMatch(const MATCH* matchToRemove, Node* matches) {
    Node* curr = matches;
    Node* prev = nullptr;

    while (curr != nullptr) {
        if (curr->match == matchToRemove) {
            if (prev == nullptr) { // matchToRemove is the head of the list
                matches = curr->next;
            }
            else {
                prev->next = curr->next;
            }
            free(curr->match);
            free(curr);
            return matches;
        }
        prev = curr;
        curr = curr->next;
    }

    return matches; // matchToRemove not found
}

void freeMatches(Node* matches) {
    Node* curr = matches;
    while (curr != nullptr) {
        Node* next = curr->next;
        free(curr->match);
        free(curr);
        curr = next;
    }
    matches = nullptr;
}

void printMatchesWideChar(int length, Node* matches) {
    Node* head = matches;
    Node* curr = head;
    int size = length * sizeof(WCHAR) + 1; // 16bit wide chars + null terminator
    WCHAR* remote_value = (WCHAR*)malloc(size * sizeof(WCHAR));

    while (curr != nullptr) {
        MATCH* match = curr->match;
        if (!ReadProcessMemory(match->memblock->hProc, match->address, remote_value, size, NULL)) {
            printf("Error reading updated value of match: %p\nError id: %d\nError msg: %ls\n", match->address, GetLastError(), getLastErrorStr());
        }
        printf("\nMemblock ID: %d Address: 0x%p Value: %ls\n", match->memblock_id, match->address, remote_value);

        curr = curr->next;
    }
}

// mirror iteration of printMatches for UI selection after print
MATCH* getMatchByPrintOrder(Node* matches, int selection)
{
    Node* head = matches;
    Node* curr = head;
    int size = sizeof(uintptr_t);
    uintptr_t remote_value;
    int counter = 1;

    while (curr != nullptr) {
        MATCH* match = curr->match;
        if (counter == selection)
            return match;
        counter++;

        curr = curr->next;
    }

    return nullptr;
}

// generic print for any non-string matches
void printMatches(Node* matches)
{
    Node* head = matches;
    Node* curr = head;
    int counter = 1;

    while (curr != nullptr) {
        const MATCH* match = curr->match;
        printf("%d. ", counter++);
        printMatch(match);
        printInsights(match);

        curr = curr->next;
    }

    return;
}

void printMatch(const MATCH* match)
{
    int size = sizeof(uintptr_t);
    uintptr_t remote_value;

    if (!ReadProcessMemory(match->memblock->hProc, match->address, &remote_value, size, nullptr)) {
        if (GetLastError() != 299)
            printf("Error reading updated value of match: %p\nError id: %lu\nError msg: %ls\n", match->address, GetLastError(), getLastErrorStr());
    }
    printf("Memblock ID: %d Address: 0x%p ",
        match->memblock_id,
        match->address
    );
    HUNTING_TYPE type = match->type;
    switch (type)
    {
    case type_byte:
        printf("Value: 0x%02x\n", remote_value);
        break;
    case type_char:
        printf("Value: %c\n", remote_value);
        break;
    case type_short:
        printf("Value: %d\n", remote_value);
        break;
    case type_int:
        printf("Value: %d\n", remote_value);
        break;
    case type_float:
        printf("Value: %f\n", remote_value);
        break;
    case type_double:
        printf("Value: %lf\n", remote_value);
        break;
    case type_long_long_int:
        printf("Value: %lld\n", remote_value);
        break;
    case type_pointer:
        if (match->pointTotype != type_null) {
            printf("Value: %p (P->", remote_value);
            printValue(type, remote_value);
            printf(")\n");
        }
        else
            printf("Value: %p (Pointer)\n", remote_value);
        break;
    }

    return;
}

void printInsights(const MATCH* match)
{
    if (match->isStatic) {
        const char* charAddr = (char*)match->address;
        const char* charBase = (char*)match->memblock->mbi.AllocationBase;
        ptrdiff_t offset = charAddr - charBase;
        printf("    [+] Dynamic Address: %ls + 0x%x\n", getStringUse(match->memblock), offset);
    }
    // [+] check for ASLR disabled
    // [-] check for stack
    // [-] check for heap
}

// for x86-64 modern cpu
int getSizeForType(int dataType)
{
    switch (dataType)
    {
        case type_byte:
            return 1;
        case type_char:
            return 1; 
        case type_float:
            return 4;
        case type_double:
            return 8;
        case type_short:
            return 2;
        case type_int:
            return 4;
        case type_long_long_int:
            return 8;
default: ;
    }
    return 0;
}
