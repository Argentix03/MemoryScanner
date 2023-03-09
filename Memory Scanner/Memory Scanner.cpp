//  Memscan - A memory scanner
//  DONE:
//      1. create structs and linked list and stuff to hold memory matches and metadata
//      2. map memory protections and allocation state + parse memory regions into memblocks 
//      3. core search logic
//  TODO: 
//      1. filtering aka 'next scan'.
//      2. scans for other data types.
//      3. hotkey to pause/resume target process
//      4. extended information on modules and relative/static addresses and commit types.
//      5. pointermaps!!
//      6. tracing aka 'find what access/writes to this address'???
//      7. bonus: generic speedhack (hook game ticks to fake time). ex: https://github.com/onethawt/speedhack/blob/master/SpeedHack.cpp

#include <Windows.h>
#include <stdio.h>
#include "memscan.h"

// globals

// flag used to discard unwritable memory (not that we technically cant write to it but that its probably not a value in the game we care about changing)
// literal strings and resources may be here, code. might seperate this later to a choice of RO/RW/X etc.
bool writable_only;
bool debug;
int memblock_counter = 0;
Node* matches = nullptr;

// add commit type (mapped/image/private)
// Convert MEMORY_BASIC_INFORMATION.Protect into comfy string representation.
// Return a pointer to a newly allocated string.
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

    strcpy_s(buf, "Memory Permissions: ");
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
        strcat_s(buf, "PAGE_TARGETS_INVALID");
    else if (protection == PAGE_TARGETS_NO_UPDATE) // 0x40000000 (CFG Stuff)
        strcat_s(buf, "PAGE_TARGETS_NO_UPDATE");

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
char* getStringState(DWORD state)
{
    char buf[50];
    char* memory_state = (char*)calloc(sizeof(char), sizeof(buf));
    strcpy_s(buf, "State: ");
    if (state == MEM_COMMIT) // 0x1000
        strcat_s(buf, "MEM_COMMIT");
    else if (state == MEM_FREE) // 0x10000
        strcat_s(buf, "MEM_FREE");
    else if (state == MEM_RESERVE) // 0x2000
        strcat_s(buf, "MEM_RESERVE");

    strcpy_s(memory_state, sizeof(buf), buf);
    return memory_state;
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
        if (!ReadProcessMemory(hProc, meminfo.BaseAddress, mb->buffer, meminfo.RegionSize, NULL)) {
            printf("Error ReadProcessMemory: %d\n%ws\n", GetLastError(), getLastErrorStr());
        }
    }

    return mb;
}

void printMemblock(int memblock_id, MBLOCK* memlist)
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
                long long int offset = membyte - (long long int) (mb->buffer);
                long long int remote_address = (long long int) mb->addr + offset;
                newMatch->address = (PVOID) remote_address;
                newMatch->memblock_id = mb->id;
                newMatch->memblock = mb;
                insertMatch(newMatch);
            }

            ++membyte;
        }

        mb = mb->next;
    }

    return;
}

void filterAddresses(MBLOCK* memlist, double value, int dataType, int data_len, Node* matches)
{
    printf("searching for value:");
    switch (dataType)
    {
    case type_byte:
        printValue(dataType, (BYTE)value);
        break;
    case type_char:
        printValue(dataType, (char)value);
        break;
    case type_float:
        printValue(dataType, (float)value);
        break;
    case type_double:
        printValue(dataType, (double)value);
        break;
    case type_short:
        printValue(dataType, (short)value);
        break;
    case type_int:
        printValue(dataType, (int)value);
        break;
    case type_long_int:
        printValue(dataType, (long int)value);
        break;
    }
    putchar('\n');

    MBLOCK* mb = memlist;
    long long int membyte = (long long int) mb->buffer;
    long long int finalAddr = ((long long int)mb->buffer) + mb->size;
    bool matched = 0;
    while (membyte <= finalAddr) {
        switch (dataType)
        {
            case type_byte:
                matched = (*((BYTE*)membyte) == (BYTE) value); // 1 Byte unsigned
                break;
            case type_char:
                matched = (*((char*)membyte) == (char) value); // 1 Byte signed
                break;
            case type_float:
                matched = (*((float*)membyte) == (float) value); // 4 Byte floating point
                break;
            case type_double:
                matched = (*((double*)membyte) == (double) value); // 8 Byte floating point
                break;
            case type_short:
                matched = (*((short*)membyte) == (short) value); // 2 Byte signed
                break;
            case type_int:
                matched = (*((int*)membyte) == (int) value); // 4 Byte signed
                break;
            case type_long_int:
                matched = (*((long int*)membyte) == (long int) value); // 8 Byte signed
                break;
        }
        if (matched) {
            printf("Memblock id: %d\n", mb->id);
            printf("Memblock address: 0x%llx\n", membyte);
            printf("content: ");
            const char* fmt = printValue(dataType, value);
            putchar('\n');

            MATCH* newMatch = (MATCH*)malloc(sizeof(MATCH));
            long long int offset = membyte - (long long int) (mb->buffer);
            long long int remote_address = (long long int) mb->addr + offset;
            newMatch->address = (PVOID)remote_address;
            newMatch->memblock_id = mb->id;
            newMatch->memblock = mb;
            insertMatch(newMatch);
        }

        ++membyte;
    }

    return;
}

bool matchValue(long long int addr, int value, int pattern_len)
{
    int matching = 0;
    --pattern_len;
    for (int i = 0; i <= pattern_len; ++i) {
        if (!(*((int*)addr + i) == value))
            return false;
        else
            matching++;
    }

    return true;
}

const char* printValue(int dataType, double value)
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
        printf("%h", (short)value);
        break;
    case type_int:
        printf("%d", (int)value);
        break;
    case type_long_int:
        printf("%ld", (long int)value);
        break;
    }

    return "";
}

// basically matches wide strings
bool matchPatternWideChar(long long int addr, const WCHAR pattern[], int pattern_len)
{
    int matching = 0;
    --pattern_len;
    for (int i = 0; i <= pattern_len; ++i) {
        if (!(*((WCHAR*)addr + i) == pattern[i]))
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
        if (*(BYTE*)membyte == 41)
            printf("0x%02x ", (BYTE*)membyte);
        //printf("%02x ", *(BYTE *)membyte);
        ++membyte;
    }

    return;
}

// free blocks that fail the 'next scan' filter or all of them when a scan is discarded.
// not implemented yet. need to free mb->buffer, mb, and not break the linked list.
void freeMemBlock(MBLOCK* mb)
{
    if (!mb)
        return;

    if (mb->buffer) {
        free(mb->buffer);
    }
}

// starts a scan. currenly no filters implemeneted. scans through a full process' (commited) memory.
// returns memlist - first member of the linked-list of memblocks created in the scan.
MBLOCK* startScan(int pid)
{
    MBLOCK* memlist = NULL;
    MEMORY_BASIC_INFORMATION mbi;
    PVOID addr = 0;

    HANDLE hProc = OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, false, pid);
    if (!hProc) {
        printf("Error open process handle: %d\n%ws\n", GetLastError(), getLastErrorStr());
        return nullptr;
    }

    do {
        // query a memory region and 
        VirtualQueryEx(hProc, addr, &mbi, sizeof(mbi));
        if (debug)
            printf("VirtualQuery: %p\n", addr);

        // skip if memory not commited or writable flag set and memory isnt writable
        bool mem_commited = mbi.State & MEM_COMMIT;
        bool mem_writable = mbi.Protect & WRITEABLE_MEM;
        if (mem_commited && (!writable_only || mem_writable)) {
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
                if (!mem_commited)
                    printf("Skipping uncommited memory: %p\n", addr);
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
    do {
        CloseHandle(memlist->hProc);
        MBLOCK* mb = memlist;
        freeMemBlock(mb);
    } while (memlist = memlist->next);

    return;
}

// print all memblocks in a memlist including metadata
void printScan(MBLOCK* memlist)
{
    MBLOCK* mb = memlist;

    while (mb) {
        unsigned long int size_kb = mb->size >> 10;
        PVOID addr = mb->addr;
        const char* mem_state = getStringState(mb->mbi.State);
        const char* mem_protect = getStringProtection(mb->mbi.Protect);
        printf("ID: %d\t", mb->id); // memblock id
        printf("0x%p\t", addr); // address
        printf("%8lu KB\t", size_kb); // size
        printf("%s\t", mem_state);  // commit state
        printf("%s\n", mem_protect);  // permissions
        mb = mb->next;
    }

    return;
}

// This one is insanely good...
WCHAR* getLastErrorStr()
{
    WCHAR buf[256];
    FormatMessageW(
        FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
        NULL, GetLastError(), MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
        buf, (sizeof(buf) / sizeof(WCHAR)), NULL
    );

    return buf;
}

int main(int argc, char** argv)
{
    // argument check
    if (argc < 2) 
        printUsageAndExit();

    writable_only = false;
    debug = false;
    int pid = 0;
    for (int i = 1; i < argc; ++i) {
        if (!strcmp(argv[i], "-pid")) {
            pid = atoi(argv[i+1]);
            ++i;
        }
        else if (!strcmp(argv[i], "-writable_mem"))
            writable_only = true;
        else if(!strcmp(argv[i], "-debug"))
            debug = true;
    }

    if (pid == 0)
        printUsageAndExit();


    // scan game
    printf("Starting scan\n");
    MBLOCK* scanResults = startScan(pid);
    if (!scanResults) {
        printf("Scan failed\n");
        return 1;
    }

    printScan(scanResults);

    // Test 1: Open notepad (or any application using text) and type a long enough text to search
    
    // Define search_pattern and length accordingly
    //const WCHAR *search_pattern = L"HOSHEA";
    //int pattern_len = 6;
    //searchWideChar(scanResults, search_pattern, pattern_len, matches);
    
    // Change the text then press any key to continue (on memscan console) and notice the changed value
    //system("pause");
    //printf("Matches for pattern: %ws\n", search_pattern);
    //printMatchesWideChar(pattern_len);


    // Test 2: Open a program that stores numbers (not as strings like calc), specifically integers) and input a unique long 32bit integer
    // Define search_pattern as the integer and length to 1
    // (Implement searchSignedInt() and filterMatches()...)
    // Make the value change (add something and press =) and use filterMatches() accordingly
    // Repeat untill you notice the changes value
    int dataType = type_int;
    int data_len = 1;
    int value = 187562453;
    filterAddresses(scanResults, value, dataType, data_len, matches);
    printMatches(type_int);
    system("pause");

    return 0;
}

void printUsageAndExit()
{
    printf("Usage: memscan.exe <-pid PID> [-writable_mem] [-debug]\n");
    printf("Example: memscan.exe -pid 1785 -writable_mem -debug\n");
    exit(1);
}

Node* insertMatch(MATCH* newMatch) {
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

void freeMatches() {
    Node* curr = matches;
    while (curr != nullptr) {
        Node* next = curr->next;
        free(curr->match);
        free(curr);
        curr = next;
    }
    matches = nullptr;
}

void printMatchesWideChar(int length) {
    Node* head = matches;
    Node* curr = head;
    int size = length * sizeof(WCHAR) + 1; // 16bit wide chars + null terminator
    WCHAR* remote_value = (WCHAR*)malloc(size * sizeof(WCHAR));

    while (curr != nullptr) {
        MATCH* match = curr->match;
        if (!ReadProcessMemory(match->memblock->hProc, match->address, remote_value, size, NULL)) {
            printf("Error reading updated value of match: %p\nError id: %d\nError msg: %ls\n", match->address, GetLastError(), getLastErrorStr());
        }
        printf("\nMemblock ID: %d Address: 0x%llx Value: %ls\n", match->memblock_id, match->address, remote_value);

        curr = curr->next;
    }
}

void printMatches(int dataType)
{
    switch (dataType)
    {
    case type_byte:
        printf("not implemented");
        break;
    case type_char:
        printf("not implemented");
        break;
    case type_float:
        printf("not implemented");
        break;
    case type_double:
        printMatchesDouble();
        break;
    case type_short:
        printf("not implemented");
        break;
    case type_int:
        printMatchesInt();
        break;
    case type_long_int:
        printf("not implemented");
        break;
    }

    return;
}

void printMatchesInt() 
{
    Node* head = matches;
    Node* curr = head;
    int size = sizeof(int);
    int remote_value;

    while (curr != nullptr) {
        MATCH* match = curr->match;
        if (!ReadProcessMemory(match->memblock->hProc, match->address, &remote_value, size, NULL)) {
            printf("Error reading updated value of match: %p\nError id: %d\nError msg: %ls\n", match->address, GetLastError(), getLastErrorStr());
        }
        printf("\nMemblock ID: %d Address: 0x%llx Value: %d\n", match->memblock_id, match->address, remote_value);

        curr = curr->next;
    }
}

void printMatchesDouble()
{
    Node* head = matches;
    Node* curr = head;
    double size = sizeof(double);
    double remote_value;

    while (curr != nullptr) {
        MATCH* match = curr->match;
        if (!ReadProcessMemory(match->memblock->hProc, match->address, &remote_value, size, NULL)) {
            printf("Error reading updated value of match: %p\nError id: %d\nError msg: %ls\n", match->address, GetLastError(), getLastErrorStr());
        }
        printf("\nMemblock ID: %d Address: 0x%llx Value: %f\n", match->memblock_id, match->address, remote_value);

        curr = curr->next;
    }
}


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
        case type_long_int:
            return 8;
    }
}
