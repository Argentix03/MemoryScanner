// Memscan - A memory scanner
#include <Windows.h>
#include <stdio.h>

#define WRITEABLE_MEM (PAGE_READWRITE | PAGE_WRITECOPY | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY)

//flags

// used to discard unwritable memory (not that we technically cant write to it but that its probably not a value in the game we care about changing)
// literal strings and resources may be here, code. might seperate this later to a choice of RO/RW/X etc.
bool writable_only = false;

// set with the argument "-debug". debug currently will print skipped memory and every virtualQuery.
bool debug = false;


//structs

// A struct to hold memory blocks (memory regions with the same protection). 
// A memory address will associate with a block in order to maintain metadata such as memory protections and module rva.
// the blocks are enumerated using VirtualQueryEx and the MEMORY_BASIC_INFORMATION of each region is saved in the block
typedef struct _MEMORYBLOCK
{
    HANDLE hProc;
    PVOID addr;
    int size;
    PVOID buffer;
    MEMORY_BASIC_INFORMATION mbi;
    struct _MEMORYBLOCK *next;
} MBLOCK;


// Prototypes
wchar_t* getLastErrorStr();
char* getStringProtection(DWORD);
MBLOCK* createMemBlock(HANDLE hProc, MEMORY_BASIC_INFORMATION mbi);
char* getStringState(DWORD);
WCHAR* getLastErrorStr();
void printScan(MBLOCK*);
void closeScan(MBLOCK*);
MBLOCK* startScan(int pid);
void freeMemBlock(MBLOCK*);


// Convert MEMORY_BASIC_INFORMATION.Protect into comfy string representation.
// Return a pointer to a newly allocated string.
char* getStringProtection(DWORD protection)
{
    // Constants defined as DWORD in winnt.h, more information can be found at:
    // https://learn.microsoft.com/en-us/windows/win32/memory/memory-protection-constants
    char buf[30];
    char* protection_string = (char*)calloc(sizeof(char), sizeof(buf));
    if (!protection) {
        strcpy_s(buf, "No query permission");
        strcpy_s(protection_string, sizeof(buf), buf);
        return protection_string;
    }

    strcpy_s(buf, "Memory Permissions: ");
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
    if (protection == PAGE_GUARD) // 0x100
        strcat_s(buf, "+G");
    else if (protection == PAGE_NOCACHE) //0x200
        strcat_s(buf, "+NOCACHE");
    else if (protection == PAGE_WRITECOMBINE) // 0x400
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
    MBLOCK *mb =(MBLOCK *) malloc(sizeof(MBLOCK));
    if (mb) {
        mb->addr = meminfo.BaseAddress;
        mb->hProc = hProc;
        mb->size = meminfo.RegionSize;
        mb->buffer = malloc(meminfo.RegionSize);
        // actually insert data to the buffer
        mb->mbi = meminfo;
    }

    return mb;
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
    MBLOCK *memlist = NULL;
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
        addr = (BYTE *)(mbi.BaseAddress) + mbi.RegionSize;
    } while (VirtualQueryEx(hProc, addr, &mbi, sizeof(mbi)));

    return memlist;
}

// free all memblocks in a memlist 
void closeScan(MBLOCK *memlist)
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
        const char *mem_protect = getStringProtection(mb->mbi.Protect);
        printf("0x%p\t", addr); // address
        printf("%8lu KB\t", size_kb); // size
        printf("%s\t", mem_state);  // commit state
        printf("%s\n", mem_protect);  // permissions
        mb = mb->next;
    }

    return;
}

// This one is insanely good...
WCHAR * getLastErrorStr() 
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
    if (argc < 2) {
        printf("Usage: memscan.exe <pid> [-writable_mem] [-debug]\n");
        return 1;
    }
    int pid = atoi(argv[1]);
    if (argc >= 3) 
        writable_only = strcmp(argv[2], "-writable_mem") ? false : true;
    if (argc >= 4)
        debug = strcmp(argv[3], "-debug") ? false : true;

        
    // scan game
    printf("Starting scan\n");
    MBLOCK* scanResults = startScan(pid);
    if (!scanResults) {
        printf("Scan failed\n");
        return 1;
    }

    printScan(scanResults);

    return 0;
}
