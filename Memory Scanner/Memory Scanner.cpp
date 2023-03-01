// Memscan - A memory scanner
#include <Windows.h>
#include <stdio.h>
#include "memhelpers.h"

#define WRITEABLE_MEM (PAGE_READWRITE | PAGE_WRITECOPY | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY)
wchar_t* getLastErrorStr();
bool writable_only = false;
bool debug = false;

// explain
typedef struct _MEMORYBLOCK
{
    HANDLE hProc;
    PVOID addr;
    int size;
    PVOID buffer;
    MEMORY_BASIC_INFORMATION* mbi;
    struct _MEMORYBLOCK *next;
} MBLOCK;

// flag used to discard unwritable memory (not that we technically cant write to it but that its probably not a value in the game we care about changing)
// for example literal strings and resources may be here, code. maybe seperate this late to a choice of RO/RW/X etc.


// explain
MBLOCK* createMemBlock(HANDLE hProc, MEMORY_BASIC_INFORMATION *meminfo)
{
    MBLOCK *mb =(MBLOCK *) malloc(sizeof(MBLOCK));
    if (mb) {
        mb->addr = meminfo->BaseAddress;
        mb->hProc = hProc;
        mb->size = meminfo->RegionSize;
        mb->buffer = malloc(meminfo->RegionSize);
        mb->mbi = meminfo;
    }

    return mb;
}

// explain
void freeMemBlock(MBLOCK* mb)
{
    if (!mb)
        return;

    if (mb->buffer) {
        free(mb->buffer);
    }
}

// explain
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
            MBLOCK* memblock = createMemBlock(hProc, &mbi);
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

void closeScan(MBLOCK *memlist)
{
    do {
        CloseHandle(memlist->hProc);
        MBLOCK* mb = memlist;
        freeMemBlock(mb);
    } while (memlist = memlist->next);

    return;
}

void printScan(MBLOCK* memlist)
{
    MBLOCK* mb = memlist;

    while (mb) {
        unsigned long int size_kb = mb->size >> 10;
        PVOID addr = mb->addr;
        const char *mem_protect = ProtectionToString(mb->mbi->Protect);
        const char *mem_alloc_protect = ProtectionToString(mb->mbi->AllocationProtect);
        printf("0x%p\t", addr);
        printf("0x%8llu KB\t", size_kb);
        printf("%s\t", mem_protect);
        printf("%s\n", mem_alloc_protect);
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
