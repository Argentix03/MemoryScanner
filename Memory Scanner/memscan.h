#pragma once
#include <Windows.h>

// set of windows constants for memory protections indicating the memory is writable
#define WRITEABLE_MEM (PAGE_READWRITE | PAGE_WRITECOPY | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY)

// A struct to hold memory blocks (memory regions with the same protection). 
// A memory address will associate with a block in order to maintain metadata such as memory protections and module rva.
// the blocks are enumerated using VirtualQueryEx and the MEMORY_BASIC_INFORMATION of each region is saved in the block
typedef struct _MEMORYBLOCK {
    int id;
    HANDLE hProc;
    PVOID addr;
    int size;
    PVOID buffer;
    MEMORY_BASIC_INFORMATION mbi;
    struct _MEMORYBLOCK* next;
} MBLOCK;

// hold individual matches
typedef struct _MATCH {
    int memblock_id;
    PVOID address;
    MBLOCK* memblock;
} MATCH;

// for the sorted list of matches
struct Node {
    MATCH* match;
    Node* next;
};

// enum for different data types for different types of pattern searches
enum HUNTING_TYPE {
    type_byte,
    type_char,
    type_int,
    type_float,
    type_double,
    type_long_int
};

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
void printBuffer(MBLOCK* mb);
void printUsageAndExit();
bool matchPatternWideChar(long long int addr, const WCHAR pattern[], int pattern_len);
Node* insertMatch(MATCH* newMatch);
void printMatchesWideChar(int length);