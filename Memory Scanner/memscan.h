#pragma once
#include <Windows.h>
#include <unordered_set>

// set of windows constants for memory protections indicating the memory is writable
#define WRITEABLE_MEM (PAGE_READWRITE | PAGE_WRITECOPY | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY)

#define NOT_IMPLEMENTED "Not yet implemented\n"

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

// enum for different data types for different types of pattern searches
enum HUNTING_TYPE {
    type_null = 0,
    type_byte,
    type_char,
    type_short,
    type_int,
    type_float,
    type_double,
    type_long_long_int,
    type_pointer
};

// enum for freeze/unfreeze
enum FREEZE_ACTION {
    action_freeze,
    action_unfreeze
};

// for freeze/unfreeze handler thread
typedef struct _freezeRequest {
    uintptr_t address;
    uintptr_t value;
    FREEZE_ACTION action;
    HANDLE unfreeze_event;
    HANDLE hProc;
} FreezeRequest;

// hold individual matches
typedef struct _MATCH {
    long long int id;
    int memblock_id;
    bool isStatic;
    PVOID address;
    MBLOCK* memblock;
    HUNTING_TYPE type;
    HUNTING_TYPE pointTotype;  // user supplied in saved addresses or known when doing pointerscan/map for saved address
    FreezeRequest* freeze;
} MATCH;

// for the sorted list of matches
struct Node {
    MATCH* match;
    Node* next;
};

// for the pointer paths
struct PointerPath {
    const MATCH* match;
    int offset;
    PointerPath* next;
};

// for the pointer maps
struct PointerMap {
    PointerPath* pathHead;
    PointerMap* next;
};

// enum for various shortcuts
enum SHORTCUT_TYPE {
    shortcut_suspend
};

// hotkeys for shurtcut configurations
typedef struct _HOTKEY {
    int keyId;
    bool CTRL;
    bool ALT;
    bool SHIFT;
    int hotkeyId;
    SHORTCUT_TYPE type;
    HANDLE hProc;
    bool reset;
} HOTKEY;

// number of bytes for offset and pointer calculations
enum DATASIZE {
    size_type_byte = 1,
    size_type_char = 1,
    size_type_short = 2,
    size_type_wchar = 2,
    size_type_int = 4,
    size_type_float = 4,
    size_type_double = 8,
    size_type_long_long_int = 8,
    size_type_pointer = 8
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
void freeMemBlock(const MBLOCK*);
void printBuffer(MBLOCK* mb);
void printUsageAndExit();
bool matchPatternWideChar(long long int addr, const WCHAR pattern[], int pattern_len);
Node* insertMatch(MATCH* newMatch, Node* matches);
void printMatchesWideChar(int length, Node* matches);
Node* filterAddresses(MBLOCK* scanResults, uintptr_t value, int dataType, int data_len, Node* matches);
void printValue(int dataType, uintptr_t value);
int getSizeForType(int dataType);
void freeMatches(Node* matches);
Node* removeMatch(const MATCH* match, Node* matches);
void printMemblock(MBLOCK* mb, bool print_memory);
bool newScanUI();
void filterResultsUI(MBLOCK* scanData);
void intScanUI(MBLOCK* scanData);
void byteScanUI(MBLOCK* scanData);
void charScanUI(MBLOCK* scanData);
void longIntScanUI(MBLOCK* scanData);
void doubleScanUI(MBLOCK* scanData);
void floatScanUI(MBLOCK* scanData);
void wcharScanUI(MBLOCK* scanData);
void shortScanUI(MBLOCK* scanData);
void pointerScanUI(MBLOCK* scanData);
void configureHotkeyUI(MBLOCK* scanData);
void configureHotkey(int keyId, bool CTRL, bool ALT, bool SHIFT, SHORTCUT_TYPE type, HANDLE hProc);
bool suspendTarget(HANDLE hProc, bool toggle);
DWORD WINAPI shortcutHandler(LPVOID lpParam);
char* getStringType(DWORD memType);
void printInsights(const MATCH* match);
void saveMatches(Node* matches);
void savedMatchesUI(MBLOCK* scanData);
void mainMenuUI();
void printMatches(Node* matches);
void scanUI(MBLOCK* scanData, HUNTING_TYPE type);
uintptr_t getUserInputForTypeUI(HUNTING_TYPE type);
int countMatches(const Node* matches);
PointerMap* pointermapScan(MBLOCK* scanData, const MATCH* match, int recurseLevel, PointerPath* pathNode, PointerMap* pointermap, std::unordered_set<uintptr_t> visitedAddresses);
MATCH* getMatchByPrintOrder(Node* matches, int selection);
void pointermapUI(MBLOCK* scanData);
void printPointermap(PointerMap* pointermap);
void printMatch(const MATCH* match);
FreezeRequest* freezeAddress(const MATCH* match, uintptr_t value);
DWORD WINAPI freezeHandler(LPVOID lpFreezeRequest);
bool unfreezeAddress(MATCH* match);
void freezeAddressUI();
void writeAddressUI();
bool writeAddress(MATCH* match, uintptr_t value);