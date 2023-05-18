# MemoryScanner
its a memory scanner.


Goal:
Explore and experiment with all this cool stuff:

## Explored Topics
- About memory analysis
    - Traditional step-through debugging vs memory analysis.
    - Hunting for interesting memory.
    - Memory allocation in Windows.
    - Memory relocations, VA, RVA.
- Possible different implementation for memory scanning:
    - 32bit's 0 to 0x7FFFFFFF (4GB) scans vs 64bit memory region enumeration.
    - Persistent addresses.
    - Mass calling memory API's vs cloning memory and internal scanning.
    - Suspending target process.
    - Pointer path mapping.
    - Freezing values.
    - Speedhacks.
    - Tracing memory access.
- Include study of common security tactics:
    - 3rd party Anti-Cheats vs self protections
    - Address rotation.
    - Module enumeration (dll injection and sideloading detection).
    - Using ridiculously precise floating values.
    - Memory integrity sweeps. checking all memory region protections, checksum for code regions. etc.
    - Hiding memory regions (eg. Yumekage).
    - Classic anti-tampering. handle manipulation, etc.
    - Memory monitoring, profiling and analytics.
    - Implementing at least one of my own silly detections.

## Todo List

- [x] Create structs and linked list and stuff to hold memory, matches and metadata
- [x] Map memory protections and allocation states
- [x] Parse memory regions into memblocks
- [x] Implement core search logic
- [x] Add filtering functionality
- [x] Implement scans for various data types
- [x] Save matches (addresses)
- [x] Write small deterministic apps to test on
- [x] Add hotkey to pause/resume target process
- [x] Provide extended information on modules and relative/static addresses and commit types. Add 'use' for mapped/image
- [x] Pointer path tracing (pointermaps)
- [ ] Implement tracing functionality for reads/writes to saved addresses
- [ ] Add freeze/unfreeze values (Continuous WPM is enough for basic prodding on a value from the tool)
- [ ] Implement generic speedhacks (hook game ticks to fake time etc.)
- [ ] Parsing the process's PE headers and import tables to determine which DLLs are loaded and which functions are being used. This can help identify memory regions that are being used for code or data from a particular DLL
- [ ] Check stack and heap to identify memory regions that are being used for local variables, function arguments, or dynamically allocated memory
- [ ] Identify memory regions that are being used for thread stacks
- [ ] Identify memory regions that are being used for shared memory or other inter-process communication mechanisms
- [ ] Write tidbit more complex apps with various defences
- [ ] Learn proper c++ and rewrite everything so it doesnt look like a 10 year old kids code
