# MemoryScanner
its a memory scanner.

## Getting Started

### Prerequisites

**Rust port** (in `rust/`)

- [Rust toolchain](https://rustup.rs/) (stable, 1.77+)
- Windows GNU cross-compilation target:
  ```sh
  rustup target add x86_64-pc-windows-gnu
  ```
- A MinGW-w64 linker — install via your package manager, e.g.:
  ```sh
  # Debian / Ubuntu
  sudo apt install gcc-mingw-w64-x86-64
  # Arch
  sudo pacman -S mingw-w64-gcc
  ```
  On Windows with the MSVC toolchain you can skip MinGW and just use
  `--target x86_64-pc-windows-msvc`.

**C++ port** (in `Memory Scanner/`, `Test/`, `PlayersTests/`)

- Windows + Visual Studio 2019 or later (the `.sln` / `.vcxproj` files are
  included). Open `Memory Scanner.sln` and build from there.

---

### Rust — compile-check (any OS)

```sh
cd rust
cargo check --target x86_64-pc-windows-gnu
```

### Rust — build all binaries (Windows or cross-compile)

```sh
cd rust
cargo build --release --target x86_64-pc-windows-gnu
```

Outputs land in `rust/target/x86_64-pc-windows-gnu/release/`:

| Binary | Purpose |
|---|---|
| `memscan.exe` | The memory scanner |
| `test_target.exe` | Simple int / pointer test target |
| `players_test.exe` | Complex struct / pointer-path test target |

### Rust — run unit tests (Windows only)

The 71 unit tests cover all pure-logic functions (type-size lookups,
protection-flag formatting, match-list operations, in-memory buffer scans, etc.).
They must be run **on Windows** because the `windows` crate links to Win32.

With the default MSVC toolchain (no extra flags needed):

```sh
cd rust
cargo test
```

Or explicitly with the GNU toolchain:

```sh
cd rust
cargo test --target x86_64-pc-windows-gnu
```

Expected output: `test result: ok. 71 passed; 0 failed`

---

### Manual integration testing (Windows)

1. Build both binaries (see above).
2. In one terminal, run a test target and note the PID it prints:
   ```
   test_target.exe
   # or
   players_test.exe
   ```
3. In a second **elevated** terminal (Administrator), run the scanner and
   enter the PID when prompted:
   ```
   memscan.exe
   ```
4. Follow the interactive scanner menu to attach, scan, filter, freeze, and
   write values in the test target process.

---


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
- [x] Add freeze/unfreeze values (Continuous WPM is enough for basic prodding on a value from the tool)
- [ ] Implement generic speedhacks (hook game ticks to fake time etc.)
- [ ] Parsing the process's PE headers and import tables to determine which DLLs are loaded and which functions are being used. This can help identify memory regions that are being used for code or data from a particular DLL
- [ ] Check stack and heap to identify memory regions that are being used for local variables, function arguments, or dynamically allocated memory
- [ ] Identify memory regions that are being used for thread stacks
- [ ] Identify memory regions that are being used for shared memory or other inter-process communication mechanisms
- [ ] Write tidbit more complex apps with various defences
- [ ] Learn proper c++ and rewrite everything so it doesnt look like a 10 year old kids code
