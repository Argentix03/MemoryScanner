#![allow(
    non_snake_case,
    dead_code,
    clippy::not_unsafe_ptr_arg_deref,
    clippy::missing_safety_doc
)]

use std::collections::HashSet;
use std::ffi::c_void;
use std::io::{self, Write};
use std::sync::atomic::{AtomicBool, AtomicI32, AtomicI64, AtomicIsize, Ordering};
use std::sync::{Mutex, OnceLock};

use windows::Win32::Foundation::{
    CloseHandle, GetLastError, FALSE, HANDLE, HMODULE, HWND, WAIT_OBJECT_0, WAIT_TIMEOUT,
};
use windows::Win32::System::Diagnostics::Debug::{
    FormatMessageW, ReadProcessMemory, WriteProcessMemory, FORMAT_MESSAGE_FROM_SYSTEM,
    FORMAT_MESSAGE_IGNORE_INSERTS,
};
use windows::Win32::System::LibraryLoader::{GetModuleHandleW, GetProcAddress};
use windows::Win32::System::Memory::{
    MEM_COMMIT, MEM_IMAGE, MEM_MAPPED, MEM_PRIVATE, MEM_RESERVE, MEMORY_BASIC_INFORMATION,
    PAGE_EXECUTE, PAGE_EXECUTE_READ, PAGE_EXECUTE_READWRITE, PAGE_EXECUTE_WRITECOPY, PAGE_GUARD,
    PAGE_NOACCESS, PAGE_NOCACHE, PAGE_PROTECTION_FLAGS, PAGE_READONLY, PAGE_READWRITE,
    PAGE_TARGETS_INVALID, PAGE_WRITECOMBINE, PAGE_WRITECOPY, VirtualQueryEx,
};
use windows::Win32::System::ProcessStatus::GetModuleFileNameExW;
use windows::Win32::System::Threading::{
    CreateEventW, CreateThread, OpenProcess, SetEvent, Sleep, WaitForSingleObject, INFINITE,
    PROCESS_QUERY_INFORMATION, PROCESS_SUSPEND_RESUME, PROCESS_VM_READ, PROCESS_VM_WRITE,
    THREAD_CREATION_FLAGS,
};
use windows::Win32::UI::Input::KeyboardAndMouse::{
    GetAsyncKeyState, RegisterHotKey, HOT_KEY_MODIFIERS, MOD_ALT, MOD_CONTROL, MOD_NOREPEAT,
    MOD_SHIFT, VK_CONTROL, VK_DOWN, VK_END, VK_ESCAPE, VK_HOME, VK_LCONTROL, VK_LEFT,
    VK_LMENU, VK_LSHIFT, VK_MENU, VK_RCONTROL, VK_RIGHT, VK_RMENU, VK_RSHIFT, VK_SHIFT, VK_TAB,
    VK_UP,
};
use windows::Win32::UI::WindowsAndMessaging::{
    GetMessageW, PeekMessageW, MSG, PM_NOREMOVE, WM_HOTKEY,
};
use windows::core::{PCWSTR, PWSTR};

// ─── constants ──────────────────────────────────────────────────────────────

const WRITEABLE_MEM: u32 = 0x04 | 0x08 | 0x40 | 0x80; // PAGE_READWRITE|WRITECOPY|EXEC_READWRITE|EXEC_WRITECOPY
const NOT_IMPLEMENTED: &str = "Not yet implemented\n";
const MAX_PATH: usize = 260;

// ─── enums ───────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(C)]
enum HuntingType {
    Null = 0,
    Byte,
    Char,
    Short,
    Int,
    Float,
    Double,
    LongLongInt,
    Pointer,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum FreezeAction {
    Freeze,
    Unfreeze,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ShortcutType {
    Suspend,
}

// ─── structs ─────────────────────────────────────────────────────────────────

struct MemBlock {
    id: i32,
    h_proc: HANDLE,
    addr: *mut c_void,
    size: usize,
    buffer: Vec<u8>,
    mbi: MEMORY_BASIC_INFORMATION,
}

// HANDLE is *mut c_void internally; we manage lifetime carefully
unsafe impl Send for MemBlock {}
unsafe impl Sync for MemBlock {}

struct FreezeRequest {
    address: usize,
    value: usize,
    action: FreezeAction,
    unfreeze_event: HANDLE,
    h_proc: HANDLE,
}

unsafe impl Send for FreezeRequest {}
unsafe impl Sync for FreezeRequest {}

struct Match {
    id: i64,
    memblock_id: i32,
    is_static: bool,
    address: *mut c_void,
    memblock: *mut MemBlock, // raw pointer – same lifetime semantics as C++
    data_type: HuntingType,
    point_to_type: HuntingType,
    freeze: *mut FreezeRequest, // null when not frozen
}

unsafe impl Send for Match {}
unsafe impl Sync for Match {}

struct Hotkey {
    key_id: i32,
    ctrl: bool,
    alt: bool,
    shift: bool,
    hotkey_id: i32,
    shortcut_type: ShortcutType,
    h_proc: HANDLE,
    reset: bool,
}

unsafe impl Send for Hotkey {}
unsafe impl Sync for Hotkey {}

// Pointer-map helper structures (mirror the C++ linked lists)
struct PointerPathNode {
    match_ptr: *const Match,
    offset: i32,
    next: *mut PointerPathNode,
}

struct PointerMapNode {
    path_head: *mut PointerPathNode,
    next: *mut PointerMapNode,
}

// ─── global state ────────────────────────────────────────────────────────────

static WRITABLE_ONLY: AtomicBool = AtomicBool::new(false);
static DEBUG_MODE: AtomicBool = AtomicBool::new(false);
static MEMBLOCK_COUNTER: AtomicI32 = AtomicI32::new(0);
static SHORTCUT_COUNTER: AtomicI32 = AtomicI32::new(0);
static MATCH_COUNTER: AtomicI64 = AtomicI64::new(0);

// Store HANDLE as isize (HANDLE is *mut c_void = isize on Windows)
static HOTKEYS_READY_EVENT: AtomicIsize = AtomicIsize::new(0);

fn hotkeys_ready_event() -> HANDLE {
    HANDLE(HOTKEYS_READY_EVENT.load(Ordering::SeqCst) as *mut c_void)
}

static G_SAVED_MATCHES: OnceLock<Mutex<Vec<Box<Match>>>> = OnceLock::new();

fn g_saved_matches() -> &'static Mutex<Vec<Box<Match>>> {
    G_SAVED_MATCHES.get_or_init(|| Mutex::new(Vec::new()))
}

// shortcuts[5] equivalent
static SHORTCUTS: OnceLock<Mutex<[Option<Box<Hotkey>>; 5]>> = OnceLock::new();

fn shortcuts_global() -> &'static Mutex<[Option<Box<Hotkey>>; 5]> {
    SHORTCUTS.get_or_init(|| Mutex::new([None, None, None, None, None]))
}

// Critical-section equivalent (just std::sync::Mutex on the shortcut counter/array)
static CS: OnceLock<Mutex<()>> = OnceLock::new();

fn cs() -> &'static Mutex<()> {
    CS.get_or_init(|| Mutex::new(()))
}

// ─── Windows helpers ─────────────────────────────────────────────────────────

fn get_last_error_str() -> String {
    unsafe {
        let err = GetLastError().0;
        let mut buf = vec![0u16; 256];
        FormatMessageW(
            FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
            None,
            err,
            0x0400, // MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT)
            PWSTR(buf.as_mut_ptr()),
            256,
            None,
        );
        let end = buf.iter().position(|&c| c == 0).unwrap_or(buf.len());
        String::from_utf16_lossy(&buf[..end])
            .trim_end_matches(['\r', '\n'])
            .to_string()
    }
}

fn get_string_protection(protection: PAGE_PROTECTION_FLAGS) -> String {
    if protection.0 == 0 {
        return "No query permission".to_string();
    }
    let mut buf = String::new();
    let protection_extra = protection;
    let protection_val = protection.0 & 0xff;
    if protection_val == PAGE_EXECUTE.0 {
        buf.push_str("X");
    } else if protection_val == PAGE_EXECUTE_READ.0 {
        buf.push_str("RX");
    } else if protection_val == PAGE_EXECUTE_READWRITE.0 {
        buf.push_str("RWX");
    } else if protection_val == PAGE_EXECUTE_WRITECOPY.0 {
        buf.push_str("WCX");
    } else if protection_val == PAGE_NOACCESS.0 {
        buf.push_str("NA");
    } else if protection_val == PAGE_READONLY.0 {
        buf.push_str("R");
    } else if protection_val == PAGE_READWRITE.0 {
        buf.push_str("RW");
    } else if protection_val == PAGE_WRITECOPY.0 {
        buf.push_str("WC");
    } else if protection_val == PAGE_TARGETS_INVALID.0 {
        buf.push_str("CFG Stuff");
    }
    if protection_extra.0 & PAGE_GUARD.0 != 0 {
        buf.push_str("+G");
    } else if protection_extra.0 & PAGE_NOCACHE.0 != 0 {
        buf.push_str("+NOCACHE");
    } else if protection_extra.0 & PAGE_WRITECOMBINE.0 != 0 {
        buf.push_str("+WRITECOMBINE");
    }
    buf
}

fn get_string_state(state: u32) -> String {
    if state == MEM_COMMIT.0 {
        "MEM_COMMIT".to_string()
    } else if state == 0x10000 {
        // MEM_FREE
        "MEM_FREE".to_string()
    } else if state == MEM_RESERVE.0 {
        "MEM_RESERVE".to_string()
    } else {
        String::new()
    }
}

fn get_string_type(mem_type: u32) -> String {
    if mem_type == MEM_PRIVATE.0 {
        "Private".to_string()
    } else if mem_type == MEM_MAPPED.0 {
        "Mapped".to_string()
    } else if mem_type == MEM_IMAGE.0 {
        "Image".to_string()
    } else {
        String::new()
    }
}

fn get_string_use(mb: &MemBlock) -> String {
    unsafe {
        if mb.mbi.Type == MEM_IMAGE {
            let mut path = vec![0u16; MAX_PATH];
            GetModuleFileNameExW(mb.h_proc, HMODULE(mb.mbi.AllocationBase), &mut path);
            let end = path.iter().position(|&c| c == 0).unwrap_or(path.len());
            String::from_utf16_lossy(&path[..end]).to_string()
        } else {
            String::new()
        }
    }
}

// Find last backslash in a path (PathFindFileNameW equivalent)
fn path_find_file_name(path: &str) -> &str {
    if let Some(pos) = path.rfind('\\') {
        &path[pos + 1..]
    } else {
        path
    }
}

fn get_size_for_type(data_type: HuntingType) -> usize {
    match data_type {
        HuntingType::Byte => 1,
        HuntingType::Char => 1,
        HuntingType::Short => 2,
        HuntingType::Int => 4,
        HuntingType::Float => 4,
        HuntingType::Double => 8,
        HuntingType::LongLongInt => 8,
        HuntingType::Pointer => 8,
        HuntingType::Null => 0,
    }
}

// ─── user input helpers ──────────────────────────────────────────────────────

fn flush_stdout() {
    let _ = io::stdout().flush();
}

fn read_line_raw() -> String {
    let mut line = String::new();
    let _ = io::stdin().read_line(&mut line);
    line.trim_end_matches(['\r', '\n']).to_string()
}

fn read_int() -> i32 {
    let line = read_line_raw();
    line.trim().parse().unwrap_or(0)
}

fn read_char() -> char {
    let line = read_line_raw();
    line.trim().chars().next().unwrap_or('\0')
}

fn read_hex_u64() -> u64 {
    let line = read_line_raw();
    let s = line.trim().trim_start_matches("0x").trim_start_matches("0X");
    u64::from_str_radix(s, 16).unwrap_or(0)
}

fn read_long_long() -> i64 {
    let line = read_line_raw();
    line.trim().parse().unwrap_or(0)
}

// ─── MemBlock functions ──────────────────────────────────────────────────────

fn create_mem_block(h_proc: HANDLE, meminfo: MEMORY_BASIC_INFORMATION) -> Option<Box<MemBlock>> {
    let id = MEMBLOCK_COUNTER.fetch_add(1, Ordering::SeqCst) + 1;
    let size = meminfo.RegionSize;
    let mut buffer = vec![0u8; size];
    unsafe {
        if let Err(_) = ReadProcessMemory(
            h_proc,
            meminfo.BaseAddress as *const c_void,
            buffer.as_mut_ptr() as *mut c_void,
            size,
            None,
        ) {
            let err = GetLastError().0;
            if err != 299 {
                print!(
                    "Error ReadProcessMemory: {}\n{}\n",
                    err,
                    get_last_error_str()
                );
            }
        }
    }
    Some(Box::new(MemBlock {
        id,
        h_proc,
        addr: meminfo.BaseAddress,
        size,
        buffer,
        mbi: meminfo,
    }))
}

fn print_buffer(mb: &MemBlock) {
    print!("Memblock id: {}\nBuffer:\n", mb.id);
    for byte in &mb.buffer {
        print!("{:02x} ", byte);
    }
    println!();
}

fn free_mem_block(mb: &MemBlock) {
    // buffer is a Vec; it will be freed when MemBlock is dropped.
    // This function exists to mirror the C++ freeMemBlock call site.
    let _ = mb;
}

// ─── match list helpers (Vec<Box<Match>>, sorted by address) ────────────────

fn insert_match(new_match: Box<Match>, matches: &mut Vec<Box<Match>>) {
    let addr = new_match.address as usize;
    let pos = matches
        .iter()
        .position(|m| m.address as usize >= addr)
        .unwrap_or(matches.len());
    matches.insert(pos, new_match);
}

fn remove_match(match_to_remove: *const Match, matches: &mut Vec<Box<Match>>) {
    if let Some(pos) = matches.iter().position(|m| m.as_ref() as *const Match == match_to_remove) {
        matches.remove(pos);
    }
}

fn count_matches(matches: &[Box<Match>]) -> usize {
    matches.len()
}

fn get_match_by_print_order(matches: &[Box<Match>], selection: usize) -> Option<&Match> {
    if selection == 0 || selection > matches.len() {
        return None;
    }
    Some(&matches[selection - 1])
}

fn get_match_by_print_order_mut(
    matches: &mut Vec<Box<Match>>,
    selection: usize,
) -> Option<&mut Match> {
    if selection == 0 || selection > matches.len() {
        return None;
    }
    Some(&mut matches[selection - 1])
}

fn save_matches(matches: &[Box<Match>]) {
    let mut saved = g_saved_matches().lock().unwrap();
    for m in matches {
        // Clone the relevant fields; memblock pointer stays the same
        let new_match = Box::new(Match {
            id: m.id,
            memblock_id: m.memblock_id,
            is_static: m.is_static,
            address: m.address,
            memblock: m.memblock,
            data_type: m.data_type,
            point_to_type: m.point_to_type,
            freeze: std::ptr::null_mut(),
        });
        insert_match(new_match, &mut saved);
    }
}

fn print_value(data_type: HuntingType, value: usize) {
    match data_type {
        HuntingType::Byte => print!("{:02x}", value as u8),
        HuntingType::Char => print!("{}", value as u8 as char),
        HuntingType::Float | HuntingType::Double => {
            print!("{}", f64::from_bits(value as u64))
        }
        HuntingType::Short => print!("{}", value as i16),
        HuntingType::Int => print!("{}", value as i32),
        HuntingType::LongLongInt => print!("{}", value as i64),
        HuntingType::Pointer => print!("0x{:p}", value as *const c_void),
        HuntingType::Null => {}
    }
}

fn print_match(m: &Match) {
    let size = std::mem::size_of::<usize>();
    let mut remote_value: usize = 0;
    unsafe {
        let mb = &*m.memblock;
        if let Err(_) = ReadProcessMemory(
            mb.h_proc,
            m.address as *const c_void,
            &mut remote_value as *mut usize as *mut c_void,
            size,
            None,
        ) {
            let err = GetLastError().0;
            if err != 299 {
                print!(
                    "Error reading updated value of match: {:p}\nError id: {}\nError msg: {}\n",
                    m.address,
                    err,
                    get_last_error_str()
                );
            }
        }
    }
    print!(
        "Memblock ID: {} Address: 0x{:p} ",
        m.memblock_id, m.address
    );
    match m.data_type {
        HuntingType::Byte => println!("Value: 0x{:02x}", remote_value as u8),
        HuntingType::Char => println!("Value: {}", remote_value as u8 as char),
        HuntingType::Short => println!("Value: {}", remote_value as i16),
        HuntingType::Int => println!("Value: {}", remote_value as i32),
        HuntingType::Float => println!("Value: {}", f32::from_bits(remote_value as u32)),
        HuntingType::Double => println!("Value: {}", f64::from_bits(remote_value as u64)),
        HuntingType::LongLongInt => println!("Value: {}", remote_value as i64),
        HuntingType::Pointer => {
            if m.point_to_type != HuntingType::Null {
                print!("Value: {:p} (P->", remote_value as *const c_void);
                print_value(m.data_type, remote_value);
                println!(")");
            } else {
                println!("Value: {:p} (Pointer)", remote_value as *const c_void);
            }
        }
        HuntingType::Null => {}
    }
}

fn print_insights(m: &Match) {
    if m.is_static {
        unsafe {
            let mb = &*m.memblock;
            let char_addr = m.address as usize;
            let char_base = mb.mbi.AllocationBase as usize;
            let offset = char_addr.wrapping_sub(char_base) as isize;
            let use_str = get_string_use(mb);
            print!("    [+] Dynamic Address: {} + 0x{:x}\n", use_str, offset);
        }
    }
}

fn print_matches(matches: &[Box<Match>]) {
    for (i, m) in matches.iter().enumerate() {
        print!("{}. ", i + 1);
        print_match(m);
        print_insights(m);
    }
}

fn print_mem_block(mb: &MemBlock, print_memory: bool) {
    let size_kb = mb.size >> 10;
    let addr = mb.addr;
    let mem_state = get_string_state(mb.mbi.State.0);
    let mem_type = get_string_type(mb.mbi.Type.0);
    let mem_protect = get_string_protection(mb.mbi.Protect);
    let mem_use = get_string_use(mb);
    print!("{:<4}\t", mb.id);
    print!("0x{:<18p}\t\t", addr);
    print!("{:>5} KB\t", size_kb);
    print!("{:<7}: {:<5}\t", mem_type, mem_state);
    print!("{:<14}\t", mem_protect);
    println!("{}", mem_use);
    if print_memory {
        print_buffer(mb);
    }
}

fn print_scan(memlist: &[Box<MemBlock>]) {
    println!(
        "{:<4}\t{:<18}\t{:>16}\t{:<20}\t{:<14}\t{}",
        "ID", "Address", "Size", "Type:State", "Permissions", "Use"
    );
    println!("---------------------------------------------------------------------------------------------------");
    for mb in memlist {
        print_mem_block(mb, false);
    }
}

// ─── startScan / closeScan ───────────────────────────────────────────────────

fn start_scan(pid: u32) -> Option<Vec<Box<MemBlock>>> {
    MEMBLOCK_COUNTER.store(0, Ordering::SeqCst);
    let desired_access = PROCESS_VM_READ
        | PROCESS_QUERY_INFORMATION
        | PROCESS_SUSPEND_RESUME
        | PROCESS_VM_WRITE;
    let h_proc = unsafe {
        match OpenProcess(desired_access, FALSE, pid) {
            Ok(h) => h,
            Err(_) => {
                print!(
                    "Error open process handle: {}\n{}\n",
                    GetLastError().0,
                    get_last_error_str()
                );
                return None;
            }
        }
    };

    let mut memlist: Vec<Box<MemBlock>> = Vec::new();
    let mut addr: *mut c_void = std::ptr::null_mut();
    let mbi_size = std::mem::size_of::<MEMORY_BASIC_INFORMATION>();

    // Mirror the C++ do { VQEx; process; advance } while (VQEx) loop.
    // We prime the first VQEx outside, then at loop-end re-query as the "while" check.
    let mut mbi = MEMORY_BASIC_INFORMATION::default();
    if unsafe { VirtualQueryEx(h_proc, Some(addr as *const c_void), &mut mbi, mbi_size) } == 0 {
        return Some(memlist);
    }

    loop {
        if DEBUG_MODE.load(Ordering::Relaxed) {
            print!("VirtualQuery: {:p}\n", addr);
        }

        let mem_committed = (mbi.State.0 & MEM_COMMIT.0) != 0;
        let mem_writable = (mbi.Protect.0 & WRITEABLE_MEM) != 0;

        if mem_committed && (!WRITABLE_ONLY.load(Ordering::Relaxed) || mem_writable) {
            match create_mem_block(h_proc, mbi) {
                Some(mb) => {
                    // Prepend (mirrors: memblock->next = memlist; memlist = memblock)
                    memlist.insert(0, mb);
                }
                None => {
                    print!(
                        "Error creating memblock: {}\n{}\n",
                        unsafe { GetLastError().0 },
                        get_last_error_str()
                    );
                    return Some(memlist);
                }
            }
        } else if DEBUG_MODE.load(Ordering::Relaxed) {
            if !mem_committed {
                print!("Skipping uncommitted memory: {:p}\n", addr);
            } else if !mem_writable {
                print!("Skipping unwritable memory: {:p}\n", addr);
            }
        }

        // Advance address (same as C++: addr = (BYTE*)(mbi.BaseAddress) + mbi.RegionSize)
        addr = unsafe { (mbi.BaseAddress as *mut u8).add(mbi.RegionSize) as *mut c_void };

        // "while (VirtualQueryEx(...))" — re-query next address; break if end of address space
        if unsafe { VirtualQueryEx(h_proc, Some(addr as *const c_void), &mut mbi, mbi_size) } == 0
        {
            break;
        }
    }

    Some(memlist)
}

fn close_scan(memlist: Vec<Box<MemBlock>>) {
    // Close the process handle (held by last block in list, same as C++ which closes on last->next==NULL)
    // In C++: "if (!memlist->next) CloseHandle(memlist->hProc);"
    // We iterate and close the handle on the first block (which was the last in the C++ list)
    if let Some(last) = memlist.last() {
        unsafe {
            let _ = CloseHandle(last.h_proc);
        }
    }
    // Unfreeze all saved matches
    let mut saved = g_saved_matches().lock().unwrap();
    for m in saved.iter_mut() {
        unsafe {
            unfreeze_address_raw(m.as_mut());
        }
    }
    // memlist drops here, freeing all MemBlocks and their buffers
}

// ─── filterAddresses ────────────────────────────────────────────────────────

fn filter_addresses(
    memlist: Option<&[Box<MemBlock>]>,
    value: usize,
    data_type: HuntingType,
    _data_len: usize,
    matches: &mut Vec<Box<Match>>,
) {
    match memlist {
        None => {
            // Filter existing matches
            let size = get_size_for_type(data_type);
            let mut to_remove: Vec<*const Match> = Vec::new();
            for m in matches.iter() {
                let mut remote_value: usize = 0;
                unsafe {
                    let mb = &*m.memblock;
                    if let Err(_) = ReadProcessMemory(
                        mb.h_proc,
                        m.address as *const c_void,
                        &mut remote_value as *mut usize as *mut c_void,
                        size,
                        None,
                    ) {
                        let err = GetLastError().0;
                        if err != 299 {
                            print!(
                                "Error reading updated value of match: {:p}\nError id: {}\nError msg: {}\n",
                                m.address, err, get_last_error_str()
                            );
                        }
                    }
                }
                let matched = value_matches(data_type, remote_value, value);
                if !matched {
                    to_remove.push(m.as_ref() as *const Match);
                }
            }
            for ptr in to_remove {
                remove_match(ptr, matches);
            }
        }
        Some(scan_data) => {
            // Search all memory blocks
            for mb in scan_data.iter() {
                let buf_ptr = mb.buffer.as_ptr() as usize;
                let final_addr = buf_ptr + mb.size;
                let mut membyte = buf_ptr;
                while membyte <= final_addr {
                    let (matched, matched_type) = match data_type {
                        HuntingType::Byte => {
                            let v = unsafe { *(membyte as *const u8) } as usize;
                            (v == (value & 0xFF), HuntingType::Byte)
                        }
                        HuntingType::Char => {
                            let v = unsafe { *(membyte as *const i8) } as usize;
                            (v == (value as i8 as usize), HuntingType::Char)
                        }
                        HuntingType::Short => {
                            let v = unsafe { *(membyte as *const i16) } as usize;
                            (v == (value as i16 as usize), HuntingType::Short)
                        }
                        HuntingType::Int => {
                            let v = unsafe { *(membyte as *const i32) } as usize;
                            (v == (value as i32 as usize), HuntingType::Int)
                        }
                        HuntingType::Float => {
                            let v = unsafe { *(membyte as *const f32) };
                            let target = f32::from_bits(value as u32);
                            (v == target, HuntingType::Float)
                        }
                        HuntingType::Double => {
                            let v = unsafe { *(membyte as *const f64) };
                            let target = f64::from_bits(value as u64);
                            (v == target, HuntingType::Double)
                        }
                        HuntingType::LongLongInt => {
                            let v = unsafe { *(membyte as *const i64) } as usize;
                            (v == value, HuntingType::LongLongInt)
                        }
                        HuntingType::Pointer => {
                            let v = unsafe { *(membyte as *const usize) };
                            (v == value, HuntingType::Pointer)
                        }
                        HuntingType::Null => (false, HuntingType::Null),
                    };
                    if matched {
                        let offset = (membyte - buf_ptr) as isize;
                        let remote_address = (mb.addr as usize).wrapping_add(offset as usize);
                        let is_static = !get_string_use(mb).is_empty();
                        let id = MATCH_COUNTER.fetch_add(1, Ordering::SeqCst);
                        let new_match = Box::new(Match {
                            id,
                            memblock_id: mb.id,
                            is_static,
                            address: remote_address as *mut c_void,
                            memblock: mb.as_ref() as *const MemBlock as *mut MemBlock,
                            data_type: matched_type,
                            point_to_type: HuntingType::Null,
                            freeze: std::ptr::null_mut(),
                        });
                        insert_match(new_match, matches);
                    }
                    membyte += 1;
                }
            }
        }
    }
}

fn value_matches(data_type: HuntingType, remote_value: usize, target: usize) -> bool {
    match data_type {
        HuntingType::Byte => (remote_value as u8) == (target as u8),
        HuntingType::Char => (remote_value as i8) == (target as i8),
        HuntingType::Short => (remote_value as i16) == (target as i16),
        HuntingType::Int => (remote_value as i32) == (target as i32),
        HuntingType::Float => {
            f32::from_bits(remote_value as u32) == f32::from_bits(target as u32)
        }
        HuntingType::Double => {
            f64::from_bits(remote_value as u64) == f64::from_bits(target as u64)
        }
        HuntingType::LongLongInt => (remote_value as i64) == (target as i64),
        HuntingType::Pointer => remote_value == target,
        HuntingType::Null => false,
    }
}

fn write_address(m: &Match, value: usize) -> bool {
    let size = get_size_for_type(m.data_type);
    unsafe {
        let mb = &*m.memblock;
        match WriteProcessMemory(
            mb.h_proc,
            m.address as *const c_void,
            &value as *const usize as *const c_void,
            size,
            None,
        ) {
            Ok(_) => true,
            Err(_) => {
                let err = GetLastError().0;
                print!(
                    "Error writing value 0x{:x} ({}) for match: {:p}\nError id: {}\nError msg: {}\n",
                    value, value as i64, m.address, err, get_last_error_str()
                );
                print!("number of bytes written: 0\n");
                false
            }
        }
    }
}

// ─── freeze / unfreeze ───────────────────────────────────────────────────────

unsafe extern "system" fn freeze_handler(lp_freeze_request: *mut c_void) -> u32 {
    let ms_wait: u32 = 16; // ~60 FPS
    // Use a raw pointer (not Box::from_raw) — the main thread owns this allocation,
    // mirroring C++: FreezeRequest* fr = (FreezeRequest*)lpFreezeRequest;
    let fr = &*(lp_freeze_request as *const FreezeRequest);
    loop {
        let value = fr.value;
        unsafe {
            let addr = fr.address as *const c_void;
            if let Err(_) = WriteProcessMemory(
                fr.h_proc,
                addr,
                &value as *const usize as *const c_void,
                std::mem::size_of::<usize>(),
                None,
            ) {
                print!(
                    "Error writing value 0x{:x} to address: {:p}\nError id: {}\nError msg: {}\n",
                    fr.value,
                    fr.address as *const c_void,
                    GetLastError().0,
                    get_last_error_str()
                );
            }
        }
        let wait_result = unsafe { WaitForSingleObject(fr.unfreeze_event, ms_wait) };
        if wait_result == WAIT_TIMEOUT {
            continue;
        } else if wait_result == WAIT_OBJECT_0 {
            break;
        } else {
            print!(
                "Unexpected results from WaitForSingleObject: 0x{:x}\nError id: {}\nError msg: {}\n",
                wait_result.0,
                unsafe { GetLastError().0 },
                get_last_error_str()
            );
            break;
        }
    }
    1
}

fn freeze_address(m: &Match, value: usize) -> *mut FreezeRequest {
    let unfreeze_event = unsafe {
        CreateEventW(None, FALSE, FALSE, PCWSTR::null())
            .expect("CreateEventW failed for freeze")
    };
    let fr = Box::new(FreezeRequest {
        action: FreezeAction::Freeze,
        address: m.address as usize,
        value,
        h_proc: unsafe { (*m.memblock).h_proc },
        unfreeze_event,
    });
    let fr_ptr = Box::into_raw(fr);
    unsafe {
        let _ = CreateThread(
            None,
            0,
            Some(freeze_handler),
            Some(fr_ptr as *const c_void),
            THREAD_CREATION_FLAGS(0),
            None,
        )
        .expect("CreateThread failed for freezeHandler");
    }
    fr_ptr
}

/// Unfreeze and free the FreezeRequest; sets m.freeze to null.
/// Caller must hold no lock over m.
unsafe fn unfreeze_address_raw(m: &mut Match) -> bool {
    if m.freeze.is_null() {
        return false;
    }
    let fr = &*m.freeze;
    if SetEvent(fr.unfreeze_event).is_err() {
        print!("SetEvent failed ({})\n", GetLastError().0);
        return false;
    }
    // Free the FreezeRequest (thread owns the Box; we already signaled it to stop,
    // but to match C++ free() behavior we drop it here)
    drop(Box::from_raw(m.freeze));
    m.freeze = std::ptr::null_mut();
    true
}

// ─── suspendTarget ───────────────────────────────────────────────────────────

fn suspend_target(h_proc: HANDLE, toggle: bool) -> bool {
    unsafe {
        let ntdll = match GetModuleHandleW(windows::core::w!("ntdll.dll")) {
            Ok(h) => h,
            Err(_) => {
                print!(
                    "Error getting addresses for suspend/resume from ndtll: {}\n{}\n",
                    GetLastError().0,
                    get_last_error_str()
                );
                return false;
            }
        };

        type NtSuspendFn = unsafe extern "system" fn(HANDLE) -> i32;
        type NtResumeFn = unsafe extern "system" fn(HANDLE) -> i32;

        let nt_suspend_proc =
            GetProcAddress(ntdll, windows::core::s!("NtSuspendProcess"));
        let nt_resume_proc =
            GetProcAddress(ntdll, windows::core::s!("NtResumeProcess"));

        if let (Some(suspend_fn), Some(resume_fn)) = (nt_suspend_proc, nt_resume_proc) {
            let nt_suspend: NtSuspendFn = std::mem::transmute(suspend_fn);
            let nt_resume: NtResumeFn = std::mem::transmute(resume_fn);
            let result = if toggle {
                nt_suspend(h_proc)
            } else {
                nt_resume(h_proc)
            };
            // NT_SUCCESS: result >= 0
            if result < 0 {
                print!(
                    "Error suspend or resume process: {}\n{}\n",
                    GetLastError().0,
                    get_last_error_str()
                );
                return false;
            }
        } else {
            print!(
                "Error getting addresses for suspend/resume from ndtll: {}\n{}\n",
                GetLastError().0,
                get_last_error_str()
            );
            return false;
        }
    }
    true
}

// ─── shortcutHandler (Windows thread proc) ──────────────────────────────────

unsafe extern "system" fn shortcut_handler(_lp_param: *mut c_void) -> u32 {
    let mut msg = MSG::default();
    let mut toggle = true;

    // Wait until hotkeys have been registered
    WaitForSingleObject(hotkeys_ready_event(), INFINITE);

    loop {
        // Check if any hotkey needs (re-)registration
        {
            let shortcut_count = SHORTCUT_COUNTER.load(Ordering::SeqCst) as usize;
            for i in 0..shortcut_count {
                let needs_reset = {
                    let guard = shortcuts_global().lock().unwrap();
                    guard[i].as_ref().map(|s| s.reset).unwrap_or(false)
                };
                if needs_reset {
                    let _guard = cs().lock().unwrap();
                    let mut shortcuts_guard = shortcuts_global().lock().unwrap();
                    if let Some(shortcut) = shortcuts_guard[i].as_mut() {
                        let mut mods = MOD_NOREPEAT;
                        if shortcut.ctrl {
                            mods = HOT_KEY_MODIFIERS(mods.0 | MOD_CONTROL.0);
                        }
                        if shortcut.alt {
                            mods = HOT_KEY_MODIFIERS(mods.0 | MOD_ALT.0);
                        }
                        if shortcut.shift {
                            mods = HOT_KEY_MODIFIERS(mods.0 | MOD_SHIFT.0);
                        }
                        let result =
                            RegisterHotKey(HWND(std::ptr::null_mut()), i as i32, mods, shortcut.key_id as u32);
                        shortcut.reset = false;
                        match result {
                            Err(_) => {
                                print!(
                                    "Error registering hotkey: {}\n{}\n",
                                    GetLastError().0,
                                    get_last_error_str()
                                );
                            }
                            Ok(_) => {
                                print!(
                                    "Registered hotkey {} {} {} {} (0x{:02x})\n",
                                    if shortcut.ctrl { "CTRL +" } else { "" },
                                    if shortcut.alt { "ALT +" } else { "" },
                                    if shortcut.shift { "SHIFT +" } else { "" },
                                    shortcut.key_id as u8 as char,
                                    shortcut.key_id
                                );
                            }
                        }
                    }
                }
            }
        }

        // Message pump
        if PeekMessageW(
            &mut msg,
            HWND(std::ptr::null_mut()),
            0,
            0,
            PM_NOREMOVE,
        )
        .as_bool()
        {
            if msg.message == WM_HOTKEY {
                let _ = GetMessageW(&mut msg, HWND(std::ptr::null_mut()), 0, 0);
                let idx = msg.wParam.0;
                let h_proc = {
                    let guard = shortcuts_global().lock().unwrap();
                    guard[idx].as_ref().map(|s| {
                        (s.shortcut_type, s.h_proc)
                    })
                };
                if let Some((ShortcutType::Suspend, h_proc)) = h_proc {
                    suspend_target(h_proc, toggle);
                    toggle = !toggle;
                }
            }
        }
    }
}

// ─── pointer-map scan ────────────────────────────────────────────────────────

static POINTER_SCAN_COUNTER: AtomicI32 = AtomicI32::new(1);

unsafe fn pointermap_scan(
    scan_data: &[Box<MemBlock>],
    match_ref: *const Match,
    recurse_level: i32,
    path_node: *mut PointerPathNode,
    pointermap: *mut PointerMapNode,
    visited_addresses: HashSet<usize>,
) -> *mut PointerMapNode {
    if recurse_level <= 0 {
        return pointermap;
    }

    let mut pointermap = if pointermap.is_null() {
        let pm = Box::new(PointerMapNode {
            path_head: std::ptr::null_mut(),
            next: std::ptr::null_mut(),
        });
        Box::into_raw(pm)
    } else {
        pointermap
    };

    let guess_size: usize = 100;
    let base_address = (*match_ref).address as usize;
    let mut visited_addresses = visited_addresses;

    for offset in 0..guess_size {
        let search_addr = base_address.wrapping_sub(offset);
        let mut local_matches: Vec<Box<Match>> = Vec::new();
        filter_addresses(
            Some(scan_data),
            search_addr,
            HuntingType::Pointer,
            1,
            &mut local_matches,
        );
        if local_matches.is_empty() {
            continue;
        }

        for found_match in local_matches.iter() {
            let m_addr = found_match.address as usize;

            // Check if already in path
            let mut match_in_path = false;
            let mut path = path_node;
            while !path.is_null() {
                if (*path).match_ptr as usize == found_match.as_ref() as *const Match as usize {
                    match_in_path = true;
                    break;
                }
                path = (*path).next;
            }

            let address_visited = visited_addresses.contains(&m_addr);

            if !match_in_path && !address_visited {
                visited_addresses.insert(m_addr);

                let new_path_node = Box::into_raw(Box::new(PointerPathNode {
                    match_ptr: found_match.as_ref() as *const Match,
                    offset: offset as i32,
                    next: path_node,
                }));

                // Print the path
                let counter = POINTER_SCAN_COUNTER.fetch_add(1, Ordering::SeqCst);
                print!("{}:\tAddress: ", counter);
                let mut print_path = new_path_node;
                let mut print_offset = 0i32;
                while !print_path.is_null() {
                    if print_offset != 0 {
                        print!("[+ 0x{:x}] ", print_offset);
                    }
                    print!("{:p} -> ", (*print_path).match_ptr as *const c_void);
                    print_offset = (*print_path).offset;
                    if (*print_path).next.is_null() {
                        if print_offset != 0 {
                            print!("[+ 0x{:x}] ", print_offset);
                        }
                        print!("(target)\n");
                    }
                    print_path = (*print_path).next;
                }

                if (*pointermap).path_head.is_null() {
                    (*pointermap).path_head = new_path_node;
                } else {
                    let tmp = Box::into_raw(Box::new(PointerMapNode {
                        path_head: new_path_node,
                        next: pointermap,
                    }));
                    pointermap = tmp;
                }

                pointermap = pointermap_scan(
                    scan_data,
                    found_match.as_ref() as *const Match,
                    recurse_level - 1,
                    new_path_node,
                    pointermap,
                    visited_addresses.clone(),
                );
            }
        }
    }

    pointermap
}

unsafe fn print_pointermap(pointermap: *mut PointerMapNode) {
    println!("\n==Simple print==");
    let mut tmp = pointermap;
    let mut count = 0i32;
    while !tmp.is_null() {
        count += 1;
        let mut path = (*tmp).path_head;
        print!("{}:\tAddress: ", count);
        let mut offset = 0i32;
        while !path.is_null() {
            if offset != 0 {
                print!("[+ 0x{:x}] ", offset);
            }
            print!("{:p} -> ", (*path).match_ptr as *const c_void);
            offset = (*path).offset;
            if (*path).next.is_null() {
                if offset != 0 {
                    print!("[+ 0x{:x}] ", offset);
                }
                println!("(target)");
            }
            path = (*path).next;
        }
        tmp = (*tmp).next;
    }

    println!("\n==Informatic print==");
    let mut count = 1i32;
    let mut tmp = pointermap;
    while !tmp.is_null() {
        let mut path = (*tmp).path_head;
        println!("\n=={}==", count);
        count += 1;
        let mut offset = 0i32;
        while !path.is_null() {
            let m = &*(*path).match_ptr;
            print_match(m);
            print_insights(m);
            if !(*path).next.is_null() {
                if offset != 0 {
                    print!("    |\n     --> [+ 0x{:x}] = (0x{:p})\n", (*path).offset, (*(*path).next).match_ptr as *const c_void);
                }
            } else {
                let size = std::mem::size_of::<usize>();
                let mut remote_value: usize = 0;
                let mb = &*m.memblock;
                if let Err(_) = ReadProcessMemory(
                    mb.h_proc,
                    m.address as *const c_void,
                    &mut remote_value as *mut usize as *mut c_void,
                    size,
                    None,
                ) {
                    let err = GetLastError().0;
                    if err != 299 {
                        print!(
                            "Error reading updated value of match: {:p}\nError id: {}\nError msg: {}\n",
                            m.address, err, get_last_error_str()
                        );
                    }
                }
                if offset != 0 {
                    print!(
                        "    [+ 0x{:x}] = (0x{:p})\n",
                        (*path).offset,
                        remote_value.wrapping_add((*path).offset as usize) as *const c_void
                    );
                }
                println!("\t\t^^ target ^^");
            }
            offset = (*path).offset;
            path = (*path).next;
        }
        tmp = (*tmp).next;
    }
}

// ─── hotkey configuration ────────────────────────────────────────────────────

fn configure_hotkey(
    key_id: i32,
    ctrl: bool,
    alt: bool,
    shift: bool,
    shortcut_type: ShortcutType,
    h_proc: HANDLE,
) {
    let shortcut = Box::new(Hotkey {
        hotkey_id: SHORTCUT_COUNTER.load(Ordering::SeqCst),
        key_id,
        shortcut_type,
        h_proc,
        ctrl,
        alt,
        shift,
        reset: true,
    });
    {
        let _guard = cs().lock().unwrap();
        let idx = SHORTCUT_COUNTER.fetch_add(1, Ordering::SeqCst) as usize;
        let mut shortcuts_guard = shortcuts_global().lock().unwrap();
        shortcuts_guard[idx] = Some(shortcut);
    }
    unsafe {
        Sleep(500);
        let _ = SetEvent(hotkeys_ready_event());
    }
    print!(
        "Registered hotkey {} {} {} {} (0x{:02x})\n",
        if ctrl { "CTRL + " } else { "" },
        if alt { "ALT + " } else { "" },
        if shift { "SHIFT + " } else { "" },
        key_id as u8 as char,
        key_id
    );
}

// ─── UI functions ────────────────────────────────────────────────────────────

fn get_user_input_for_type_ui(hunting_type: HuntingType) -> usize {
    match hunting_type {
        HuntingType::Byte => {
            print!("Enter value (hex): ");
            flush_stdout();
            read_hex_u64() as usize
        }
        HuntingType::Char => {
            print!("Enter value (single character): ");
            flush_stdout();
            read_char() as usize
        }
        HuntingType::Short | HuntingType::Int => {
            print!("Enter value: ");
            flush_stdout();
            read_int() as usize
        }
        HuntingType::Float | HuntingType::Double => {
            print!("{}", NOT_IMPLEMENTED);
            0
        }
        HuntingType::LongLongInt => {
            print!("Enter value: ");
            flush_stdout();
            read_long_long() as usize
        }
        HuntingType::Pointer => {
            print!("Enter value (hex): ");
            flush_stdout();
            read_hex_u64() as usize
        }
        HuntingType::Null => {
            print!("stfu what is this type how did it get here\n");
            0
        }
    }
}

fn scan_ui(scan_data: &[Box<MemBlock>], hunting_type: HuntingType) {
    let mut matches: Vec<Box<Match>> = Vec::new();

    let value = get_user_input_for_type_ui(hunting_type);
    filter_addresses(Some(scan_data), value, hunting_type, 1, &mut matches);
    print_matches(&matches);

    print!("Next Filter? (y/n): ");
    flush_stdout();
    let mut repeat = read_char();
    while repeat == 'y' {
        let value = get_user_input_for_type_ui(hunting_type);
        filter_addresses(None, value, hunting_type, 1, &mut matches);
        let match_count = count_matches(&matches);
        print!("Matches found: {}\n", match_count);
        if match_count <= 20 {
            print_matches(&matches);
        }
        print!("Filter more? (y/n): ");
        flush_stdout();
        repeat = read_char();
    }

    print!("Save matches? (y/n): ");
    flush_stdout();
    let choice = read_char();
    if choice == 'y' {
        save_matches(&matches);
    }
}

fn filter_results_ui(scan_data: &[Box<MemBlock>]) {
    loop {
        print!(
            "Choose a data type:\n\
             1: Byte (1 Byte unsigned)\n\
             2: Char (1 Byte signed)\n\
             3: Short (2 Byte signed)\n\
             4: Int (4 Byte signed)\n\
             5: Float (4 Byte floating point)\n\
             6: Double (8 Byte floating point)\n\
             7: Long Int (8 Byte signed)\n\
             8: Pointer (64 bit)\n\
             9: Go back\n"
        );
        flush_stdout();
        let choice = read_int();
        match choice {
            1 => { scan_ui(scan_data, HuntingType::Byte); return; }
            2 => { scan_ui(scan_data, HuntingType::Char); return; }
            3 => { scan_ui(scan_data, HuntingType::Short); return; }
            4 => { scan_ui(scan_data, HuntingType::Int); return; }
            5 | 6 => { print!("{}", NOT_IMPLEMENTED); return; }
            7 => { scan_ui(scan_data, HuntingType::LongLongInt); return; }
            8 => { scan_ui(scan_data, HuntingType::Pointer); return; }
            9 => return,
            _ => print!("Invalid choice\n"),
        }
    }
}

fn write_address_ui() {
    print!("Select address (number): ");
    flush_stdout();
    let match_choice = read_int() as usize;
    let saved = g_saved_matches().lock().unwrap();
    let value;
    let m_type;
    {
        let m = match get_match_by_print_order(&saved, match_choice) {
            Some(m) => m,
            None => { print!("Invalid selection\n"); return; }
        };
        m_type = m.data_type;
        // drop guard temporarily to read input
    }
    drop(saved);

    value = get_user_input_for_type_ui(m_type);

    let mut saved = g_saved_matches().lock().unwrap();
    let m = match get_match_by_print_order_mut(&mut saved, match_choice) {
        Some(m) => m,
        None => { print!("Invalid selection\n"); return; }
    };

    if !write_address(m, value) {
        print!("Failed writing to address. Memory region info:\n");
        unsafe { print_mem_block(&*m.memblock, false); }
    }
}

fn freeze_address_ui() {
    print!("Select address (number): ");
    flush_stdout();
    let match_choice = read_int() as usize;

    loop {
        print!(
            "\nEnter your choice:\n\
             1: Freeze address\n\
             2: Unfreeze address\n"
        );
        flush_stdout();
        let choice = read_int();
        match choice {
            1 => {
                let mut saved = g_saved_matches().lock().unwrap();
                let m = match get_match_by_print_order_mut(&mut saved, match_choice) {
                    Some(m) => m,
                    None => { print!("Invalid selection\n"); return; }
                };
                if !m.freeze.is_null() {
                    print!("Address is already frozen\n");
                } else {
                    let val_type = m.data_type;
                    let _addr = m.address;
                    let _mb_ptr = m.memblock;
                    drop(saved);
                    let value = get_user_input_for_type_ui(val_type);
                    // Re-acquire lock
                    let mut saved = g_saved_matches().lock().unwrap();
                    let m = match get_match_by_print_order_mut(&mut saved, match_choice) {
                        Some(m) => m,
                        None => { print!("Invalid selection\n"); return; }
                    };
                    m.freeze = freeze_address(m, value);
                    print!("Address frozen\n");
                }
                return;
            }
            2 => {
                let mut saved = g_saved_matches().lock().unwrap();
                let m = match get_match_by_print_order_mut(&mut saved, match_choice) {
                    Some(m) => m,
                    None => { print!("Invalid selection\n"); return; }
                };
                if m.freeze.is_null() {
                    print!("Address was not frozen\n");
                } else {
                    unsafe { unfreeze_address_raw(m); }
                    print!("Address unfrozen\n");
                }
                return;
            }
            _ => print!("Invalid choice\n"),
        }
    }
}

fn pointermap_ui(scan_data: &[Box<MemBlock>]) {
    let recurse_level = 3;
    print!("Select address (number): ");
    flush_stdout();
    let match_choice = read_int() as usize;

    let match_ptr: *const Match = {
        let saved = g_saved_matches().lock().unwrap();
        match get_match_by_print_order(&saved, match_choice) {
            Some(m) => m as *const Match,
            None => { print!("Invalid selection\n"); return; }
        }
    };

    let visited: HashSet<usize> = HashSet::new();
    POINTER_SCAN_COUNTER.store(1, Ordering::SeqCst);
    let pointermap = unsafe {
        pointermap_scan(scan_data, match_ptr, recurse_level, std::ptr::null_mut(), std::ptr::null_mut(), visited)
    };
    unsafe {
        if (*pointermap).path_head.is_null() {
            print!("No results for pointermap.\n");
        } else {
            print_pointermap(pointermap);
        }
    }
}

fn saved_matches_ui(scan_data: &[Box<MemBlock>]) {
    {
        let saved = g_saved_matches().lock().unwrap();
        print!("Saved addresses: {}\n", count_matches(&saved));
        print_matches(&saved);
    }
    loop {
        print!(
            "\nEnter your choice:\n\
             1: Write value to address\n\
             2: Freeze/Unfreeze address\n\
             3: Generate pointermap for address\n\
             4: Trace address\n\
             5: Print saved addresses\n\
             6: Back\n"
        );
        flush_stdout();
        let choice = read_int();
        match choice {
            1 => write_address_ui(),
            2 => freeze_address_ui(),
            3 => pointermap_ui(scan_data),
            4 => print!("{}", NOT_IMPLEMENTED),
            5 => {
                let saved = g_saved_matches().lock().unwrap();
                print!("Saved addresses: {}\n", count_matches(&saved));
                print_matches(&saved);
            }
            6 => return,
            _ => print!("Invalid choice\n"),
        }
    }
}

fn configure_hotkey_ui(scan_data: &[Box<MemBlock>]) {
    loop {
        print!(
            "Choose a shortcut to configure:\n\
             1: Suspend target process\n\
             2: Go back\n"
        );
        flush_stdout();
        let choice = read_int();
        match choice {
            1 => {
                print!("Enter a key: ");
                flush_stdout();
                unsafe { Sleep(500); }
                let mut key_ready = false;
                let mut key_id = 0i32;
                let mut shift = false;
                let mut alt = false;
                let mut ctrl = false;
                while !key_ready {
                    for k in 8..=190i32 {
                        let state = unsafe { GetAsyncKeyState(k) };
                        if (state as u16) & 0x8000 != 0 {
                            if k == 190 || k == 110 {
                                print!(".");
                            } else if k == 8 {
                                print!("[BACKSPACE]");
                                key_id = k;
                                key_ready = true;
                            } else if k == 13 {
                                print!("[ENTER]");
                                key_id = k;
                                key_ready = true;
                            } else if k == 32 {
                                print!("[SPACE]");
                                key_id = k;
                                key_ready = true;
                            } else if k == VK_TAB.0 as i32 {
                                print!("[TAB]");
                                key_id = k;
                                key_ready = true;
                            } else if k == VK_SHIFT.0 as i32 {
                                if !shift {
                                    print!("[SHIFT] + ");
                                }
                                shift = true;
                            } else if k == VK_CONTROL.0 as i32 {
                                if !ctrl {
                                    print!("[CONTROL] + ");
                                }
                                ctrl = true;
                            } else if k == VK_MENU.0 as i32 {
                                if !alt {
                                    print!("[ALT] + ");
                                }
                                alt = true;
                            } else if k == VK_ESCAPE.0 as i32 {
                                print!("[ESCAPE]");
                                key_id = k;
                                key_ready = true;
                            } else if k == VK_END.0 as i32 {
                                print!("[END]");
                                key_id = k;
                                key_ready = true;
                            } else if k == VK_HOME.0 as i32 {
                                print!("[HOME]");
                                key_id = k;
                                key_ready = true;
                            } else if k == VK_LEFT.0 as i32 {
                                print!("[LEFT]");
                                key_id = k;
                                key_ready = true;
                            } else if k == VK_UP.0 as i32 {
                                print!("[UP]");
                                key_id = k;
                                key_ready = true;
                            } else if k == VK_RIGHT.0 as i32 {
                                print!("[RIGHT]");
                                key_id = k;
                                key_ready = true;
                            } else if k == VK_DOWN.0 as i32 {
                                print!("[DOWN]");
                                key_id = k;
                                key_ready = true;
                            } else if k != VK_LSHIFT.0 as i32
                                && k != VK_RSHIFT.0 as i32
                                && k != VK_LCONTROL.0 as i32
                                && k != VK_RCONTROL.0 as i32
                                && k != VK_LMENU.0 as i32
                                && k != VK_RMENU.0 as i32
                            {
                                key_id = k;
                                key_ready = true;
                                print!("{}\n", k as u8 as char);
                                break;
                            }
                        }
                    }
                }
                // Get h_proc from first memblock
                let h_proc = scan_data[0].h_proc;
                configure_hotkey(key_id, ctrl, alt, shift, ShortcutType::Suspend, h_proc);
                return;
            }
            2 => return,
            _ => print!("Invalid choice\n"),
        }
    }
}

fn new_scan_ui() -> bool {
    print!("Enter PID: ");
    flush_stdout();
    let pid = read_int() as u32;
    print!("Starting scan\n");
    let scan_data = match start_scan(pid) {
        Some(d) if !d.is_empty() => d,
        _ => {
            print!("Scan failed\n");
            return false;
        }
    };

    // Get process name from first memblock's h_proc
    let h_proc = scan_data[0].h_proc;
    let mut image_path = vec![0u16; MAX_PATH];
    unsafe {
        GetModuleFileNameExW(h_proc, HMODULE(std::ptr::null_mut()), &mut image_path);
    }
    let path_end = image_path.iter().position(|&c| c == 0).unwrap_or(image_path.len());
    let image_path_str = String::from_utf16_lossy(&image_path[..path_end]).to_string();
    let process_name = path_find_file_name(&image_path_str).to_string();
    print!("Process: {}\n", process_name);
    print!("Image path: {}\n", image_path_str);

    print_scan(&scan_data);

    loop {
        print!(
            "\nEnter your choice:\n\
             1: Filter for addresses\n\
             2: Print scan data\n\
             3: Print scan data (debug)\n\
             4: Configure shortcuts\n\
             5: View saved addresses\n\
             6: Quit scan\n"
        );
        flush_stdout();
        let choice = read_int();
        match choice {
            1 => filter_results_ui(&scan_data),
            2 => print_scan(&scan_data),
            3 => {
                let memblock_count = MEMBLOCK_COUNTER.load(Ordering::SeqCst);
                let memblock_id = loop {
                    print!(
                        "Found {} memory blocks. Choose memory block to print (1-{})\n",
                        memblock_count, memblock_count
                    );
                    flush_stdout();
                    let id = read_int();
                    if id >= 1 && id <= memblock_count {
                        break id;
                    }
                };
                for mb in &scan_data {
                    if mb.id == memblock_id {
                        print_mem_block(mb, true);
                    }
                }
            }
            4 => configure_hotkey_ui(&scan_data),
            5 => saved_matches_ui(&scan_data),
            6 => {
                close_scan(scan_data);
                return true;
            }
            _ => print!("Invalid choice\n"),
        }
    }
}

fn main_menu_ui() {
    loop {
        print!(
            "\nEnter your choice:\n\
             1: New Scan\n\
             2: Quit\n"
        );
        flush_stdout();
        let choice = read_int();
        match choice {
            1 => {
                let result = new_scan_ui();
                if !result {
                    print!("newScanUI return fail status. maybe run as admin\n");
                }
            }
            2 => std::process::exit(0),
            _ => {}
        }
    }
}

// ─── main ────────────────────────────────────────────────────────────────────

fn main() {
    let args: Vec<String> = std::env::args().collect();
    for i in 1..args.len() {
        if args[i] == "-writable_mem" {
            WRITABLE_ONLY.store(true, Ordering::SeqCst);
        } else if args[i] == "-debug" {
            DEBUG_MODE.store(true, Ordering::SeqCst);
        }
    }

    // Initialize critical section (our Mutex-based cs)
    let _ = cs();

    // Create hotkeysReadyEvent (manual-reset=false, initial=false)
    let hke = unsafe {
        CreateEventW(None, FALSE, FALSE, PCWSTR::null())
            .expect("CreateEventW failed for hotkeysReadyEvent")
    };
    HOTKEYS_READY_EVENT.store(hke.0 as isize, Ordering::SeqCst);

    // Start shortcutHandler thread using Windows CreateThread
    unsafe {
        let _ = CreateThread(
            None,
            0,
            Some(shortcut_handler),
            None,
            THREAD_CREATION_FLAGS(0),
            None,
        )
        .expect("CreateThread failed for shortcutHandler");
    }

    main_menu_ui();
}
