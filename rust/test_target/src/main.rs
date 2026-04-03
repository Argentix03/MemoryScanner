//! Port of Test/tests.cpp — a simple test target for the memory scanner.
//! Provides an interactive menu to exercise integer and pointer scenarios.

use std::io::{self, Write};
use std::process;

static mut G_A: i32 = 1337;
static mut G_B: i32 = 123456;
static mut G_C: i32 = 76453;
static mut G_POINTER_A: *mut i32 = std::ptr::null_mut();
static mut G_POINTER_B: *mut i32 = std::ptr::null_mut();

fn flush() {
    let _ = io::stdout().flush();
}

fn read_int() -> i32 {
    let mut line = String::new();
    let _ = io::stdin().read_line(&mut line);
    line.trim().parse().unwrap_or(0)
}

fn pause() {
    print!("Press Enter to continue...");
    flush();
    let mut line = String::new();
    let _ = io::stdin().read_line(&mut line);
}

fn test_int() -> i32 {
    println!("Test 1: Simple Integer Test");

    let a: i32 = 13371;
    let b: i32 = 13372;
    let c: i32 = 13373;
    println!("var [INT] (local): a\tvalue: {}\taddress:{:p}", a, &a);
    println!("var [INT] (local): b\tvalue: {}\taddress:{:p}", b, &b);
    println!("var [INT] (local): c\tvalue: {}\taddress:{:p}", c, &c);
    unsafe {
        println!("var [INT] (global): a\tvalue: {}\taddress:{:p}", G_A, &G_A);
        println!("var [INT] (global): b\tvalue: {}\taddress:{:p}", G_B, &G_B);
        println!("var [INT] (global): c\tvalue: {}\taddress:{:p}", G_C, &G_C);
    }

    pause();

    let a: i32 = 76453;
    unsafe { G_A = 76453; }
    std::thread::sleep(std::time::Duration::from_millis(500));
    println!("var [INT] (local): a\tvalue: {}\taddress:{:p}", a, &a);
    println!("var [INT] (local): b\tvalue: {}\taddress:{:p}", b, &b);
    println!("var [INT] (local): c\tvalue: {}\taddress:{:p}", c, &c);
    unsafe {
        println!("var [INT] (global): a\tvalue: {}\taddress:{:p}", G_A, &G_A);
        println!("var [INT] (global): b\tvalue: {}\taddress:{:p}", G_B, &G_B);
        println!("var [INT] (global): c\tvalue: {}\taddress:{:p}", G_C, &G_C);
    }

    pause();

    let a: i32 = 123456;
    unsafe { G_A = 76453; }
    std::thread::sleep(std::time::Duration::from_millis(500));
    println!("var [INT] (local): a\tvalue: {}\taddress:{:p}", a, &a);
    println!("var [INT] (local): b\tvalue: {}\taddress:{:p}", b, &b);
    println!("var [INT] (local): c\tvalue: {}\taddress:{:p}", c, &c);
    unsafe {
        println!("var [INT] (global): a\tvalue: {}\taddress:{:p}", G_A, &G_A);
        println!("var [INT] (global): b\tvalue: {}\taddress:{:p}", G_B, &G_B);
        println!("var [INT] (global): c\tvalue: {}\taddress:{:p}", G_C, &G_C);
    }

    pause();
    // suppress "unused variable" warnings for re-bound names
    let _ = a;
    1
}

fn test_pointers() -> i32 {
    println!("Test 2: Simple Pointer Test");

    let mut int_a: i32 = 13371;
    let mut int_b: i32 = 13372;
    let pointer_a: *mut i32 = &mut int_a;
    let pointer_b: *mut i32 = &mut int_b;
    println!("var [INT] (local): a\tvalue: {}\taddress:{:p}", int_a, &int_a);
    println!("var [INT] (global): c\tvalue: {}\taddress:{:p}", int_b, &int_b);
    println!("var [pointer] (local): a\tvalue: 0x{:p}\taddress:{:p}", pointer_a, &pointer_a);
    println!("var [pointer] (global): c\tvalue: 0x{:p}\taddress:{:p}", pointer_b, &pointer_b);
    unsafe {
        println!("var [INT] (global): a\tvalue: 0x{:p}\taddress:{:p}", G_POINTER_A, &G_POINTER_A);
        println!("var [INT] (global): b\tvalue: 0x{:p}\taddress:{:p}", G_POINTER_B, &G_POINTER_B);
    }

    pause();

    int_a = 123456;
    int_b = 123457;
    unsafe { G_A = 1; }
    std::thread::sleep(std::time::Duration::from_millis(500));
    println!("var [INT] (local): a\tvalue: {}\taddress:{:p}", int_a, &int_a);
    println!("var [INT] (global): c\tvalue: {}\taddress:{:p}", int_b, &int_b);
    println!("var [pointer] (local): a\tvalue: 0x{:p}\taddress:{:p}", pointer_a, &pointer_a);
    println!("var [pointer] (global): c\tvalue: 0x{:p}\taddress:{:p}", pointer_b, &pointer_b);
    unsafe {
        println!("var [INT] (global): a\tvalue: 0x{:p}\taddress:{:p}", G_POINTER_A, &G_POINTER_A);
        println!("var [INT] (global): b\tvalue: 0x{:p}\taddress:{:p}", G_POINTER_B, &G_POINTER_B);
    }

    pause();

    int_a = 4321;
    int_b = 4322;
    unsafe { G_B = 2; }
    std::thread::sleep(std::time::Duration::from_millis(500));
    println!("var [INT] (local): a\tvalue: {}\taddress:{:p}", int_a, &int_a);
    println!("var [INT] (global): c\tvalue: {}\taddress:{:p}", int_b, &int_b);
    println!("var [pointer] (local): a\tvalue: 0x{:p}\taddress:{:p}", pointer_a, &pointer_a);
    println!("var [pointer] (global): c\tvalue: 0x{:p}\taddress:{:p}", pointer_b, &pointer_b);
    unsafe {
        println!("var [INT] (global): a\tvalue: 0x{:p}\taddress:{:p}", G_POINTER_A, &G_POINTER_A);
        println!("var [INT] (global): b\tvalue: 0x{:p}\taddress:{:p}", G_POINTER_B, &G_POINTER_B);
    }

    pause();
    1
}

fn main() {
    println!("PID: {}", process::id());
    loop {
        print!(
            "Choose an option:\n\
             1: Test basic Int\n\
             2: Test Pointers\n"
        );
        flush();
        let choice = read_int();
        match choice {
            1 => { test_int(); }
            2 => { test_pointers(); }
            _ => println!("Invalid choice"),
        }
    }
}
