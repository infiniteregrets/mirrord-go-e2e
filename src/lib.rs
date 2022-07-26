#![feature(naked_functions)]
#![feature(result_option_inspect)]
#![cfg_attr(rustc_nightly, feature(test))]

use ctor::ctor;
use frida_gum::{interceptor::Interceptor, Gum};

use lazy_static::lazy_static;
// use libc::c_void;
use std::{arch::asm, sync::Mutex};
use tracing::debug;

lazy_static! {
    static ref GUM: Gum = unsafe { Gum::obtain() };
    static ref SOCKETS: Mutex<Vec<i32>> = Mutex::new(vec![]);
}

macro_rules! hook_sym {
    ($interceptor:expr, $func:expr, $detour_name:expr, $binary:expr) => {
        $interceptor
            .replace(
                frida_gum::Module::find_symbol_by_name(Some($binary), $func).unwrap(),
                frida_gum::NativePointer($detour_name as *mut libc::c_void),
                frida_gum::NativePointer(std::ptr::null_mut::<libc::c_void>()),
            )
            .inspect_err(|err| {
                debug!("Failed to hook {:?}", err);
            })
            .inspect(|_| debug!("{:?} hooked", $func))
            .unwrap()
    };
}

#[cfg(target_os = "linux")]
#[cfg(target_arch = "x86_64")]
#[naked]
unsafe extern "C" fn go_syscall_detour() {
    asm!("nop", options(noreturn),);
}

/// Actual RawSyscall
#[cfg(target_os = "linux")]
#[cfg(target_arch = "x86_64")]
#[naked]
unsafe extern "C" fn go_very_raw_syscall_detour() {
    asm!(
        "mov rdi, QWORD PTR [rsp+0x10]",
        "mov rsi, QWORD PTR [rsp+0x18]",
        "mov rdx, QWORD PTR [rsp+0x20]",
        "mov rax, QWORD PTR [rsp+0x8]",
        "syscall",
        "mov  QWORD PTR [rsp+0x28],rax",
        "mov  QWORD PTR [rsp+0x30],rdx",
        "mov  QWORD PTR [rsp+0x38],0x0",
        "ret",
        options(noreturn),
    );
}

#[cfg(target_os = "linux")]
#[cfg(target_arch = "x86_64")]
#[naked]
unsafe extern "C" fn go_raw_syscall_detour() {
    asm!(
        "mov rsi, QWORD PTR [rsp+0x10]",
        "mov rdx, QWORD PTR [rsp+0x18]",
        "mov rcx, QWORD PTR [rsp+0x20]",
        "mov rdi, QWORD PTR [rsp+0x8]",
        "call c_abi_syscall_handler",
        "mov  QWORD PTR [rsp+0x28],rax",
        "mov  QWORD PTR [rsp+0x30],rdx",
        "mov  QWORD PTR [rsp+0x38],0x0",
        "ret",
        options(noreturn),
    );
}


#[cfg(target_os = "linux")]
#[cfg(target_arch = "x86_64")]
#[naked]
unsafe extern "C" fn go_asmcgocall() {
    asm!(
        "mov rbx, QWORD PTR [rsp+0x10]",        
        "mov r10, QWORD PTR [rsp+0x18]",        
        "mov r11, QWORD PTR [rsp+0x20]",        
        "mov rax, QWORD PTR [rsp+0x8]",        
        "mov    rdx, rsp",        
        "mov    rdi, QWORD PTR fs:[0xfffffff8]",        
        "cmp    rdi, 0x0",        
        "je     2f",        
        "mov    r8,QWORD PTR [rdi+0x30]",
        "mov    rsi,QWORD PTR [r8+0x50]",        
        "cmp    rdi,rsi",
        "je     2f",        
        "mov    rsi,QWORD PTR [r8]",    
        "cmp    rdi,rsi",        
        "je     2f",                
        "mov    QWORD PTR fs:[0xfffffff8], rsi",        
        "mov    rsp,QWORD PTR [rsi+0x38]",        
        "sub    rsp,0x40",        
        "and    rsp,0xfffffffffffffff0",
        "mov    QWORD PTR [rsp+0x30],rdi",
        "mov    rdi,QWORD PTR [rdi+0x8]",
        "sub    rdi,rdx",
        "mov    QWORD PTR [rsp+0x28],rdi",
        "mov rsi, rbx",
        "mov rdx, r10",
        "mov rcx, r11",
        "mov rdi, rax",
        "call   c_abi_syscall_handler",
        "mov    rdi,QWORD PTR [rsp+0x30]",
        "mov    rsi,QWORD PTR [rdi+0x8]",
        "sub    rsi,QWORD PTR [rsp+0x28]",
        "mov    QWORD PTR fs:0xfffffff8, rdi",
        "mov    rsp,rsi",
        "mov  QWORD PTR [rsp+0x28],rax",
        "mov  QWORD PTR [rsp+0x30],rdx",
        "mov  QWORD PTR [rsp+0x38],0x0",
        "ret",

        "2:",
        "sub    rsp,0x40",
        "and    rsp,0xfffffffffffffff0",
        "mov    QWORD PTR [rsp+0x30],0x0",
        "mov    QWORD PTR [rsp+0x28],rdx",
        "mov    rsi, rbx",
        "mov    rdx, r10",
        "mov    rcx, r11",
        "mov    rdi, rax",        
        "call   c_abi_syscall_handler",
        "mov    rsi,QWORD PTR [rsp+0x28]",
        "mov    rsp,rsi",
        "mov  QWORD PTR [rsp+0x28],rax",
        "mov  QWORD PTR [rsp+0x30],rdx",
        "mov  QWORD PTR [rsp+0x38],0x0",
        "ret",

        "3:",
        "lea    r9,[rip+0xdd9]",
        "mov    QWORD PTR [r14+0x40],r9",
        "lea    r9,[rsp+0x8]",
        "mov    QWORD PTR [r14+0x38],r9",
        "mov    QWORD PTR [R14 + 0x58],0x0",
        "mov    QWORD PTR [r14+0x68],rbp",
        "mov    r9,QWORD PTR [r14+0x50]",
        "test   r9,r9",
        "jz     4f",
        "call   5f",
        "4:",
        "ret",
        "5:",
        "jmp    5b",
        options(noreturn)
    );
}

fn socket(domain: i32, type_: i32, protocol: i32) -> i32 {    
    let sockfd = unsafe { libc::socket(domain, type_, protocol) };
    debug!("socket detour returned socket fd: {}", sockfd);
    sockfd
}

#[no_mangle]
unsafe extern "C" fn c_abi_syscall_handler(
    syscall: i64,
    param1: i64,
    param2: i64,
    param3: i64,
) -> i32 {
    debug!("C ABI handler received `Syscall - {:?}` with args >> arg1 -> {:?}, arg2 -> {:?}, arg3 -> {:?}", syscall, param1, param2, param3);
    let res = match syscall {
        libc::SYS_socket => {
            let sock = socket(param1 as i32, param2 as i32, param3 as i32);                              
            sock
        }
        _ => libc::syscall(syscall, param1, param2, param3) as i32,
    };
    return res;
}

#[ctor]
fn init() {
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::DEBUG)
        .init();
    debug!("LD_PRELOAD SET");

    enable_hooks();
}

fn enable_hooks() {
    let mut interceptor = Interceptor::obtain(&GUM);
    hook_sym!(
        interceptor,
        "syscall.RawSyscall.abi0",
        go_asmcgocall,
        "go-e2e"
    )
}
