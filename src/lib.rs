#![feature(naked_functions)]
#![feature(result_option_inspect)]

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

/// RawSyscall
#[cfg(target_os = "linux")]
#[cfg(target_arch = "x86_64")]
#[naked]
unsafe extern "C" fn go_raw_syscall_detour() {
    asm!("nop", options(noreturn),);
}

/// SysCall
#[allow(dead_code)]
#[cfg(target_os = "linux")]
#[cfg(target_arch = "x86_64")]
#[naked]
unsafe extern "C" fn go_syscall_detour() {
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

/// Actual RawSyscall
#[allow(dead_code)]
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

#[no_mangle]
unsafe extern "C" fn c_abi_syscall_handler(syscall: i64, param1: i64, param2: i64, param3: i64) {
    debug!("C ABI handler received `Syscall - {:?}` with args >> arg1 -> {:?}, arg2 -> {:?}, arg3 -> {:?}", syscall, param1, param2, param3);
    let res: i32 = match syscall {
        libc::SYS_socket => {
            let sock = libc::socket(param1 as i32, param2 as i32, param3 as i32);
            debug!("C ABI handler returned socket descriptor -> {:?}", sock);
            SOCKETS.lock().unwrap().push(sock);
            sock
        }
        _ => panic!("Unhandled Syscall - {:?}", syscall),
    };
    asm!("mov rax, {0}", in(reg) res);
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
        go_raw_syscall_detour,
        "go-e2e"
    )
}
