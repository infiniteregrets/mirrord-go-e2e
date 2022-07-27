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

/*
TODO: Add missing instructions.

000000000049fba0 <syscall.RawSyscall.abi0>:
  49fba0:	48 8b 7c 24 10       	mov    rdi,QWORD PTR [rsp+0x10]
  49fba5:	48 8b 74 24 18       	mov    rsi,QWORD PTR [rsp+0x18]
  49fbaa:	48 8b 54 24 20       	mov    rdx,QWORD PTR [rsp+0x20]
  49fbaf:	48 8b 44 24 08       	mov    rax,QWORD PTR [rsp+0x8]
  49fbb4:	0f 05                	syscall 
  49fbb6:	48 3d 01 f0 ff ff    	cmp    rax,0xfffffffffffff001
  49fbbc:	76 1b                	jbe    49fbd9 <syscall.RawSyscall.abi0+0x39>
  49fbbe:	48 c7 44 24 28 ff ff 	mov    QWORD PTR [rsp+0x28],0xffffffffffffffff
  49fbc5:	ff ff 
  49fbc7:	48 c7 44 24 30 00 00 	mov    QWORD PTR [rsp+0x30],0x0
  49fbce:	00 00 
  49fbd0:	48 f7 d8             	neg    rax
  49fbd3:	48 89 44 24 38       	mov    QWORD PTR [rsp+0x38],rax
  49fbd8:	c3                   	ret    
  49fbd9:	48 89 44 24 28       	mov    QWORD PTR [rsp+0x28],rax
  49fbde:	48 89 54 24 30       	mov    QWORD PTR [rsp+0x30],rdx
  49fbe3:	48 c7 44 24 38 00 00 	mov    QWORD PTR [rsp+0x38],0x0
  49fbea:	00 00 
  49fbec:	c3                   	ret    
*/

/// Actual RawSyscall
#[cfg(target_os = "linux")]
#[cfg(target_arch = "x86_64")]
#[naked]
unsafe extern "C" fn go_raw_syscall() {
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


/// This detour calls the ABI handler, but fails because its using the g0 stack instead of the system stack.
/// Calls the functions like println!() or debug!() end up with a segfault.
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
        "mov    r8, QWORD PTR [rdi+0x30]",
        "mov    rsi, QWORD PTR [r8+0x50]",        
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
        "mov    rsi, rbx",
        "mov    rdx, r10",
        "mov    rcx, r11",
        "mov    rdi, rax",
        "call   c_abi_syscall_handler",
        "mov    rdi,QWORD PTR [rsp+0x30]",
        "mov    rsi,QWORD PTR [rdi+0x8]",
        "sub    rsi,QWORD PTR [rsp+0x28]",
        "mov    QWORD PTR fs:0xfffffff8, rdi",
        "mov    rsp,rsi",
        "mov    QWORD PTR [rsp+0x28], rax",
        "mov    QWORD PTR [rsp+0x30], rdx",
        "mov    QWORD PTR [rsp+0x38], 0x0",
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
        "call   go_runtime_abort",
        "4:",
        "ret",        
        options(noreturn)
    );
}

/// runtime.abort.abi0()
#[no_mangle]
#[cfg(target_os = "linux")]
#[cfg(target_arch = "x86_64")]  
#[naked]
unsafe extern "C" fn go_runtime_abort() {
    asm!("int 0x3",
        "jmp go_runtime_abort", 
        options(noreturn));
}


fn socket(sockfd:i32, _domain: i32, _type_: i32, _protocol: i32) -> i32 {        
    debug!("socket detour returned socket fd: {}", sockfd);
    SOCKETS.lock().unwrap().push(sockfd);
    sockfd
}

/// Syscall handler: socket calls go to the socket detour, while rest are passed to libc::syscall.
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
            let sock = libc::socket(param1 as i32, param2 as i32, param3 as i32);
            socket(sock, param1 as i32, param2 as i32, param3 as i32)                                                   
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
