// #![allow(dead_code)]
#![allow(non_snake_case)]
#![allow(non_camel_case_types)]
#![allow(clippy::upper_case_acronyms)]

use core::ffi::c_void;

use crate::utils::djb2;

// Put this at the end of the loader so we can
// start seeking for our PE from there.
// Also include a mutable ptr for running in debug.
#[unsafe(link_section = ".text$z")]
pub static LDREND: u32 = 0x1234;
pub static mut P_LDREND: *const u8 = &LDREND as *const _ as *const u8;

// Functions
pub const KERNEL32: u64 = djb2(b"kernel32.dll");
pub const GETPROCADDRESS: u64 = djb2(b"GetProcAddress");
pub const LOADLIBRARY: u64 = djb2(b"LoadLibraryA");
pub const VIRTUALALLOC: u64 = djb2(b"VirtualAlloc");
pub const VIRTUALPROTECT: u64 = djb2(b"VirtualProtect");

// Data directories
// Commented ones are unused.
// pub const IMAGE_NUMBEROF_DIRECTORY_ENTRIES: usize = 16;
pub const IMAGE_DIRECTORY_ENTRY_EXPORT: usize = 0;
pub const IMAGE_DIRECTORY_ENTRY_IMPORT: usize = 1;
// pub const IMAGE_DIRECTORY_ENTRY_RESOURCE: usize = 2;
// pub const IMAGE_DIRECTORY_ENTRY_EXCEPTION: usize = 3;
// pub const IMAGE_DIRECTORY_ENTRY_SECURITY: usize = 4;
pub const IMAGE_DIRECTORY_ENTRY_BASERELOC: usize = 5;
// pub const IMAGE_DIRECTORY_ENTRY_DEBUG: usize = 6;
// pub const IMAGE_DIRECTORY_ENTRY_ARCHITECTURE: usize = 7;
// pub const IMAGE_DIRECTORY_ENTRY_GLOBALPTR: usize = 8;
pub const IMAGE_DIRECTORY_ENTRY_TLS: usize = 9;
// pub const IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG: usize = 10;
// pub const IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT: usize = 11;
// pub const IMAGE_DIRECTORY_ENTRY_IAT: usize = 12;
// pub const IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT: usize = 13;
// pub const IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR: usize = 14;

pub const IMAGE_ORDINAL_FLAG: u64 = 9223372036854775808u64;

pub const MEM_COMMIT: u32 = 4096u32;
pub const MEM_RESERVE: u32 = 8192u32;

pub const DLL_PROCESS_ATTACH: u32 = 1u32;
pub const DLL_PROCESS_DETACH: u32 = 4u32;

pub type IMAGE_FILE_MACHINE = u16;
pub type IMAGE_FILE_CHARACTERISTICS = u16;
pub type IMAGE_OPTIONAL_HEADER_MAGIC = u16;
pub type IMAGE_SUBSYSTEM = u16;
pub type IMAGE_DLL_CHARACTERISTICS = u16;
pub type IMAGE_SECTION_CHARACTERISTICS = u32;

pub type PCSTR = *const u8;
pub type HMODULE = *mut u8;
pub type VIRTUAL_ALLOCATION_TYPE = u32;
pub type PAGE_PROTECTION_FLAGS = u32;
pub type PWSTR = *const u16;
pub type PPS_POST_PROCESS_INIT_ROUTINE = Option<unsafe extern "system" fn()>;

pub type FnGetProcAddress = extern "C" fn(HMODULE, PCSTR) -> HMODULE;
pub type FnLoadLibraryA = extern "C" fn(PCSTR) -> HMODULE;
pub type FnVirtualAlloc = extern "C" fn(
    lpaddress: u64,
    dwsize: usize,
    flallocationtype: VIRTUAL_ALLOCATION_TYPE,
    flprotect: PAGE_PROTECTION_FLAGS,
) -> *const c_void;
pub type FnVirtualProtect = extern "C" fn (
    lpaddress: usize,
    dwsize: usize,
    flnewprotect: u32,
    lpfloldprotect: *mut u32,
) -> bool;

pub const PAGE_NOACCESS: PAGE_PROTECTION_FLAGS = 0x01;
pub const PAGE_WRITECOPY: PAGE_PROTECTION_FLAGS  = 0x08;
pub const PAGE_READONLY: PAGE_PROTECTION_FLAGS  = 0x02;
pub const PAGE_READWRITE: PAGE_PROTECTION_FLAGS  = 0x04;
pub const PAGE_EXECUTE: PAGE_PROTECTION_FLAGS  = 0x10;
pub const PAGE_EXECUTE_WRITECOPY: PAGE_PROTECTION_FLAGS  = 0x80;
pub const PAGE_EXECUTE_READ: PAGE_PROTECTION_FLAGS  = 0x20;
pub const PAGE_EXECUTE_READWRITE: PAGE_PROTECTION_FLAGS  = 0x40;
pub const PAGE_NOCACHE: PAGE_PROTECTION_FLAGS = 0x200;

pub const IMAGE_SCN_MEM_EXECUTE: u32 = 0x20000000;
pub const IMAGE_SCN_MEM_READ: u32 = 0x40000000;
pub const IMAGE_SCN_MEM_WRITE: u32 = 0x80000000;
pub const IMAGE_SCN_MEM_NOT_CACHED: u32 = 0x04000000;

// Stolen from MemoryModule.
pub const PROTECTION_FLAGS: [[[u32; 2]; 2]; 2] = [
    [
        [PAGE_NOACCESS, PAGE_WRITECOPY],
        [PAGE_READONLY, PAGE_READWRITE],
    ], [
        [PAGE_EXECUTE, PAGE_EXECUTE_WRITECOPY],
        [PAGE_EXECUTE_READ, PAGE_EXECUTE_READWRITE]
    ],
];

#[derive(Copy, Clone)]
#[repr(C)]
pub struct IMAGE_DOS_HEADER {
    pub e_magic: u16,
    pub e_cblp: u16,
    pub e_cp: u16,
    pub e_crlc: u16,
    pub e_cparhdr: u16,
    pub e_minalloc: u16,
    pub e_maxalloc: u16,
    pub e_ss: u16,
    pub e_sp: u16,
    pub e_csum: u16,
    pub e_ip: u16,
    pub e_cs: u16,
    pub e_lfarlc: u16,
    pub e_ovno: u16,
    pub e_res: [u16; 4],
    pub e_oemid: u16,
    pub e_oeminfo: u16,
    pub e_res2: [u16; 10],
    pub e_lfanew: u32,
}

#[derive(Debug, Copy, Clone)]
#[repr(C)]
pub struct IMAGE_NT_HEADERS64 {
    pub Signature: u32,
    pub FileHeader: IMAGE_FILE_HEADER,
    pub OptionalHeader: IMAGE_OPTIONAL_HEADER64,
}

#[derive(Debug, Copy, Clone)]
#[repr(C)]
pub struct IMAGE_FILE_HEADER {
    pub Machine: IMAGE_FILE_MACHINE,
    pub NumberOfSections: u16,
    pub TimeDateStamp: u32,
    pub PointerToSymbolTable: u32,
    pub NumberOfSymbols: u32,
    pub SizeOfOptionalHeader: u16,
    pub Characteristics: IMAGE_FILE_CHARACTERISTICS,
}

#[derive(Debug, Copy, Clone)]
#[repr(C)]
pub struct IMAGE_OPTIONAL_HEADER64 {
    pub Magic: IMAGE_OPTIONAL_HEADER_MAGIC,
    pub MajorLinkerVersion: u8,
    pub MinorLinkerVersion: u8,
    pub SizeOfCode: u32,
    pub SizeOfInitializedData: u32,
    pub SizeOfUninitializedData: u32,
    pub AddressOfEntryPoint: u32,
    pub BaseOfCode: u32,
    pub ImageBase: u64,
    pub SectionAlignment: u32,
    pub FileAlignment: u32,
    pub MajorOperatingSystemVersion: u16,
    pub MinorOperatingSystemVersion: u16,
    pub MajorImageVersion: u16,
    pub MinorImageVersion: u16,
    pub MajorSubsystemVersion: u16,
    pub MinorSubsystemVersion: u16,
    pub Win32VersionValue: u32,
    pub SizeOfImage: u32,
    pub SizeOfHeaders: u32,
    pub CheckSum: u32,
    pub Subsystem: IMAGE_SUBSYSTEM,
    pub DllCharacteristics: IMAGE_DLL_CHARACTERISTICS,
    pub SizeOfStackReserve: u64,
    pub SizeOfStackCommit: u64,
    pub SizeOfHeapReserve: u64,
    pub SizeOfHeapCommit: u64,
    pub LoaderFlags: u32,
    pub NumberOfRvaAndSizes: u32,
    pub DataDirectory: [IMAGE_DATA_DIRECTORY; 16],
}

#[derive(Debug, Copy, Clone)]
#[repr(C)]
pub struct IMAGE_DATA_DIRECTORY {
    pub VirtualAddress: u32,
    pub Size: u32,
}

#[derive(Debug, Copy, Clone)]
#[repr(C)]
pub struct IMAGE_SECTION_HEADER {
    pub Name: [u8; 8],
    pub VirtualSize: u32,
    pub VirtualAddress: u32,
    pub SizeOfRawData: u32,
    pub PointerToRawData: u32,
    pub PointerToRelocations: u32,
    pub PointerToLinenumbers: u32,
    pub NumberOfRelocations: u16,
    pub NumberOfLinenumbers: u16,
    pub Characteristics: IMAGE_SECTION_CHARACTERISTICS,
}

#[derive(Copy, Clone)]
#[repr(C)]
pub union IMAGE_IMPORT_DESCRIPTOR_0 {
    pub Characteristics: u32,
    pub OriginalFirstThunk: u32,
}

#[derive(Copy, Clone)]
#[repr(C)]
pub struct IMAGE_IMPORT_DESCRIPTOR {
    pub Anonymous: IMAGE_IMPORT_DESCRIPTOR_0,
    pub TimeDateStamp: u32,
    pub ForwarderChain: u32,
    pub Name: u32,
    pub FirstThunk: u32,
}

#[derive(Copy, Clone)]
#[repr(C)]
pub struct IMAGE_BASE_RELOCATION {
    pub VirtualAddress: u32,
    pub SizeOfBlock: u32,
}

#[derive(Debug)]
#[repr(C)]
pub struct IMAGE_EXPORT_DIRECTORY {
    pub Characteristics: u32,
    pub TimeDateStamp: u32,
    pub MajorVersion: u16,
    pub MinorVersion: u16,
    pub Name: u32,
    pub Base: u32,
    pub NumberOfFunctions: u32,
    pub NumberOfNames: u32,
    pub AddressOfFunctions: u32,
    pub AddressOfNames: u32,
    pub AddressOfNameOrdinals: u32,
}

#[repr(C)]
#[derive(Debug)]
pub struct PEB {
    pub Reserved1: [u8; 2],
    pub BeingDebugged: u8,
    pub Reserved2: [u8; 1],
    pub Reserved3: [*const c_void; 2],
    pub Ldr: *const PEB_LDR_DATA,
    pub ProcessParameters: *const RTL_USER_PROCESS_PARAMETERS,
    pub Reserved4: [*const c_void; 3],
    pub AtlThunkSListPtr: *const c_void,
    pub Reserved5: *const c_void,
    pub Reserved6: u32,
    pub Reserved7: *const c_void,
    pub Reserved8: u32,
    pub AtlThunkSListPtr32: u32,
    pub Reserved9: [*const c_void; 45],
    pub Reserved10: [u8; 96],
    pub PostProcessInitRoutine: PPS_POST_PROCESS_INIT_ROUTINE,
    pub Reserved11: [u8; 128],
    pub Reserved12: [*const c_void; 1],
    pub SessionId: u32,
}

#[repr(C)]
#[derive(Debug)]
pub struct RTL_USER_PROCESS_PARAMETERS {
    pub Reserved1: [u8; 16],
    pub Reserved2: [*const c_void; 10],
    pub ImagePathName: UNICODE_STRING,
    pub CommandLine: UNICODE_STRING,
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct UNICODE_STRING {
    pub Length: u16,
    pub MaximumLength: u16,
    pub Buffer: PWSTR,
}

#[repr(C)]
#[derive(Debug)]
pub struct PEB_LDR_DATA {
    pub Reserved1: [u8; 8],
    pub Reserved2: [*const c_void; 3],
    pub InMemoryOrderModuleList: LIST_ENTRY,
}

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct LIST_ENTRY {
    pub Flink: *const LIST_ENTRY,
    pub Blink: *const LIST_ENTRY,
}

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct LDR_DATA_TABLE_ENTRY {
    pub Reserved1: [*const c_void; 2],
    pub InMemoryOrderLinks: LIST_ENTRY,
    pub Reserved2: [*const c_void; 2],
    pub DllBase: *const c_void,
    pub Reserved3: [*const c_void; 2],
    pub FullDllName: UNICODE_STRING,
    pub Reserved4: [u8; 8],
    pub Reserved5: [*const c_void; 3],
    pub Checksum: u32,
    pub TimeDateStamp: u32,
}

#[repr(C)]
pub struct IMAGE_THUNK_DATA64 {
    pub u1: IMAGE_THUNK_DATA64_0,
}

#[repr(C)]
pub union IMAGE_THUNK_DATA64_0 {
    pub ForwarderString: u64,
    pub Function: u64,
    pub Ordinal: u64,
    pub AddressOfData: u64,
}

#[repr(C)]
pub struct IMAGE_IMPORT_BY_NAME {
    pub Hint: u16,
    pub Name: [u8; 1],
}

#[derive(Copy, Clone)]
#[repr(C)]
pub struct IMAGE_TLS_DIRECTORY64 {
    pub StartAddressOfRawData: u64,
    pub EndAddressOfRawData: u64,
    pub AddressOfIndex: u64,
    pub AddressOfCallBacks: u64,
    pub SizeOfZeroFill: u32,
    pub Anonymous: IMAGE_TLS_DIRECTORY64_0,
}

#[derive(Copy, Clone)]
#[repr(C)]
pub struct IMAGE_TLS_DIRECTORY64_0_0 {
    pub _bitfield: u32,
}

#[derive(Copy, Clone)]
#[repr(C)]
pub union IMAGE_TLS_DIRECTORY64_0 {
    pub Characteristics: u32,
    pub Anonymous: IMAGE_TLS_DIRECTORY64_0_0,
}
