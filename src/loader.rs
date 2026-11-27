use core::arch::asm;
use core::ffi::c_void;
use core::mem::size_of;
use core::ptr::null_mut;

use crate::defs::*;
use crate::utils::*;
use crate::{call, containing_record, utils};

pub fn find_module(peb: *const PEB, module: u64) -> isize {
    let mut p_modules = unsafe { (*(*peb).Ldr).InMemoryOrderModuleList.Flink };
    let mut modules = unsafe { *p_modules };
    let first_module = p_modules;

    while modules.Flink != first_module {
        let entry = containing_record!(p_modules, LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks);

        let raw_dll_path = unsafe { (*entry).FullDllName };
        let dll_path = unicode_string_to_string(&raw_dll_path);
        let dll_path_len = dll_path.len();
        let dll = &dll_path[dll_path_len - 12..dll_path_len];

        if djb2_from_u16(dll) == module {
            return unsafe { (*entry).DllBase as isize };
        }

        p_modules = modules.Flink;
        modules = unsafe { *p_modules };
    }

    1
}

pub fn get_peb_addr() -> u64 {
    let mut peb_addr: u64 = 0;
    unsafe {
        asm!(
            "mov {0:r}, gs:[0x60]",
            inout(reg) peb_addr
        );
    }

    peb_addr
}

pub fn remap_pe(
    base: *const IMAGE_DOS_HEADER,
    virtual_alloc_ptr: *const (),
) -> *const IMAGE_DOS_HEADER {
    let nt = get_nt(base);
    let optional_header = unsafe { (get_optional(base)).read_unaligned() };
    let image_size = optional_header.SizeOfImage;
    let headers_size = optional_header.SizeOfHeaders;
    let secnum = get_number_of_sections(base);
    let relocations = get_data_dir(base, IMAGE_DIRECTORY_ENTRY_BASERELOC).VirtualAddress;

    let mem: *const c_void = match relocations {
        0 => call!(
            FnVirtualAlloc,
            virtual_alloc_ptr,
            optional_header.ImageBase,
            image_size as usize,
            MEM_COMMIT | MEM_RESERVE,
            PAGE_READWRITE
        ),
        _ => call!(
            FnVirtualAlloc,
            virtual_alloc_ptr,
            0,
            image_size as usize,
            MEM_COMMIT | MEM_RESERVE,
            PAGE_READWRITE
        ),
    };

    utils::memset(mem as *mut u8, 0, image_size as usize);
    utils::memcpy(mem as *mut u8, base as *const u8, headers_size as usize);

    let sections = slice_from_raw_parts(
        (nt as usize + size_of::<IMAGE_NT_HEADERS64>()) as *const IMAGE_SECTION_HEADER,
        secnum,
    );

    for i in 0..secnum {
        let section = sections[i];
        utils::memcpy(
            (mem as usize + section.VirtualAddress as usize) as *mut u8,
            (base as usize + section.PointerToRawData as usize) as *const u8,
            section.SizeOfRawData as usize,
        );
    }

    mem as *const IMAGE_DOS_HEADER
}

pub fn resolve_imports(
    base: *const IMAGE_DOS_HEADER,
    load_library_ptr: *const (),
    get_proc_address_ptr: *const (),
) {
    let dir_entry_import = get_data_dir(base, IMAGE_DIRECTORY_ENTRY_IMPORT);
    let mut p_image_import_descriptors = (base as usize + dir_entry_import.VirtualAddress as usize)
        as *const IMAGE_IMPORT_DESCRIPTOR;
    let mut image_import_descriptors = unsafe { *p_image_import_descriptors };

    while image_import_descriptors.Name != 0 {
        if image_import_descriptors.Name == 0xFFFF {
            p_image_import_descriptors = unsafe { p_image_import_descriptors.add(1) };
            image_import_descriptors = unsafe { *p_image_import_descriptors };
            continue;
        }

        let name_ptr = (base as usize + image_import_descriptors.Name as usize) as *const u8;
        let module_address = call!(FnLoadLibraryA, load_library_ptr, name_ptr);

        if module_address as isize == 0 {
            return;
        };

        let mut p_original_first_thunk = unsafe {
            (base as usize + image_import_descriptors.Anonymous.OriginalFirstThunk as usize)
                as *const IMAGE_THUNK_DATA64
        };

        let mut p_first_thunk = (image_import_descriptors.FirstThunk as usize + base as usize)
            as *mut IMAGE_THUNK_DATA64;

        while unsafe { (*p_original_first_thunk).u1.AddressOfData } != 0 {
            let original_first_thunk = unsafe { &*p_original_first_thunk };
            let first_thunk = unsafe { &mut *p_first_thunk };
            let oft_ordinal = unsafe { original_first_thunk.u1.Ordinal };

            if oft_ordinal & IMAGE_ORDINAL_FLAG != 0 {
                // import by ordinal if there is one
                let addr = call!(
                    FnGetProcAddress,
                    get_proc_address_ptr,
                    module_address,
                    (oft_ordinal & 0xFFFF) as *const u8
                ) as u64;

                first_thunk.u1.Function = addr;
            } else {
                let p_import_by_name = unsafe {
                    (original_first_thunk.u1.AddressOfData + base as u64)
                        as *const IMAGE_IMPORT_BY_NAME
                };
                let import_by_name =
                    unsafe { core::ptr::addr_of!((*p_import_by_name).Name) } as *const u8;

                let addr = call!(
                    FnGetProcAddress,
                    get_proc_address_ptr,
                    module_address,
                    import_by_name
                ) as u64;

                first_thunk.u1.Function = addr;
            }

            unsafe {
                p_original_first_thunk = p_original_first_thunk.add(1);
                p_first_thunk = p_first_thunk.add(1);
            }
        }

        p_image_import_descriptors = unsafe { p_image_import_descriptors.add(1) };
        image_import_descriptors = unsafe { *p_image_import_descriptors };
    }
}

pub fn get_nt(base: *const IMAGE_DOS_HEADER) -> *const IMAGE_NT_HEADERS64 {
    let dos = unsafe { *base };
    return unsafe { base.byte_add(dos.e_lfanew as usize) } as *const IMAGE_NT_HEADERS64;
}

pub fn get_optional(base: *const IMAGE_DOS_HEADER) -> *const IMAGE_OPTIONAL_HEADER64 {
    let nt = get_nt(base);
    let a = core::mem::offset_of!(IMAGE_NT_HEADERS64, OptionalHeader);
    return unsafe { nt.byte_add(a) } as *const IMAGE_OPTIONAL_HEADER64;
}

pub fn get_data_dir(base: *const IMAGE_DOS_HEADER, data_dir: usize) -> IMAGE_DATA_DIRECTORY {
    let p_optional = get_optional(base);
    let optional = unsafe { p_optional.read_unaligned() };

    return optional.DataDirectory[data_dir];
}

pub fn get_number_of_sections(base: *const IMAGE_DOS_HEADER) -> usize {
    let nt = unsafe { get_nt(base).read_unaligned() };

    nt.FileHeader.NumberOfSections as usize
}

pub fn get_aop(base: *const IMAGE_DOS_HEADER) -> usize {
    let optional = unsafe { get_optional(base).read_unaligned() };

    optional.AddressOfEntryPoint as usize
}

pub fn relocate_pe(base: *const IMAGE_DOS_HEADER) -> bool {
    let optional = unsafe { get_optional(base).read_unaligned() };
    let delta = (base as usize - optional.ImageBase as usize) as u64;
    let dir_base_reloc = get_data_dir(base, IMAGE_DIRECTORY_ENTRY_BASERELOC);
    let mut p_relocations =
        (dir_base_reloc.VirtualAddress as usize + base as usize) as *const IMAGE_BASE_RELOCATION;
    let image_base_relocation_size = core::mem::size_of::<IMAGE_BASE_RELOCATION>();
    let mut relocations = unsafe { *p_relocations };

    while relocations.VirtualAddress != 0 {
        let final_addr = base as usize + relocations.VirtualAddress as usize;
        let info = (p_relocations as usize + image_base_relocation_size) as *const u16;

        let num_entries =
            if (relocations.SizeOfBlock as isize - image_base_relocation_size as isize) < 0 {
                return false;
            } else {
                (relocations.SizeOfBlock as usize - image_base_relocation_size) / 2
            };

        for i in 0..num_entries {
            let entry = unsafe { *((info).add(i)) };
            let entry_type = (entry >> 12) & 0xF;
            let offset = entry & 0xFFF;

            match entry_type {
                0xA => unsafe {
                    let ptr = (final_addr as u64 + offset as u64) as *mut u64;
                    *ptr += delta;
                },
                _ => continue,
            }
        }

        p_relocations = (p_relocations as usize + relocations.SizeOfBlock as usize)
            as *const IMAGE_BASE_RELOCATION;
        relocations = unsafe { *p_relocations };
    }

    true
}

pub fn execute_tls(base: *const IMAGE_DOS_HEADER) {
    let tls_dir_entry = get_data_dir(base, IMAGE_DIRECTORY_ENTRY_TLS);

    if tls_dir_entry.VirtualAddress == 0 {
        return;
    }

    let tls = unsafe {
        ((base as usize + tls_dir_entry.VirtualAddress as usize) as *const IMAGE_TLS_DIRECTORY64)
            .read_unaligned()
    };

    let tls_callbacks = tls.AddressOfCallBacks; // Pointer to array of tls callback functions
    type image_tls_callback = extern "C" fn(*mut isize, u32, *mut c_void);

    let mut callback = tls_callbacks as *const image_tls_callback;
    let mut base = base as isize;

    if tls_callbacks == 0 {
        return;
    };

    #[allow(clippy::fn_to_numeric_cast_with_truncation)]
    unsafe {
        while *callback as i32 != 0 {
            (*callback)(&mut base, DLL_PROCESS_ATTACH, null_mut());
            callback = callback.add(1);
        }
    }
}

pub fn find_export(base: *const IMAGE_DOS_HEADER, export: u64) -> *const () {
    let export_entry = get_data_dir(base, IMAGE_DIRECTORY_ENTRY_EXPORT).VirtualAddress;
    let p_export_dir = (base as usize + export_entry as usize) as *const IMAGE_EXPORT_DIRECTORY;
    let export_dir = unsafe { &*p_export_dir };
    let number_of_names = export_dir.NumberOfNames as usize;

    // get names, ordinals, and addresses
    let names = slice_from_raw_parts(
        (base as usize + export_dir.AddressOfNames as usize) as *const u32,
        number_of_names,
    );

    let ordinals = slice_from_raw_parts(
        (base as usize + export_dir.AddressOfNameOrdinals as usize) as *const u16,
        export_dir.NumberOfFunctions as usize,
    );

    let addresses = slice_from_raw_parts(
        (base as usize + export_dir.AddressOfFunctions as usize) as *const u32,
        export_dir.NumberOfFunctions as usize,
    );

    for name_index in 0..number_of_names {
        let name = read_C_string(base as isize, names[name_index]);

        if djb2(name) == export {
            let ordinal = ordinals[name_index];
            let function_pointer = base as usize + addresses[ordinal as usize] as usize;
            return function_pointer as *const ();
        }
    }

    core::ptr::null()
}

pub fn finalize_sections(base: *const IMAGE_DOS_HEADER, virtual_protect_ptr: *const ()) -> bool {
    let p_nt = get_nt(base);
    let number_of_sections = get_number_of_sections(base);
    let sections = slice_from_raw_parts(
        (p_nt as usize + size_of::<IMAGE_NT_HEADERS64>()) as *const IMAGE_SECTION_HEADER,
        number_of_sections,
    );

    for i in 0..number_of_sections {
        let section = sections[i];
        let executable = ((section.Characteristics & IMAGE_SCN_MEM_EXECUTE) != 0) as usize;
        let readable = ((section.Characteristics & IMAGE_SCN_MEM_READ) != 0) as usize;
        let writeable = ((section.Characteristics & IMAGE_SCN_MEM_WRITE) != 0) as usize;
        let mut protect = PROTECTION_FLAGS[executable][readable][writeable];
        let mut old_protect = 0u32;

        if (section.Characteristics & IMAGE_SCN_MEM_NOT_CACHED) > 0 {
            protect |= PAGE_NOCACHE;
        }

        let res = call!(
            FnVirtualProtect,
            virtual_protect_ptr,
            base as usize + section.VirtualAddress as usize,
            section.SizeOfRawData as usize,
            protect,
            &mut old_protect
        );

        if !res {
            return false;
        }
    }

    true
}
