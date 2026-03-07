use core::{mem, slice};

use crate::defs::UNICODE_STRING;

#[cfg(not(debug_assertions))]
#[panic_handler]
pub fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

pub const fn djb2(input: &[u8]) -> u64 {
    let mut hash: u64 = 5381;
    let mut count = 0;

    while count < input.len() {
        let byte = input[count];
        hash = (hash.wrapping_shl(5)).wrapping_add(hash) + byte.to_ascii_lowercase() as u64;
        count += 1;
    }

    hash
}

#[macro_export]
macro_rules! call {
    ($function_type:ty, $function_pointer:expr, $($args:expr),* ) => {
        {
            type func_type = $function_type;
            let func_ptr = $function_pointer;
            let function = unsafe {
                core::mem::transmute::<*const (), func_type>(func_ptr)
            };

            function($($args),*)
        }
    };
}

pub fn slice_from_raw_parts<'a, T>(data: *const T, len: usize) -> &'a [T] {
    unsafe { slice::from_raw_parts(data, len) }
}

pub fn djb2_from_u16(input: &[u16]) -> u64 {
    let mut hash: u64 = 5381;
    let mut count = 0;

    while count < input.len() {
        let byte = unsafe { char::from_u32_unchecked(input[count] as u32) };
        hash = (hash.wrapping_shl(5)).wrapping_add(hash) + byte.to_ascii_lowercase() as u64;
        count += 1;
    }

    hash
}

pub fn unicode_string_to_string(unicode_string: &UNICODE_STRING) -> &[u16] {
    let address = unicode_string.Buffer;
    let elements = unicode_string.Length as usize / mem::size_of::<u16>();

    unsafe { slice::from_raw_parts(address, elements) }
}

#[macro_export]
macro_rules! containing_record {
    ($ptr:expr, $container:path, $($field:expr)?) => {
        (($ptr as *const _ as usize) - core::mem::offset_of!($container, $($field)?))
            as *const $container
    };
}

pub fn read_C_string(base: isize, rva: u32) -> &'static [u8] {
    let address = (base as usize + rva as usize) as *const u8;

    for i in 0..256 {
        unsafe {
            if *address.add(i) == 0 {
                return slice_from_raw_parts(address, i);
            }
        }
    }

    &[0]
}

#[unsafe(no_mangle)]
pub extern "C" fn memset(dest: *mut u8, value: i32, count: usize) -> *mut u8 {
    unsafe {
        for i in 0..count {
            *(dest.add(i)) = value as u8;
        }
    }

    dest
}

#[unsafe(no_mangle)]
pub extern "C" fn memcpy(dest: *mut u8, src: *const u8, size: usize) -> *mut u8 {
    unsafe {
        for i in 0..size {
            *(dest.add(i)) = *(src.add(i));
        }
    };

    dest
}

#[unsafe(no_mangle)]
pub extern "C" fn memcmp(val1: *const u8, val2: *const u8, count: usize) -> i32 {
    unsafe {
        for i in 0..count {
            if val1.add(i) != val2.add(i) {
                return (*val1 as i32) - (*val2 as i32);
            }
        }
    }

    0
}

#[unsafe(no_mangle)]
pub extern "C" fn strlen(pstr: *const i8) -> usize {
    let string = unsafe { core::ffi::CStr::from_ptr(pstr) };

    string.count_bytes()
}
