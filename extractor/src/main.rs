use exe::PEType::Disk;
use exe::{Buffer, PE, VecPE};

fn main() {
    let args: Vec<String> = std::env::args().collect();

    if args.len() < 3 {
        let current_exe = std::env::current_exe().unwrap();
        eprintln!(
            "Usage: {} <PATH TO CRABLOADER> <OUTPUT FIlE>",
            current_exe.display()
        );
        return;
    }

    let pe = VecPE::from_disk_file(args[1].as_str()).unwrap();
    let aop = pe.get_entrypoint().expect("Failed to get entrypoint");
    let section = pe
        .get_section_by_name(".text")
        .expect("Failed to find .text section");

    if section.virtual_address != aop {
        eprintln!("Entrypoint is incorrect");
    }

    let original_text_section = pe
        .read(section.data_offset(Disk), section.data_size(Disk))
        .expect("Failed to read .text section");
    let reversed_text_section = {
        let mut bytes = original_text_section.to_vec();
        bytes.reverse();

        bytes
    };

    let mut found_first = false;
    let mut found_second = false;

    for byte in reversed_text_section {
        if byte == 0x0 {
            continue;
        }

        if found_first && byte == 0x34 {
            found_second = true;
            break;
        }

        if byte == 0x12 {
            found_first = true
        }
    }

    if !found_second {
        eprintln!(".text section seems invalid. Not dumping it!");
        return;
    }

    std::fs::write(args[2].as_str(), original_text_section).unwrap();
    println!(
        "Extracted .text section from {} to {}",
        args[1].as_str(),
        args[2].as_str()
    );
}
