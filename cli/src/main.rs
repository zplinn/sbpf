use clap::{crate_version, App, Arg};
use solana_sbpf::{
    aligned_memory::AlignedMemory,
    ebpf,
    elf::Executable,
    memory_region::{MemoryMapping, MemoryRegion},
    program::{BuiltinProgram, SBPFVersion},
    verifier::RequisiteVerifier,
    vm::{Config, EbpfVm},
};
use std::{fs::File, io::Read, path::Path, process, sync::Arc};
use test_utils::TestContextObject;

const MIN_HEAP_FRAME_BYTES: u32 = 32_768;
const MAX_HEAP_FRAME_BYTES: u32 = 256 * 1024;
const MAX_COMPUTE_UNIT_LIMIT: u32 = 1_400_000;
const MAX_PERMITTED_DATA_LENGTH: usize = 10 * 1024 * 1024;
const PROGRAMDATA_METADATA_SIZE: usize = 45;
const MAX_ELF_SIZE: usize = MAX_PERMITTED_DATA_LENGTH - PROGRAMDATA_METADATA_SIZE;

fn main() {
    let matches = App::new("Solana BPF CLI")
        .version(crate_version!())
        .author("Solana Maintainers <maintainers@solana.foundation>")
        .about("CLI to execute Solana BPF programs")
        .arg(
            Arg::new("elf")
                .about("Load ELF as Solana BPF executable")
                .short('e')
                .long("elf")
                .value_name("FILE")
                .takes_value(true)
                .required(true),
        )
        .arg(
            Arg::new("input")
                .about("Input for the program to run on")
                .short('i')
                .long("input")
                .value_name("FILE / BYTES")
                .takes_value(true)
                .default_value("0"),
        )
        .arg(
            Arg::new("memory")
                .about("Heap memory in bytes, 1024-aligned, range [32768, 262144]")
                .short('m')
                .long("mem")
                .value_name("BYTES")
                .takes_value(true)
                .default_value("32768"),
        )
        .arg(
            Arg::new("use")
                .about("Method of execution to use")
                .short('u')
                .long("use")
                .takes_value(true)
                .possible_values(&["interpreter", "jit"])
                .required(true),
        )
        .arg(
            Arg::new("compute unit limit")
                .about("Compute unit limit, capped at 1400000")
                .short('l')
                .long("lim")
                .takes_value(true)
                .value_name("COUNT")
                .default_value("1400000"),
        )
        .get_matches();

    let heap_bytes: u32 = matches
        .value_of("memory")
        .unwrap()
        .parse()
        .unwrap_or_else(|_| {
            eprintln!("Error: invalid heap size");
            process::exit(1);
        });
    if heap_bytes < MIN_HEAP_FRAME_BYTES || heap_bytes > MAX_HEAP_FRAME_BYTES {
        eprintln!(
            "Error: heap size must be in range [{MIN_HEAP_FRAME_BYTES}, {MAX_HEAP_FRAME_BYTES}]"
        );
        process::exit(1);
    }
    if !heap_bytes.is_multiple_of(1024) {
        eprintln!("Error: heap size must be 1024-byte aligned");
        process::exit(1);
    }

    let compute_unit_limit: u32 = matches
        .value_of("compute unit limit")
        .unwrap()
        .parse::<u32>()
        .unwrap_or_else(|_| {
            eprintln!("Error: invalid compute unit limit");
            process::exit(1);
        })
        .min(MAX_COMPUTE_UNIT_LIMIT);

    let loader = Arc::new(BuiltinProgram::new_loader(Config {
        max_call_depth: 64,
        stack_frame_size: 4_096,
        enable_address_translation: true,
        enable_stack_frame_gaps: true,
        instruction_meter_checkpoint_distance: 10000,
        enable_instruction_meter: true,
        enable_register_tracing: false,
        enable_symbol_and_section_labels: false,
        reject_broken_elfs: false,
        noop_instruction_rate: 256,
        sanitize_user_provided_values: true,
        optimize_rodata: false,
        aligned_memory_mapping: true,
        allow_memory_region_zero: false,
        enabled_sbpf_versions: SBPFVersion::V0..=SBPFVersion::V0,
    }));

    let mut file = File::open(Path::new(matches.value_of("elf").unwrap())).unwrap();
    let mut elf = Vec::new();
    file.read_to_end(&mut elf).unwrap();
    if elf.len() > MAX_ELF_SIZE {
        eprintln!(
            "Error: ELF size {} exceeds maximum program size of {} bytes",
            elf.len(),
            MAX_ELF_SIZE,
        );
        process::exit(1);
    }
    #[allow(unused_mut)]
    let mut executable = match Executable::<TestContextObject>::from_elf(&elf, loader) {
        Ok(executable) => executable,
        Err(err) => {
            eprintln!("Error: Failed to load ELF: {err:?}");
            process::exit(1);
        }
    };

    if let Err(err) = executable.verify::<RequisiteVerifier>() {
        eprintln!("Error: ELF verification failed: {err:?}");
        process::exit(1);
    }

    #[cfg(all(not(target_os = "windows"), target_arch = "x86_64"))]
    executable.jit_compile().unwrap();

    let mut mem = match matches.value_of("input").unwrap().parse::<usize>() {
        Ok(allocate) => vec![0u8; allocate],
        Err(_) => {
            let mut file = File::open(Path::new(matches.value_of("input").unwrap())).unwrap();
            let mut memory = Vec::new();
            file.read_to_end(&mut memory).unwrap();
            memory
        }
    };
    let mut context_object = TestContextObject::new(u64::from(compute_unit_limit));
    let config = executable.get_config();
    let sbpf_version = executable.get_sbpf_version();
    let mut stack = AlignedMemory::<{ ebpf::HOST_ALIGN }>::zero_filled(config.stack_size());
    let stack_len = stack.len();
    let mut heap = AlignedMemory::<{ ebpf::HOST_ALIGN }>::zero_filled(heap_bytes as usize);
    let regions: Vec<MemoryRegion> = vec![
        executable.get_ro_region(),
        MemoryRegion::new_writable_gapped(
            stack.as_slice_mut(),
            ebpf::MM_STACK_START,
            if sbpf_version.stack_frame_gaps() && config.enable_stack_frame_gaps {
                config.stack_frame_size as u64
            } else {
                0
            },
        ),
        MemoryRegion::new_writable(heap.as_slice_mut(), ebpf::MM_HEAP_START),
        MemoryRegion::new_writable(&mut mem, ebpf::MM_INPUT_START),
    ];

    let memory_mapping = MemoryMapping::new(regions, config, sbpf_version).unwrap();

    let mut vm = EbpfVm::new(
        executable.get_loader().clone(),
        executable.get_sbpf_version(),
        &mut context_object,
        memory_mapping,
        stack_len,
    );

    let (instruction_count, result) =
        vm.execute_program(&executable, matches.value_of("use").unwrap() != "jit");
    println!("Result: {result:?}");
    println!("Instruction Count: {instruction_count}");
}
