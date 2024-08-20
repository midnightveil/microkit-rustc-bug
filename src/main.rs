#![allow(clippy::assertions_on_constants)]

use elf::ElfFile;
use microkit_tool::sysxml::{
    parse, PlatformDescription, ProtectionDomain, SysMap, SysMemoryRegion, SystemDescription,
    VirtualMachine,
};
use microkit_tool::{
    elf, sel4, util, DisjointMemoryRegion, MemoryRegion, ObjectAllocator, Region, UntypedObject,
};
use sel4::{
    Arch, ArmVmAttributes, BootInfo, Config, Invocation, InvocationArgs, Object, ObjectType,
    PageSize, Rights,
};
use std::cmp::max;
use std::collections::HashMap;
use std::fs;
use std::io::{Read, Write};
use std::iter::zip;
use std::mem::size_of;
use std::path::{Path, PathBuf};
use util::bytes_to_struct;

const SYMBOL_IPC_BUFFER: &str = "__sel4_ipc_buffer_obj";

const FAULT_BADGE: u64 = 1 << 62;
const PPC_BADGE: u64 = 1 << 63;

const INPUT_CAP_IDX: u64 = 1;
#[allow(dead_code)]
const FAULT_EP_CAP_IDX: u64 = 2;
const VSPACE_CAP_IDX: u64 = 3;
const REPLY_CAP_IDX: u64 = 4;
const MONITOR_EP_CAP_IDX: u64 = 5;
const TCB_CAP_IDX: u64 = 6;

const BASE_OUTPUT_NOTIFICATION_CAP: u64 = 10;
const BASE_OUTPUT_ENDPOINT_CAP: u64 = BASE_OUTPUT_NOTIFICATION_CAP + 64;
const BASE_IRQ_CAP: u64 = BASE_OUTPUT_ENDPOINT_CAP + 64;
const BASE_PD_TCB_CAP: u64 = BASE_IRQ_CAP + 64;
const BASE_VM_TCB_CAP: u64 = BASE_PD_TCB_CAP + 64;
const BASE_VCPU_CAP: u64 = BASE_VM_TCB_CAP + 64;
const BASE_FRAME_CAP: u64 = BASE_VCPU_CAP + 64;

const MAX_SYSTEM_INVOCATION_SIZE: u64 = util::mb(128);

const PD_CAP_SIZE: u64 = 512;
const PD_CAP_BITS: u64 = PD_CAP_SIZE.ilog2() as u64;
const PD_SCHEDCONTEXT_SIZE: u64 = 1 << 8;

const SLOT_BITS: u64 = 5;
const SLOT_SIZE: u64 = 1 << SLOT_BITS;

const INIT_NULL_CAP_ADDRESS: u64 = 0;
const INIT_TCB_CAP_ADDRESS: u64 = 1;
const INIT_CNODE_CAP_ADDRESS: u64 = 2;
const INIT_VSPACE_CAP_ADDRESS: u64 = 3;
const IRQ_CONTROL_CAP_ADDRESS: u64 = 4; // Singleton

const INIT_ASID_POOL_CAP_ADDRESS: u64 = 6;

#[derive(Debug)]
struct FixedUntypedAlloc {
    ut: UntypedObject,
    watermark: u64,
}

impl FixedUntypedAlloc {
    pub fn new(ut: UntypedObject) -> FixedUntypedAlloc {
        FixedUntypedAlloc {
            ut,
            watermark: ut.base(),
        }
    }
}

struct InitSystem {
    cap_slot: u64,
    device_untyped: Vec<FixedUntypedAlloc>,
}

impl InitSystem {
    #[allow(clippy::too_many_arguments)] // just this one time, pinky-promise...
    pub fn new(first_available_cap_slot: u64, kernel_boot_info: &BootInfo) -> InitSystem {
        let mut device_untyped: Vec<FixedUntypedAlloc> = kernel_boot_info
            .untyped_objects
            .iter()
            .filter_map(|ut| {
                if ut.is_device {
                    Some(FixedUntypedAlloc::new(*ut))
                } else {
                    None
                }
            })
            .collect();
        device_untyped.sort_by(|a, b| a.ut.base().cmp(&b.ut.base()));

        InitSystem {
            cap_slot: first_available_cap_slot,
            device_untyped,
        }
    }

    pub fn reserve(&mut self, allocations: Vec<(&UntypedObject, u64)>) {}

    pub fn allocate_objects(
        &mut self,
        object_type: ObjectType,
        names: Vec<String>,
        size: Option<u64>,
    ) -> Vec<Object> {
        vec![]
    }
}

#[allow(dead_code)]
struct BuiltSystem {
    number_of_system_caps: u64,
    invocation_data: Vec<u8>,
    invocation_data_size: u64,
    bootstrap_invocations: Vec<Invocation>,
    system_invocations: Vec<Invocation>,
    kernel_boot_info: BootInfo,
    reserved_region: MemoryRegion,
    fault_ep_cap_address: u64,
    reply_cap_address: u64,
    cap_lookup: HashMap<u64, String>,
    tcb_caps: Vec<u64>,
    sched_caps: Vec<u64>,
    ntfn_caps: Vec<u64>,
    pd_elf_regions: Vec<Vec<Region>>,
    pd_elf_files: Vec<ElfFile>,
    kernel_objects: Vec<Object>,
    initial_task_virt_region: MemoryRegion,
    initial_task_phys_region: MemoryRegion,
}

fn phys_mem_regions_from_elf(elf: &ElfFile, alignment: u64) -> Vec<MemoryRegion> {
    assert!(alignment > 0);

    elf.segments
        .iter()
        .map(|s| {
            MemoryRegion::new(
                util::round_down(s.phys_addr, alignment),
                util::round_up(s.phys_addr + s.data.len() as u64, alignment),
            )
        })
        .collect()
}

fn phys_mem_region_from_elf(elf: &ElfFile, alignment: u64) -> MemoryRegion {
    assert!(alignment > 0);
    assert!(elf.segments.len() == 1);

    phys_mem_regions_from_elf(elf, alignment)[0]
}

fn virt_mem_regions_from_elf(elf: &ElfFile, alignment: u64) -> Vec<MemoryRegion> {
    assert!(alignment > 0);
    elf.segments
        .iter()
        .map(|s| {
            MemoryRegion::new(
                util::round_down(s.virt_addr, alignment),
                util::round_up(s.virt_addr + s.data.len() as u64, alignment),
            )
        })
        .collect()
}

fn virt_mem_region_from_elf(elf: &ElfFile, alignment: u64) -> MemoryRegion {
    assert!(alignment > 0);
    assert!(elf.segments.len() == 1);

    virt_mem_regions_from_elf(elf, alignment)[0]
}

fn get_full_path(path: &Path, search_paths: &Vec<PathBuf>) -> Option<PathBuf> {
    for search_path in search_paths {
        let full_path = search_path.join(path);
        if full_path.exists() {
            return Some(full_path.to_path_buf());
        }
    }

    None
}

struct KernelPartialBootInfo {
    device_memory: DisjointMemoryRegion,
    normal_memory: DisjointMemoryRegion,
    boot_region: MemoryRegion,
}

#[repr(C)]
struct KernelFrame64 {
    pub paddr: u64,
    pub pptr: u64,
    pub execute_never: u32,
    pub user_accessible: u32,
}

fn kernel_device_addrs(kernel_config: &Config, kernel_elf: &ElfFile) -> Vec<u64> {
    assert!(kernel_config.word_size == 64, "Unsupported word-size");

    let mut kernel_devices = Vec::new();
    let (vaddr, size) = kernel_elf
        .find_symbol("kernel_device_frames")
        .expect("Could not find 'kernel_device_frames' symbol");
    let kernel_frame_bytes = kernel_elf.get_data(vaddr, size).unwrap();
    let kernel_frame_size = size_of::<KernelFrame64>();
    let mut offset: usize = 0;
    while offset < size as usize {
        let kernel_frame = unsafe {
            bytes_to_struct::<KernelFrame64>(
                &kernel_frame_bytes[offset..offset + kernel_frame_size],
            )
        };
        if kernel_frame.user_accessible == 0 {
            kernel_devices.push(kernel_frame.paddr);
        }
        offset += kernel_frame_size;
    }

    kernel_devices
}

#[repr(C)]
struct KernelRegion64 {
    start: u64,
    end: u64,
}

fn kernel_phys_mem(kernel_config: &Config, kernel_elf: &ElfFile) -> Vec<(u64, u64)> {
    assert!(kernel_config.word_size == 64, "Unsupported word-size");
    let mut phys_mem = Vec::new();
    let (vaddr, size) = kernel_elf
        .find_symbol("avail_p_regs")
        .expect("Could not find 'avail_p_regs' symbol");
    let p_region_bytes = kernel_elf.get_data(vaddr, size).unwrap();
    let p_region_size = size_of::<KernelRegion64>();
    let mut offset: usize = 0;
    while offset < size as usize {
        let p_region = unsafe {
            bytes_to_struct::<KernelRegion64>(&p_region_bytes[offset..offset + p_region_size])
        };
        phys_mem.push((p_region.start, p_region.end));
        offset += p_region_size;
    }

    phys_mem
}

fn kernel_self_mem(kernel_elf: &ElfFile) -> MemoryRegion {
    let base = kernel_elf.segments[0].phys_addr;
    let (ki_end_v, _) = kernel_elf
        .find_symbol("ki_end")
        .expect("Could not find 'ki_end' symbol");
    let ki_end_p = ki_end_v - kernel_elf.segments[0].virt_addr + base;

    MemoryRegion::new(base, ki_end_p)
}

fn kernel_boot_mem(kernel_elf: &ElfFile) -> MemoryRegion {
    let base = kernel_elf.segments[0].phys_addr;
    let (ki_boot_end_v, _) = kernel_elf
        .find_symbol("ki_boot_end")
        .expect("Could not find 'ki_boot_end' symbol");
    let ki_boot_end_p = ki_boot_end_v - kernel_elf.segments[0].virt_addr + base;

    MemoryRegion::new(base, ki_boot_end_p)
}

fn kernel_partial_boot(kernel_config: &Config, kernel_elf: &ElfFile) -> KernelPartialBootInfo {
    let mut device_memory = DisjointMemoryRegion::default();
    let mut normal_memory = DisjointMemoryRegion::default();

    device_memory.insert_region(0, kernel_config.paddr_user_device_top);

    for paddr in kernel_device_addrs(kernel_config, kernel_elf) {
        device_memory.remove_region(paddr, paddr + kernel_config.kernel_frame_size);
    }

    for (start, end) in kernel_phys_mem(kernel_config, kernel_elf) {
        device_memory.remove_region(start, end);
        normal_memory.insert_region(start, end);
    }

    let self_mem = kernel_self_mem(kernel_elf);
    normal_memory.remove_region(self_mem.base, self_mem.end);

    let boot_region = kernel_boot_mem(kernel_elf);

    KernelPartialBootInfo {
        device_memory,
        normal_memory,
        boot_region,
    }
}

fn emulate_kernel_boot_partial(
    kernel_config: &Config,
    kernel_elf: &ElfFile,
) -> (DisjointMemoryRegion, MemoryRegion) {
    let partial_info = kernel_partial_boot(kernel_config, kernel_elf);
    (partial_info.normal_memory, partial_info.boot_region)
}

fn get_n_paging(region: MemoryRegion, bits: u64) -> u64 {
    let start = util::round_down(region.base, 1 << bits);
    let end = util::round_up(region.end, 1 << bits);

    (end - start) / (1 << bits)
}

fn get_arch_n_paging(region: MemoryRegion) -> u64 {
    const PT_INDEX_OFFSET: u64 = 12;
    const PD_INDEX_OFFSET: u64 = PT_INDEX_OFFSET + 9;
    const PUD_INDEX_OFFSET: u64 = PD_INDEX_OFFSET + 9;

    get_n_paging(region, PUD_INDEX_OFFSET) + get_n_paging(region, PD_INDEX_OFFSET)
}

fn rootserver_max_size_bits() -> u64 {
    let slot_bits = 5; // seL4_SlotBits
    let root_cnode_bits = 12; // CONFIG_ROOT_CNODE_SIZE_BITS
    let vspace_bits = 13; // seL4_VSpaceBits

    let cnode_size_bits = root_cnode_bits + slot_bits;
    max(cnode_size_bits, vspace_bits)
}

fn calculate_rootserver_size(initial_task_region: MemoryRegion) -> u64 {
    let slot_bits = 5; // seL4_SlotBits
    let root_cnode_bits = 12; // CONFIG_ROOT_CNODE_SIZE_BITS
    let tcb_bits = 11; // seL4_TCBBits
    let page_bits = 12; // seL4_PageBits
    let asid_pool_bits = 12; // seL4_ASIDPoolBits
    let vspace_bits = 13; // seL4_VSpaceBits
    let page_table_bits = 12; // seL4_PageTableBits
    let min_sched_context_bits = 7; // seL4_MinSchedContextBits

    let mut size = 0;
    size += 1 << (root_cnode_bits + slot_bits);
    size += 1 << (tcb_bits);
    size += 2 * (1 << page_bits);
    size += 1 << asid_pool_bits;
    size += 1 << vspace_bits;
    size += get_arch_n_paging(initial_task_region) * (1 << page_table_bits);
    size += 1 << min_sched_context_bits;

    size
}

fn emulate_kernel_boot(
    kernel_config: &Config,
    kernel_elf: &ElfFile,
    initial_task_phys_region: MemoryRegion,
    initial_task_virt_region: MemoryRegion,
    reserved_region: MemoryRegion,
) -> BootInfo {
    assert!(initial_task_phys_region.size() == initial_task_virt_region.size());
    let partial_info = kernel_partial_boot(kernel_config, kernel_elf);
    let mut normal_memory = partial_info.normal_memory;
    let device_memory = partial_info.device_memory;
    let boot_region = partial_info.boot_region;

    normal_memory.remove_region(initial_task_phys_region.base, initial_task_phys_region.end);
    normal_memory.remove_region(reserved_region.base, reserved_region.end);

    let initial_objects_size = calculate_rootserver_size(initial_task_virt_region);
    let initial_objects_align = rootserver_max_size_bits();

    let mut region_to_remove: Option<u64> = None;
    for region in normal_memory.regions.iter().rev() {
        let start = util::round_down(
            region.end - initial_objects_size,
            1 << initial_objects_align,
        );
        if start >= region.base {
            region_to_remove = Some(start);
            break;
        }
    }
    if let Some(start) = region_to_remove {
        normal_memory.remove_region(start, start + initial_objects_size);
    } else {
        panic!("Couldn't find appropriate region for initial task kernel objects");
    }

    let fixed_cap_count = 0x10;
    let sched_control_cap_count = 1;
    let paging_cap_count = get_arch_n_paging(initial_task_virt_region);
    let page_cap_count = initial_task_virt_region.size() / kernel_config.minimum_page_size;
    let first_untyped_cap =
        fixed_cap_count + paging_cap_count + sched_control_cap_count + page_cap_count;
    let sched_control_cap = fixed_cap_count + paging_cap_count;

    let device_regions: Vec<MemoryRegion> = [
        reserved_region.aligned_power_of_two_regions(),
        device_memory.aligned_power_of_two_regions(),
    ]
    .concat();
    let normal_regions: Vec<MemoryRegion> = [
        boot_region.aligned_power_of_two_regions(),
        normal_memory.aligned_power_of_two_regions(),
    ]
    .concat();
    let mut untyped_objects = Vec::new();
    for (i, r) in device_regions.iter().enumerate() {
        let cap = i as u64 + first_untyped_cap;
        untyped_objects.push(UntypedObject::new(cap, *r, true));
    }
    let normal_regions_start_cap = first_untyped_cap + device_regions.len() as u64;
    for (i, r) in normal_regions.iter().enumerate() {
        let cap = i as u64 + normal_regions_start_cap;
        untyped_objects.push(UntypedObject::new(cap, *r, false));
    }

    let first_available_cap =
        first_untyped_cap + device_regions.len() as u64 + normal_regions.len() as u64;
    BootInfo {
        fixed_cap_count,
        paging_cap_count,
        page_cap_count,
        sched_control_cap,
        first_available_cap,
        untyped_objects,
    }
}

fn build_system(
    kernel_config: &Config,
    kernel_elf: &ElfFile,
    monitor_elf: &ElfFile,
    system: &SystemDescription,
    invocation_table_size: u64,
    system_cnode_size: u64,
    search_paths: &Vec<PathBuf>,
) -> Result<BuiltSystem, String> {
    assert!(util::is_power_of_two(system_cnode_size));
    assert!(invocation_table_size % kernel_config.minimum_page_size == 0);
    assert!(invocation_table_size <= MAX_SYSTEM_INVOCATION_SIZE);

    let mut cap_address_names: HashMap<u64, String> = HashMap::new();
    cap_address_names.insert(INIT_NULL_CAP_ADDRESS, "null".to_string());
    cap_address_names.insert(INIT_TCB_CAP_ADDRESS, "TCB: init".to_string());
    cap_address_names.insert(INIT_CNODE_CAP_ADDRESS, "CNode: init".to_string());
    cap_address_names.insert(INIT_VSPACE_CAP_ADDRESS, "VSpace: init".to_string());
    cap_address_names.insert(INIT_ASID_POOL_CAP_ADDRESS, "ASID Pool: init".to_string());
    cap_address_names.insert(IRQ_CONTROL_CAP_ADDRESS, "IRQ Control".to_string());

    let system_cnode_bits = system_cnode_size.ilog2() as u64;

    let initial_task_size =
        phys_mem_region_from_elf(monitor_elf, kernel_config.minimum_page_size).size();

    let mut pd_elf_files = Vec::with_capacity(system.protection_domains.len());
    for pd in &system.protection_domains {
        match get_full_path(&pd.program_image, search_paths) {
            Some(path) => {
                let elf = ElfFile::from_path(&path).unwrap();
                pd_elf_files.push(elf);
            }
            None => {
                return Err(format!(
                    "unable to find program image: '{}'",
                    pd.program_image.display()
                ))
            }
        }
    }

    let mut pd_elf_size = 0;
    for pd_elf in &pd_elf_files {
        for r in phys_mem_regions_from_elf(pd_elf, kernel_config.minimum_page_size) {
            pd_elf_size += r.size();
        }
    }
    let reserved_size = invocation_table_size + pd_elf_size;

    let (mut available_memory, kernel_boot_region) =
        emulate_kernel_boot_partial(kernel_config, kernel_elf);

    let reserved_base = available_memory.allocate_from(reserved_size, kernel_boot_region.end);
    assert!(kernel_boot_region.base < reserved_base);

    let initial_task_phys_base =
        available_memory.allocate_from(initial_task_size, reserved_base + reserved_size);
    assert!(reserved_base < initial_task_phys_base);

    let initial_task_phys_region = MemoryRegion::new(
        initial_task_phys_base,
        initial_task_phys_base + initial_task_size,
    );
    let initial_task_virt_region =
        virt_mem_region_from_elf(monitor_elf, kernel_config.minimum_page_size);

    let reserved_region = MemoryRegion::new(reserved_base, reserved_base + reserved_size);

    let kernel_boot_info = emulate_kernel_boot(
        kernel_config,
        kernel_elf,
        initial_task_phys_region,
        initial_task_virt_region,
        reserved_region,
    );

    for ut in &kernel_boot_info.untyped_objects {
        let dev_str = if ut.is_device { " (device)" } else { "" };
        let ut_str = format!(
            "Untyped @ 0x{:x}:0x{:x}{}",
            ut.region.base,
            ut.region.size(),
            dev_str
        );
        cap_address_names.insert(ut.cap, ut_str);
    }

    let mut kao = ObjectAllocator::new(&kernel_boot_info);

    let root_cnode_cap = kernel_boot_info.first_available_cap;
    cap_address_names.insert(root_cnode_cap, "CNode: root".to_string());

    let system_cnode_cap = kernel_boot_info.first_available_cap + 1;
    cap_address_names.insert(system_cnode_cap, "CNode: system".to_string());

    let mut bootstrap_invocations = Vec::new();


    let system_cap_address_mask = 1 << (kernel_config.cap_address_bits - 1);

    let pages_required = invocation_table_size / kernel_config.minimum_page_size;
    let base_page_cap = 0;
    for pta in base_page_cap..base_page_cap + pages_required {
        cap_address_names.insert(
            system_cap_address_mask | pta,
            "SmallPage: monitor invocation table".to_string(),
        );
    }

    let invocation_table_allocations = Vec::new();
    let mut cap_slot = base_page_cap;

    let page_tables_required = util::round_up(invocation_table_size, sel4::OBJECT_SIZE_LARGE_PAGE)
        / sel4::OBJECT_SIZE_LARGE_PAGE;
    let page_table_allocation = kao.alloc_n(sel4::OBJECT_SIZE_PAGE_TABLE, page_tables_required);
    let base_page_table_cap = cap_slot;

    for pta in base_page_table_cap..base_page_table_cap + page_tables_required {
        cap_address_names.insert(
            system_cap_address_mask | pta,
            "PageTable: monitor".to_string(),
        );
    }

    assert!(page_tables_required <= kernel_config.fan_out_limit);
    bootstrap_invocations.push(Invocation::new(InvocationArgs::UntypedRetype {
        untyped: page_table_allocation.untyped_cap_address,
        object_type: ObjectType::PageTable,
        size_bits: 0,
        root: root_cnode_cap,
        node_index: 1,
        node_depth: 1,
        node_offset: cap_slot,
        num_objects: page_tables_required,
    }));
    cap_slot += page_tables_required;

    let page_table_vaddr: u64 = 0x8000_0000;

    let mut pt_map_invocation = Invocation::new(InvocationArgs::PageTableMap {
        page_table: system_cap_address_mask | base_page_table_cap,
        vspace: INIT_VSPACE_CAP_ADDRESS,
        vaddr: page_table_vaddr,
        attr: ArmVmAttributes::default(),
    });
    pt_map_invocation.repeat(
        page_tables_required as u32,
        InvocationArgs::PageTableMap {
            page_table: 1,
            vspace: 0,
            vaddr: ObjectType::LargePage as u64,
            attr: 0,
        },
    );
    bootstrap_invocations.push(pt_map_invocation);

    let page_vaddr: u64 = 0x8000_0000;
    let mut map_invocation = Invocation::new(InvocationArgs::PageMap {
        page: system_cap_address_mask | base_page_cap,
        vspace: INIT_VSPACE_CAP_ADDRESS,
        vaddr: page_vaddr,
        rights: Rights::Read as u64,
        attr: ArmVmAttributes::default() | ArmVmAttributes::ExecuteNever as u64,
    });
    map_invocation.repeat(
        pages_required as u32,
        InvocationArgs::PageMap {
            page: 1,
            vspace: 0,
            vaddr: kernel_config.minimum_page_size,
            rights: 0,
            attr: 0,
        },
    );
    bootstrap_invocations.push(map_invocation);

    let extra_mrs = Vec::new();
    let pd_extra_maps: HashMap<&ProtectionDomain, Vec<SysMap>> = HashMap::new();
    let mut all_mrs: Vec<&SysMemoryRegion> =
        Vec::with_capacity(system.memory_regions.len() + extra_mrs.len());
    for mr_set in [&system.memory_regions, &extra_mrs] {
        for mr in mr_set {
            all_mrs.push(mr);
        }
    }
    let all_mr_by_name: HashMap<&str, &SysMemoryRegion> =
        all_mrs.iter().map(|mr| (mr.name.as_str(), *mr)).collect();

    let mut system_invocations: Vec<Invocation> = Vec::new();
    let mut init_system = InitSystem::new(cap_slot, &kernel_boot_info);

    init_system.reserve(invocation_table_allocations);

    let mut small_page_names = Vec::new();
    let mut large_page_names = Vec::new();

    for pd in &system.protection_domains {
        let ipc_buffer_str = format!(
            "Page({}): IPC Buffer PD={}",
            util::human_size_strict(PageSize::Small as u64),
            pd.name
        );
        small_page_names.push(ipc_buffer_str);
    }

    for mr in &all_mrs {
        if mr.phys_addr.is_some() {
            continue;
        }

        let page_size_human = util::human_size_strict(mr.page_size as u64);
        for idx in 0..mr.page_count {
            let page_str = format!("Page({}): MR={} #{}", page_size_human, mr.name, idx);
            match mr.page_size as PageSize {
                PageSize::Small => small_page_names.push(page_str),
                PageSize::Large => large_page_names.push(page_str),
            }
        }
    }

    let mut page_objects: HashMap<PageSize, &Vec<Object>> = HashMap::new();

    let large_page_objs =
        init_system.allocate_objects(ObjectType::LargePage, large_page_names, None);
    let small_page_objs =
        init_system.allocate_objects(ObjectType::SmallPage, small_page_names, None);

    let ipc_buffer_objs = &small_page_objs[..system.protection_domains.len()];

    page_objects.insert(PageSize::Large, &large_page_objs);
    page_objects.insert(PageSize::Small, &small_page_objs);

    let mut mr_pages: HashMap<&SysMemoryRegion, Vec<Object>> = HashMap::new();
    let mut pg_idx: HashMap<PageSize, u64> = HashMap::new();

    pg_idx.insert(PageSize::Small, ipc_buffer_objs.len() as u64);
    pg_idx.insert(PageSize::Large, 0);

    for mr in &all_mrs {
        if mr.phys_addr.is_some() {
            mr_pages.insert(mr, vec![]);
            continue;
        }
        let idx = *pg_idx.get(&mr.page_size).unwrap() as usize;
        mr_pages.insert(
            mr,
            page_objects[&mr.page_size][idx..idx + mr.page_count as usize].to_vec(),
        );

        *pg_idx.get_mut(&mr.page_size).unwrap() += mr.page_count;
    }

    let mut fixed_pages = Vec::new();
    for mr in &all_mrs {
        if let Some(mut phys_addr) = mr.phys_addr {
            for _ in 0..mr.page_count {
                fixed_pages.push((phys_addr, mr));
                phys_addr += mr.page_bytes();
            }
        }
    }

    let virtual_machines: Vec<&VirtualMachine> = system
        .protection_domains
        .iter()
        .filter_map(|pd| match &pd.virtual_machine {
            Some(vm) => Some(vm),
            None => None,
        })
        .collect();

    let mut tcb_names: Vec<String> = system
        .protection_domains
        .iter()
        .map(|pd| format!("TCB: PD={}", pd.name))
        .collect();
    let vm_tcb_names: Vec<String> = virtual_machines
        .iter()
        .map(|vm| format!("TCB: VM={}", vm.name))
        .collect();
    tcb_names.extend(vm_tcb_names);
    let tcb_objs = init_system.allocate_objects(ObjectType::Tcb, tcb_names, None);

    let pd_tcb_objs = &tcb_objs[..system.protection_domains.len()];
    let vm_tcb_objs = &tcb_objs[system.protection_domains.len()..];
    assert!(pd_tcb_objs.len() + vm_tcb_objs.len() == tcb_objs.len());

    let vcpu_names: Vec<String> = virtual_machines
        .iter()
        .map(|vm| format!("VCPU: VM={}", vm.name))
        .collect();
    let vcpu_objs = init_system.allocate_objects(ObjectType::Vcpu, vcpu_names, None);

    let mut sched_context_names: Vec<String> = system
        .protection_domains
        .iter()
        .map(|pd| format!("SchedContext: PD={}", pd.name))
        .collect();
    let vm_sched_context_names: Vec<String> = virtual_machines
        .iter()
        .map(|vm| format!("SchedContext: VM={}", vm.name))
        .collect();
    sched_context_names.extend(vm_sched_context_names);
    let sched_context_objs = init_system.allocate_objects(
        ObjectType::SchedContext,
        sched_context_names,
        Some(PD_SCHEDCONTEXT_SIZE),
    );

    let pd_sched_context_objs = &sched_context_objs[..system.protection_domains.len()];
    let vm_sched_context_objs = &sched_context_objs[system.protection_domains.len()..];

    let pd_endpoint_names: Vec<String> = system
        .protection_domains
        .iter()
        .filter(|pd| pd.needs_ep())
        .map(|pd| format!("EP: PD={}", pd.name))
        .collect();
    let endpoint_names = [vec![format!("EP: Monitor Fault")], pd_endpoint_names].concat();

    let pd_reply_names: Vec<String> = system
        .protection_domains
        .iter()
        .map(|pd| format!("Reply: PD={}", pd.name))
        .collect();
    let reply_names = [vec![format!("Reply: Monitor")], pd_reply_names].concat();
    let reply_objs = init_system.allocate_objects(ObjectType::Reply, reply_names, None);

    let pd_reply_objs = &reply_objs[1..];
    let endpoint_objs = init_system.allocate_objects(ObjectType::Endpoint, endpoint_names, None);
    let fault_ep_endpoint_object = &endpoint_objs[0];

    let pd_endpoint_objs: Vec<Option<&Object>> = {
        let mut i = 0;
        system
            .protection_domains
            .iter()
            .map(|pd| {
                if pd.needs_ep() {
                    let obj = &endpoint_objs[1..][i];
                    i += 1;
                    Some(obj)
                } else {
                    None
                }
            })
            .collect()
    };

    let notification_names = system
        .protection_domains
        .iter()
        .map(|pd| format!("Notification: PD={}", pd.name))
        .collect();
    let notification_objs =
        init_system.allocate_objects(ObjectType::Notification, notification_names, None);

    let mut all_pd_uds: Vec<(usize, u64)> = Vec::new();
    let mut all_pd_ds: Vec<(usize, u64)> = Vec::new();
    let mut all_pd_pts: Vec<(usize, u64)> = Vec::new();
    all_pd_uds.sort_by_key(|ud| ud.0);
    all_pd_ds.sort_by_key(|d| d.0);
    all_pd_pts.sort_by_key(|pt| pt.0);

    let mut all_vm_uds: Vec<(usize, u64)> = Vec::new();
    let mut all_vm_ds: Vec<(usize, u64)> = Vec::new();
    let mut all_vm_pts: Vec<(usize, u64)> = Vec::new();

    all_vm_uds.sort_by_key(|ud| ud.0);
    all_vm_ds.sort_by_key(|d| d.0);
    all_vm_pts.sort_by_key(|pt| pt.0);

    let pd_names: Vec<&str> = system
        .protection_domains
        .iter()
        .map(|pd| pd.name.as_str())
        .collect();
    let vm_names: Vec<&str> = virtual_machines.iter().map(|vm| vm.name.as_str()).collect();

    let mut vspace_names: Vec<String> = system
        .protection_domains
        .iter()
        .map(|pd| format!("VSpace: PD={}", pd.name))
        .collect();
    let vm_vspace_names: Vec<String> = virtual_machines
        .iter()
        .map(|vm| format!("VSpace: VM={}", vm.name))
        .collect();
    vspace_names.extend(vm_vspace_names);
    let vspace_objs = init_system.allocate_objects(ObjectType::VSpace, vspace_names, None);
    let pd_vspace_objs = &vspace_objs[..system.protection_domains.len()];
    let vm_vspace_objs = &vspace_objs[system.protection_domains.len()..];

    let pd_ud_names: Vec<String> = all_pd_uds
        .iter()
        .map(|(pd_idx, vaddr)| format!("PageTable: PD={} VADDR=0x{:x}", pd_names[*pd_idx], vaddr))
        .collect();
    for pud in pd_ud_names.iter() {
        println!("PUD: {}", pud);
    }
    let vm_ud_names: Vec<String> = all_vm_uds
        .iter()
        .map(|(vm_idx, vaddr)| format!("PageTable: VM={} VADDR=0x{:x}", vm_names[*vm_idx], vaddr))
        .collect();

    let pd_ud_objs = init_system.allocate_objects(ObjectType::PageTable, pd_ud_names, None);
    let vm_ud_objs = init_system.allocate_objects(ObjectType::PageTable, vm_ud_names, None);

    if kernel_config.hypervisor {
        assert!(vm_ud_objs.is_empty());
    }

    let pd_d_names: Vec<String> = all_pd_ds
        .iter()
        .map(|(pd_idx, vaddr)| format!("PageTable: PD={} VADDR=0x{:x}", pd_names[*pd_idx], vaddr))
        .collect();
    let vm_d_names: Vec<String> = all_vm_ds
        .iter()
        .map(|(vm_idx, vaddr)| format!("PageTable: VM={} VADDR=0x{:x}", vm_names[*vm_idx], vaddr))
        .collect();
    let pd_d_objs = init_system.allocate_objects(ObjectType::PageTable, pd_d_names, None);
    let vm_d_objs = init_system.allocate_objects(ObjectType::PageTable, vm_d_names, None);

    let pd_pt_names: Vec<String> = all_pd_pts
        .iter()
        .map(|(pd_idx, vaddr)| format!("PageTable: PD={} VADDR=0x{:x}", pd_names[*pd_idx], vaddr))
        .collect();
    let vm_pt_names: Vec<String> = all_vm_pts
        .iter()
        .map(|(vm_idx, vaddr)| format!("PageTable: VM={} VADDR=0x{:x}", vm_names[*vm_idx], vaddr))
        .collect();
    let pd_pt_objs = init_system.allocate_objects(ObjectType::PageTable, pd_pt_names, None);
    let vm_pt_objs = init_system.allocate_objects(ObjectType::PageTable, vm_pt_names, None);

    let mut cnode_names: Vec<String> = system
        .protection_domains
        .iter()
        .map(|pd| format!("CNode: PD={}", pd.name))
        .collect();
    let vm_cnode_names: Vec<String> = virtual_machines
        .iter()
        .map(|vm| format!("CNode: VM={}", vm.name))
        .collect();
    cnode_names.extend(vm_cnode_names);

    let cnode_objs =
        init_system.allocate_objects(ObjectType::CNode, cnode_names, Some(PD_CAP_SIZE));
    let mut cnode_objs_by_pd: HashMap<&ProtectionDomain, &Object> =
        HashMap::with_capacity(system.protection_domains.len());
    for (i, pd) in system.protection_domains.iter().enumerate() {
        cnode_objs_by_pd.insert(pd, &cnode_objs[i]);
    }

    let mut cap_slot = init_system.cap_slot;

    let mut irq_cap_addresses: HashMap<&ProtectionDomain, Vec<u64>> = HashMap::new();
    for pd in &system.protection_domains {
        irq_cap_addresses.insert(pd, vec![]);
        for sysirq in &pd.irqs {
            let cap_address = system_cap_address_mask | cap_slot;
            system_invocations.push(Invocation::new(InvocationArgs::IrqControlGetTrigger {
                irq_control: IRQ_CONTROL_CAP_ADDRESS,
                irq: sysirq.irq,
                trigger: sysirq.trigger,
                dest_root: root_cnode_cap,
                dest_index: cap_address,
                dest_depth: kernel_config.cap_address_bits,
            }));

            cap_slot += 1;
            cap_address_names.insert(cap_address, format!("IRQ Handler: irq={}", sysirq.irq));
            irq_cap_addresses.get_mut(pd).unwrap().push(cap_address);
        }
    }

    let num_asid_invocations = system.protection_domains.len() + virtual_machines.len();
    let mut asid_invocation = Invocation::new(InvocationArgs::AsidPoolAssign {
        asid_pool: INIT_ASID_POOL_CAP_ADDRESS,
        vspace: vspace_objs[0].cap_addr,
    });
    asid_invocation.repeat(
        num_asid_invocations as u32,
        InvocationArgs::AsidPoolAssign {
            asid_pool: 0,
            vspace: 1,
        },
    );
    system_invocations.push(asid_invocation);

    let pd_page_descriptors: Vec<(u64, usize, u64, u64, u64, u64, u64)> = Vec::new();
    let vm_page_descriptors: Vec<(u64, usize, u64, u64, u64, u64, u64)> = Vec::new();

    let mut all_pd_page_tables: Vec<PGD> = vec![PGD::new(); 64];

    for i in 0..64 {
        all_pd_page_tables[i].puds[0] = Some(PUD::new());
    }
    for (pd_idx, vaddr) in &all_pd_ds {
        let d_idx = (vaddr >> 30) as usize & 0x1F;
        if let Some(pud) = &mut all_pd_page_tables[*pd_idx].puds[0] {
            pud.dirs[d_idx] = Some(DIR::new());
        }
    }

    for (pd_idx, vaddr) in &all_pd_pts {
        let d_idx = (vaddr >> 30) as usize & 0x1F;
        let pt_idx = (vaddr >> 21) as usize & 0x1F;
        if let Some(pud) = &mut all_pd_page_tables[*pd_idx].puds[0] {
            if let Some(dir) = &mut pud.dirs[d_idx] {
                dir.pts[pt_idx] = Some(PT::new());
            }
        }
    }

    let mut sorted_mp_mr_pairs: Vec<(&SysMap, &SysMemoryRegion)> = vec![];
    for pd in system.protection_domains.iter() {
        for map_set in [&pd.maps, &pd_extra_maps[pd]] {
            for mp in map_set {
                let mr = all_mr_by_name[mp.mr.as_str()];
                sorted_mp_mr_pairs.push((mp, mr));
            }
        }
    }
    sorted_mp_mr_pairs.sort_by(|a, b| a.1.name.cmp(&b.1.name));
    let base_frame_cap = BASE_FRAME_CAP;

    for (pd_idx, parent) in system.protection_domains.iter().enumerate() {
        let mut parent_pd_view: Vec<PGD> = vec![PGD::new(); 64];

        for (maybe_child_idx, maybe_child_pd) in system.protection_domains.iter().enumerate() {
            if let Some(parent_idx) = maybe_child_pd.parent {
                if parent_idx == pd_idx {
                    let id = maybe_child_pd.id.unwrap() as usize;
                    parent_pd_view[id] = all_pd_page_tables[maybe_child_idx];
                }
            }
        }

        let data_file = std::fs::File::create(format!("{}_data", parent.name)).unwrap();
        let metadata_file = std::fs::File::create(format!("{}_metadata", parent.name)).unwrap();
        let mut data_writer = std::io::BufWriter::new(data_file);
        let mut metadata_writer = std::io::BufWriter::new(metadata_file);

        let page_table_array: [u64; 64] = [u64::MAX; 64];

        for value in page_table_array {
            metadata_writer.write_all(&value.to_le_bytes()).unwrap();
        }
        metadata_writer.flush().unwrap();
        data_writer.flush().unwrap();

        let file = std::fs::File::open(format!("{}_metadata", parent.name)).unwrap();
        let mut reader = std::io::BufReader::new(file);
        let mut buffer = Vec::new();

        reader.read_to_end(&mut buffer).unwrap();
        let u64_size = 8;

        let mut u64s = Vec::with_capacity(buffer.len() / u64_size);
        for chunk in buffer.chunks(u64_size) {
            let value =
                u64::from_le_bytes(chunk.try_into().expect("Failed to convert chunk to u64"));
            u64s.push(value);
        }
    }

    let badged_irq_caps: HashMap<&ProtectionDomain, Vec<u64>> = HashMap::new();

    let badged_fault_ep = system_cap_address_mask | cap_slot;

    for vm in &virtual_machines {
        let mut parent_pd = None;
        for (pd_idx, pd) in system.protection_domains.iter().enumerate() {
            if let Some(virtual_machine) = &pd.virtual_machine {
                if virtual_machine == *vm {
                    parent_pd = Some(pd_idx);
                    break;
                }
            }
        }
        assert!(parent_pd.is_some());

        let fault_ep_cap = pd_endpoint_objs[parent_pd.unwrap()].unwrap().cap_addr;
        let badge = FAULT_BADGE | vm.vcpu.id;

        let invocation = Invocation::new(InvocationArgs::CnodeMint {
            cnode: system_cnode_cap,
            dest_index: cap_slot,
            dest_depth: system_cnode_bits,
            src_root: root_cnode_cap,
            src_obj: fault_ep_cap,
            src_depth: kernel_config.cap_address_bits,
            rights: Rights::All as u64,
            badge,
        });
        system_invocations.push(invocation);
        cap_slot += 1;
    }

    for (idx, pd) in system.protection_domains.iter().enumerate() {
        let obj = if pd.needs_ep() {
            pd_endpoint_objs[idx].unwrap()
        } else {
            &notification_objs[idx]
        };
        assert!(INPUT_CAP_IDX < PD_CAP_SIZE);

        system_invocations.push(Invocation::new(InvocationArgs::CnodeMint {
            cnode: cnode_objs[idx].cap_addr,
            dest_index: INPUT_CAP_IDX,
            dest_depth: PD_CAP_BITS,
            src_root: root_cnode_cap,
            src_obj: obj.cap_addr,
            src_depth: kernel_config.cap_address_bits,
            rights: Rights::All as u64,
            badge: 0,
        }));
    }

    assert!(REPLY_CAP_IDX < PD_CAP_SIZE);
    let mut reply_mint_invocation = Invocation::new(InvocationArgs::CnodeMint {
        cnode: cnode_objs[0].cap_addr,
        dest_index: REPLY_CAP_IDX,
        dest_depth: PD_CAP_BITS,
        src_root: root_cnode_cap,
        src_obj: pd_reply_objs[0].cap_addr,
        src_depth: kernel_config.cap_address_bits,
        rights: Rights::All as u64,
        badge: 1,
    });
    reply_mint_invocation.repeat(
        system.protection_domains.len() as u32,
        InvocationArgs::CnodeMint {
            cnode: 1,
            dest_index: 0,
            dest_depth: 0,
            src_root: 0,
            src_obj: 1,
            src_depth: 0,
            rights: 0,
            badge: 0,
        },
    );
    system_invocations.push(reply_mint_invocation);

    assert!(VSPACE_CAP_IDX < PD_CAP_SIZE);
    let num_vspace_mint_invocations = system.protection_domains.len() + virtual_machines.len();
    let mut vspace_mint_invocation = Invocation::new(InvocationArgs::CnodeMint {
        cnode: cnode_objs[0].cap_addr,
        dest_index: VSPACE_CAP_IDX,
        dest_depth: PD_CAP_BITS,
        src_root: root_cnode_cap,
        src_obj: vspace_objs[0].cap_addr,
        src_depth: kernel_config.cap_address_bits,
        rights: Rights::All as u64,
        badge: 0,
    });
    vspace_mint_invocation.repeat(
        num_vspace_mint_invocations as u32,
        InvocationArgs::CnodeMint {
            cnode: 1,
            dest_index: 0,
            dest_depth: 0,
            src_root: 0,
            src_obj: 1,
            src_depth: 0,
            rights: 0,
            badge: 0,
        },
    );
    system_invocations.push(vspace_mint_invocation);

    for (pd_idx, pd) in system.protection_domains.iter().enumerate() {
        for (sysirq, irq_cap_address) in zip(&pd.irqs, &irq_cap_addresses[pd]) {
            let cap_idx = BASE_IRQ_CAP + sysirq.id;
            assert!(cap_idx < PD_CAP_SIZE);
            system_invocations.push(Invocation::new(InvocationArgs::CnodeMint {
                cnode: cnode_objs[pd_idx].cap_addr,
                dest_index: cap_idx,
                dest_depth: PD_CAP_BITS,
                src_root: root_cnode_cap,
                src_obj: *irq_cap_address,
                src_depth: kernel_config.cap_address_bits,
                rights: Rights::All as u64,
                badge: 0,
            }));
        }
    }

    for (pd_idx, _) in system.protection_domains.iter().enumerate() {
        for (maybe_child_idx, maybe_child_pd) in system.protection_domains.iter().enumerate() {
            if let Some(parent_idx) = maybe_child_pd.parent {
                if parent_idx == pd_idx {
                    let cap_idx = BASE_PD_TCB_CAP + maybe_child_pd.id.unwrap();
                    assert!(cap_idx < PD_CAP_SIZE);
                    system_invocations.push(Invocation::new(InvocationArgs::CnodeMint {
                        cnode: cnode_objs[pd_idx].cap_addr,
                        dest_index: cap_idx,
                        dest_depth: PD_CAP_BITS,
                        src_root: root_cnode_cap,
                        src_obj: tcb_objs[maybe_child_idx].cap_addr,
                        src_depth: kernel_config.cap_address_bits,
                        rights: Rights::All as u64,
                        badge: 0,
                    }));
                }
            }
        }
    }

    for (pd_idx, pd) in system.protection_domains.iter().enumerate() {
        if let Some(vm) = &pd.virtual_machine {
            let vm_idx = virtual_machines.iter().position(|&x| x == vm).unwrap();
            let cap_idx = BASE_VM_TCB_CAP + vm.vcpu.id;
            assert!(cap_idx < PD_CAP_SIZE);
            system_invocations.push(Invocation::new(InvocationArgs::CnodeMint {
                cnode: cnode_objs[pd_idx].cap_addr,
                dest_index: cap_idx,
                dest_depth: PD_CAP_BITS,
                src_root: root_cnode_cap,
                src_obj: vm_tcb_objs[vm_idx].cap_addr,
                src_depth: kernel_config.cap_address_bits,
                rights: Rights::All as u64,
                badge: 0,
            }));
        }
    }

    for (pd_idx, pd) in system.protection_domains.iter().enumerate() {
        if let Some(vm) = &pd.virtual_machine {
            let vm_idx = virtual_machines.iter().position(|&x| x == vm).unwrap();
            let cap_idx = BASE_VCPU_CAP + vm.vcpu.id;
            assert!(cap_idx < PD_CAP_SIZE);
            system_invocations.push(Invocation::new(InvocationArgs::CnodeMint {
                cnode: cnode_objs[pd_idx].cap_addr,
                dest_index: cap_idx,
                dest_depth: PD_CAP_BITS,
                src_root: root_cnode_cap,
                src_obj: vcpu_objs[vm_idx].cap_addr,
                src_depth: kernel_config.cap_address_bits,
                rights: Rights::All as u64,
                badge: 0,
            }));
        }
    }

    for cc in &system.channels {
        let pd_a = &system.protection_domains[cc.pd_a];
        let pd_b = &system.protection_domains[cc.pd_b];
        let pd_a_cnode_obj = cnode_objs_by_pd[pd_a];
        let pd_b_cnode_obj = cnode_objs_by_pd[pd_b];
        let pd_a_notification_obj = &notification_objs[cc.pd_a];
        let pd_b_notification_obj = &notification_objs[cc.pd_b];

        let pd_a_cap_idx = BASE_OUTPUT_NOTIFICATION_CAP + cc.id_a;
        let pd_a_badge = 1 << cc.id_b;
        assert!(pd_a_cap_idx < PD_CAP_SIZE);
        system_invocations.push(Invocation::new(InvocationArgs::CnodeMint {
            cnode: pd_a_cnode_obj.cap_addr,
            dest_index: pd_a_cap_idx,
            dest_depth: PD_CAP_BITS,
            src_root: root_cnode_cap,
            src_obj: pd_b_notification_obj.cap_addr,
            src_depth: kernel_config.cap_address_bits,
            rights: Rights::All as u64, // FIXME: Check rights
            badge: pd_a_badge,
        }));

        let pd_b_cap_idx = BASE_OUTPUT_NOTIFICATION_CAP + cc.id_b;
        let pd_b_badge = 1 << cc.id_a;
        assert!(pd_b_cap_idx < PD_CAP_SIZE);
        system_invocations.push(Invocation::new(InvocationArgs::CnodeMint {
            cnode: pd_b_cnode_obj.cap_addr,
            dest_index: pd_b_cap_idx,
            dest_depth: PD_CAP_BITS,
            src_root: root_cnode_cap,
            src_obj: pd_a_notification_obj.cap_addr,
            src_depth: kernel_config.cap_address_bits,
            rights: Rights::All as u64, // FIXME: Check rights
            badge: pd_b_badge,
        }));

        if pd_b.pp {
            let pd_a_cap_idx = BASE_OUTPUT_ENDPOINT_CAP + cc.id_a;
            let pd_a_badge = PPC_BADGE | cc.id_b;
            let pd_b_endpoint_obj = pd_endpoint_objs[cc.pd_b].unwrap();
            assert!(pd_a_cap_idx < PD_CAP_SIZE);

            system_invocations.push(Invocation::new(InvocationArgs::CnodeMint {
                cnode: pd_a_cnode_obj.cap_addr,
                dest_index: pd_a_cap_idx,
                dest_depth: PD_CAP_BITS,
                src_root: root_cnode_cap,
                src_obj: pd_b_endpoint_obj.cap_addr,
                src_depth: kernel_config.cap_address_bits,
                rights: Rights::All as u64, // FIXME: Check rights
                badge: pd_a_badge,
            }));
        }

        if pd_a.pp {
            let pd_b_cap_idx = BASE_OUTPUT_ENDPOINT_CAP + cc.id_b;
            let pd_b_badge = PPC_BADGE | cc.id_a;
            let pd_a_endpoint_obj = pd_endpoint_objs[cc.pd_a].unwrap();
            assert!(pd_b_cap_idx < PD_CAP_SIZE);

            system_invocations.push(Invocation::new(InvocationArgs::CnodeMint {
                cnode: pd_b_cnode_obj.cap_addr,
                dest_index: pd_b_cap_idx,
                dest_depth: PD_CAP_BITS,
                src_root: root_cnode_cap,
                src_obj: pd_a_endpoint_obj.cap_addr,
                src_depth: kernel_config.cap_address_bits,
                rights: Rights::All as u64, // FIXME: Check rights
                badge: pd_b_badge,
            }));
        }
    }

    for (pd_idx, pd) in system.protection_domains.iter().enumerate() {
        if pd.passive {
            let cnode_obj = &cnode_objs[pd_idx];
            system_invocations.push(Invocation::new(InvocationArgs::CnodeMint {
                cnode: cnode_obj.cap_addr,
                dest_index: MONITOR_EP_CAP_IDX,
                dest_depth: PD_CAP_BITS,
                src_root: root_cnode_cap,
                src_obj: fault_ep_endpoint_object.cap_addr,
                src_depth: kernel_config.cap_address_bits,
                rights: Rights::All as u64, // FIXME: Check rights

                badge: pd_idx as u64 + 1,
            }));
        }
    }

    for pd in &system.protection_domains {
        for (irq_cap_address, badged_notification_cap_address) in
            zip(&irq_cap_addresses[pd], &badged_irq_caps[pd])
        {
            system_invocations.push(Invocation::new(InvocationArgs::IrqHandlerSetNotification {
                irq_handler: *irq_cap_address,
                notification: *badged_notification_cap_address,
            }));
        }
    }

    let pd_vspace_invocations = if kernel_config.hypervisor && kernel_config.arm_pa_size_bits == 40
    {
        vec![(all_pd_ds, pd_d_objs), (all_pd_pts, pd_pt_objs)]
    } else {
        vec![
            (all_pd_uds, pd_ud_objs),
            (all_pd_ds, pd_d_objs),
            (all_pd_pts, pd_pt_objs),
        ]
    };
    for (descriptors, objects) in pd_vspace_invocations {
        for ((pd_idx, vaddr), obj) in zip(descriptors, objects) {
            system_invocations.push(Invocation::new(InvocationArgs::PageTableMap {
                page_table: obj.cap_addr,
                vspace: pd_vspace_objs[pd_idx].cap_addr,
                vaddr,
                attr: ArmVmAttributes::default(),
            }));
        }
    }
    let vm_vspace_invocations = if kernel_config.hypervisor && kernel_config.arm_pa_size_bits == 40
    {
        vec![(all_vm_ds, vm_d_objs), (all_vm_pts, vm_pt_objs)]
    } else {
        vec![
            (all_vm_uds, vm_ud_objs),
            (all_vm_ds, vm_d_objs),
            (all_vm_pts, vm_pt_objs),
        ]
    };
    for (descriptors, objects) in vm_vspace_invocations {
        for ((vm_idx, vaddr), obj) in zip(descriptors, objects) {
            system_invocations.push(Invocation::new(InvocationArgs::PageTableMap {
                page_table: obj.cap_addr,
                vspace: vm_vspace_objs[vm_idx].cap_addr,
                vaddr,
                attr: ArmVmAttributes::default(),
            }));
        }
    }

    for (page_cap_address, pd_idx, vaddr, rights, attr, count, vaddr_incr) in pd_page_descriptors {
        let mut invocation = Invocation::new(InvocationArgs::PageMap {
            page: page_cap_address,
            vspace: pd_vspace_objs[pd_idx].cap_addr,
            vaddr,
            rights,
            attr,
        });
        invocation.repeat(
            count as u32,
            InvocationArgs::PageMap {
                page: 1,
                vspace: 0,
                vaddr: vaddr_incr,
                rights: 0,
                attr: 0,
            },
        );
        system_invocations.push(invocation);
    }
    for (page_cap_address, vm_idx, vaddr, rights, attr, count, vaddr_incr) in vm_page_descriptors {
        let mut invocation = Invocation::new(InvocationArgs::PageMap {
            page: page_cap_address,
            vspace: vm_vspace_objs[vm_idx].cap_addr,
            vaddr,
            rights,
            attr,
        });
        invocation.repeat(
            count as u32,
            InvocationArgs::PageMap {
                page: 1,
                vspace: 0,
                vaddr: vaddr_incr,
                rights: 0,
                attr: 0,
            },
        );
        system_invocations.push(invocation);
    }

    for pd_idx in 0..system.protection_domains.len() {
        let (vaddr, _) = pd_elf_files[pd_idx]
            .find_symbol(SYMBOL_IPC_BUFFER)
            .unwrap_or_else(|_| panic!("Could not find {}", SYMBOL_IPC_BUFFER));
        system_invocations.push(Invocation::new(InvocationArgs::PageMap {
            page: ipc_buffer_objs[pd_idx].cap_addr,
            vspace: pd_vspace_objs[pd_idx].cap_addr,
            vaddr,
            rights: Rights::Read as u64 | Rights::Write as u64,
            attr: ArmVmAttributes::default() | ArmVmAttributes::ExecuteNever as u64,
        }));
    }

    for (pd_idx, pd) in system.protection_domains.iter().enumerate() {
        system_invocations.push(Invocation::new(
            InvocationArgs::SchedControlConfigureFlags {
                sched_control: kernel_boot_info.sched_control_cap,
                sched_context: pd_sched_context_objs[pd_idx].cap_addr,
                budget: pd.budget,
                period: pd.period,
                extra_refills: 0,
                badge: 0x100 + pd_idx as u64,
                flags: 0,
            },
        ));
    }
    for (vm_idx, vm) in virtual_machines.iter().enumerate() {
        system_invocations.push(Invocation::new(
            InvocationArgs::SchedControlConfigureFlags {
                sched_control: kernel_boot_info.sched_control_cap,
                sched_context: vm_sched_context_objs[vm_idx].cap_addr,
                budget: vm.budget,
                period: vm.period,
                extra_refills: 0,
                badge: 0x100 + vm_idx as u64,
                flags: 0,
            },
        ));
    }

    for (pd_idx, pd) in system.protection_domains.iter().enumerate() {
        system_invocations.push(Invocation::new(InvocationArgs::TcbSetSchedParams {
            tcb: pd_tcb_objs[pd_idx].cap_addr,
            authority: INIT_TCB_CAP_ADDRESS,
            mcp: pd.priority as u64,
            priority: pd.priority as u64,
            sched_context: pd_sched_context_objs[pd_idx].cap_addr,

            fault_ep: fault_ep_endpoint_object.cap_addr,
        }));
    }
    for (vm_idx, vm) in virtual_machines.iter().enumerate() {
        system_invocations.push(Invocation::new(InvocationArgs::TcbSetSchedParams {
            tcb: vm_tcb_objs[vm_idx].cap_addr,
            authority: INIT_TCB_CAP_ADDRESS,
            mcp: vm.priority as u64,
            priority: vm.priority as u64,
            sched_context: vm_sched_context_objs[vm_idx].cap_addr,

            fault_ep: fault_ep_endpoint_object.cap_addr,
        }));
    }

    if kernel_config.benchmark {
        let mut tcb_cap_copy_invocation = Invocation::new(InvocationArgs::CnodeCopy {
            cnode: cnode_objs[0].cap_addr,
            dest_index: TCB_CAP_IDX,
            dest_depth: PD_CAP_BITS,
            src_root: root_cnode_cap,
            src_obj: pd_tcb_objs[0].cap_addr,
            src_depth: kernel_config.cap_address_bits,
            rights: Rights::All as u64,
        });
        tcb_cap_copy_invocation.repeat(
            system.protection_domains.len() as u32,
            InvocationArgs::CnodeCopy {
                cnode: 1,
                dest_index: 0,
                dest_depth: 0,
                src_root: 0,
                src_obj: 1,
                src_depth: 0,
                rights: 0,
            },
        );
        system_invocations.push(tcb_cap_copy_invocation);
    }

    let num_set_space_invocations = system.protection_domains.len() + virtual_machines.len();
    let mut set_space_invocation = Invocation::new(InvocationArgs::TcbSetSpace {
        tcb: tcb_objs[0].cap_addr,
        fault_ep: badged_fault_ep,
        cspace_root: cnode_objs[0].cap_addr,
        cspace_root_data: kernel_config.cap_address_bits - PD_CAP_BITS,
        vspace_root: vspace_objs[0].cap_addr,
        vspace_root_data: 0,
    });
    set_space_invocation.repeat(
        num_set_space_invocations as u32,
        InvocationArgs::TcbSetSpace {
            tcb: 1,
            fault_ep: 1,
            cspace_root: 1,
            cspace_root_data: 0,
            vspace_root: 1,
            vspace_root_data: 0,
        },
    );
    system_invocations.push(set_space_invocation);

    Err("to".to_string())
}

#[allow(dead_code)]
struct Args<'a> {
    system: &'a str,
    board: &'a str,
    config: &'a str,
    report: &'a str,
    output: &'a str,
    search_paths: Vec<&'a String>,
}

fn main() -> Result<(), String> {
    let exe_path = std::env::current_exe().unwrap();
    let sdk_env = std::env::var("MICROKIT_SDK");
    let sdk_dir = match sdk_env {
        Ok(ref value) => Path::new(value),
        Err(err) => match err {
            std::env::VarError::NotPresent => exe_path.parent().unwrap().parent().unwrap(),
            _ => {
                return Err(format!(
                    "Could not read MICROKIT_SDK environment variable: {}",
                    err
                ))
            }
        },
    };

    let boards_path = sdk_dir.join("board");

    let args = Args {
        system: "h",
        board: "a",
        config: "b",
        report: "a",
        output: "b",
        search_paths: vec![],
    };

    let board_path = boards_path.join(args.board);


    let elf_path = sdk_dir
        .join("board")
        .join(args.board)
        .join(args.config)
        .join("elf");
    let kernel_elf_path = elf_path.join("sel4.elf");
    let monitor_elf_path = elf_path.join("monitor.elf");

    let system_path = Path::new(args.system);
    if !system_path.exists() {
        eprintln!(
            "Error: system description file '{}' does not exist",
            system_path.display()
        );
        std::process::exit(1);
    }

    let xml: String = fs::read_to_string(args.system).unwrap();

    let kernel_config = Config {
        arch: Arch::Aarch64,
        word_size: 5,
        minimum_page_size: 4096,
        paddr_user_device_top: 5,
        kernel_frame_size: 1 << 12,
        init_cnode_bits: 5,
        cap_address_bits: 64,
        fan_out_limit: 5,
        arm_pa_size_bits: 40,
        hypervisor: true,
        benchmark: args.config == "benchmark",
    };

    let plat_desc = PlatformDescription::new(&kernel_config);
    let system = match parse(args.system, &xml, &plat_desc) {
        Ok(system) => system,
        Err(err) => {
            eprintln!("{err}");
            std::process::exit(1);
        }
    };

    let kernel_elf = ElfFile::from_path(&kernel_elf_path)?;
    let monitor_elf = ElfFile::from_path(&monitor_elf_path)?;
    let search_paths = vec![std::env::current_dir().unwrap()];
    let invocation_table_size = kernel_config.minimum_page_size;
    let system_cnode_size = 2;

    let _built_system = build_system(
        &kernel_config,
        &kernel_elf,
        &monitor_elf,
        &system,
        invocation_table_size,
        system_cnode_size,
        &search_paths,
    )?;

    Ok(())
}

#[derive(Copy, Clone)]
struct PGD {
    puds: [Option<PUD>; 512],
}

impl PGD {
    fn new() -> Self {
        PGD { puds: [None; 512] }
    }
}

#[derive(Copy, Clone)]
struct PUD {
    dirs: [Option<DIR>; 512],
}

impl PUD {
    fn new() -> Self {
        PUD { dirs: [None; 512] }
    }
}

#[derive(Copy, Clone)]
struct DIR {
    pts: [Option<PT>; 512],
}

impl DIR {
    fn new() -> Self {
        DIR { pts: [None; 512] }
    }
}

#[derive(Copy, Clone)]
struct PT {
    pages: [u64; 512],
}

impl PT {
    fn new() -> Self {
        PT {
            pages: [u64::MAX; 512],
        }
    }
}
