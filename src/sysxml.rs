//
// Copyright 2024, UNSW
//
// SPDX-License-Identifier: BSD-2-Clause
//

use std::path::PathBuf;
use crate::sel4::{PageSize, ArmIrqTrigger, Config};

///
/// This module is responsible for parsing the System Description Format (SDF)
/// which is based on XML.
/// We do not use any fancy XML, and instead keep things as minimal and simple
/// as possible.
///
/// As much as possible of the validation of the SDF is done when parsing the XML
/// here.
///
/// There are various XML parsing/deserialising libraries within the Rust eco-system
/// but few seem to be concerned with giving any introspection regarding the parsed
/// XML. The roxmltree project allows us to work on a lower-level than something based
/// on serde and so we can report proper user errors.
///

/// Events that come through entry points (e.g notified or protected) are given an
/// identifier that is used as the badge at runtime.
/// On 64-bit platforms, this badge has a limit of 64-bits which means that we are
/// limited in how many IDs a Microkit protection domain has since each ID represents
/// a unique bit.
/// Currently the first bit is used to determine whether or not the event is a PPC
/// or notification. The second bit is used to determine whether a fault occurred.
/// This means we are left with 62 bits for the ID.
/// IDs start at zero.

/// There are some platform-specific properties that must be known when parsing the
/// SDF for error-checking and validation, these go in this struct.
pub struct PlatformDescription {
}

impl PlatformDescription {
    pub const fn new(_: &Config) -> PlatformDescription {
        PlatformDescription {
        }
    }
}

#[repr(u8)]
pub enum SysMapPerms {
    Read = 1,
    Write = 2,
    Execute = 4,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct SysMap {
    pub mr: String,
    pub vaddr: u64,
    pub perms: u8,
    pub cached: bool,
}

#[derive(Debug, PartialEq, Eq, Hash, Clone)]
pub struct SysMemoryRegion {
    pub name: String,
    pub size: u64,
    pub page_size: PageSize,
    pub page_count: u64,
    pub phys_addr: Option<u64>,
}

impl SysMemoryRegion {
    pub fn page_bytes(&self) -> u64 {
        self.page_size as u64
    }
}

#[derive(Debug, PartialEq, Eq, Hash)]
pub struct SysIrq {
    pub irq: u64,
    pub id: u64,
    pub trigger: ArmIrqTrigger,
}

// The use of SysSetVar depends on the context. In some
// cases it will contain a symbol and a physical or a
// symbol and vaddr. Never both.
#[derive(Debug, PartialEq, Eq, Hash)]
pub struct SysSetVar {
    pub symbol: String,
    pub region_paddr: Option<String>,
    pub vaddr: Option<u64>,
}

#[derive(Debug)]
pub struct Channel {
    pub pd_a: usize,
    pub id_a: u64,
    pub pd_b: usize,
    pub id_b: u64,
}

#[derive(Debug, PartialEq, Eq, Hash)]
pub struct ProtectionDomain {
    /// Only populated for child protection domains
    pub id: Option<u64>,
    pub name: String,
    pub priority: u8,
    pub budget: u64,
    pub period: u64,
    pub pp: bool,
    pub passive: bool,
    pub program_image: PathBuf,
    pub maps: Vec<SysMap>,
    pub irqs: Vec<SysIrq>,
    pub setvars: Vec<SysSetVar>,
    pub virtual_machine: Option<VirtualMachine>,
    /// Only used when parsing child PDs. All elements will be removed
    /// once we flatten each PD and its children into one list.
    pub child_pds: Vec<ProtectionDomain>,
    pub has_children: bool,
    /// Index into the total list of protection domains if a parent
    /// protection domain exists
    pub parent: Option<usize>,
}

#[derive(Debug, PartialEq, Eq, Hash)]
pub struct VirtualMachine {
    // Right now virtual machines are limited to a single vCPU
    pub vcpu: VirtualCpu,
    pub name: String,
    pub maps: Vec<SysMap>,
    pub priority: u8,
    pub budget: u64,
    pub period: u64,
}

#[derive(Debug, PartialEq, Eq, Hash)]
pub struct VirtualCpu {
    pub id: u64,
}

impl ProtectionDomain {
    pub fn needs_ep(&self) -> bool {
        self.pp || self.has_children || self.virtual_machine.is_some()
    }
}

#[derive(Debug)]
pub struct SystemDescription {
    pub protection_domains: Vec<ProtectionDomain>,
    pub memory_regions: Vec<SysMemoryRegion>,
    pub channels: Vec<Channel>,
}

pub fn parse(_: &str, _: &str, _: &PlatformDescription) -> Result<SystemDescription, String> {
    Ok(SystemDescription {
        protection_domains: vec![],
        memory_regions: vec![],
        channels: vec![],
    })
}
