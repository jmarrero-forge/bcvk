//! Common CLI options shared across commands

use clap::Parser;
use serde::{Deserialize, Serialize};
use std::fmt;

pub const DEFAULT_MEMORY_USER_STR: &str = "4G";

/// Memory size options
#[derive(Parser, Debug, Clone, Default, Serialize, Deserialize)]
pub struct MemoryOpts {
    #[clap(
        long,
        default_value = DEFAULT_MEMORY_USER_STR,
        help = "Memory size (e.g. 4G, 2048M, or plain number for MB)"
    )]
    pub memory: String,
}

impl fmt::Display for MemoryOpts {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.memory)
    }
}

/// Get default vCPU count (number of available processors, or 2 as fallback)
pub fn default_vcpus() -> u32 {
    std::thread::available_parallelism()
        .map(|n| n.get() as u32)
        .unwrap_or(2)
}

/// CPU and memory sizing options shared by the ephemeral VM backends
#[derive(Parser, Debug, Clone, Default, Serialize, Deserialize)]
pub struct VmSizeOpts {
    #[clap(
        long,
        help = "Instance type (e.g., u1.nano, u1.small, u1.medium). Overrides vcpus/memory if specified."
    )]
    pub itype: Option<crate::instancetypes::InstanceType>,

    #[clap(flatten)]
    pub memory: MemoryOpts,

    #[clap(long, help = "Number of vCPUs (overridden by --itype if specified)")]
    pub vcpus: Option<u32>,
}

impl VmSizeOpts {
    /// Parse memory specification to MB, using instancetype if specified
    pub fn memory_mb(&self) -> color_eyre::Result<u32> {
        match self.itype {
            Some(itype) => Ok(itype.memory_mb()),
            None => crate::utils::parse_memory_to_mb(&self.memory.memory),
        }
    }

    /// Get vCPU count, using instancetype if specified, else all host CPUs
    pub fn vcpus(&self) -> u32 {
        self.vcpus_or_else(default_vcpus)
    }

    /// Get vCPU count, using instancetype if specified, else `default`
    #[cfg_attr(not(target_os = "macos"), allow(dead_code))]
    pub fn vcpus_or(&self, default: u32) -> u32 {
        self.vcpus_or_else(|| default)
    }

    fn vcpus_or_else(&self, default: impl FnOnce() -> u32) -> u32 {
        match self.itype {
            Some(itype) => itype.vcpus(),
            None => self.vcpus.unwrap_or_else(default),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::instancetypes::InstanceType;

    #[test]
    fn test_vm_size_opts() {
        let mem = |m: &str| MemoryOpts { memory: m.into() };
        for (opts, memory_mb, vcpus) in [
            (
                VmSizeOpts {
                    itype: None,
                    memory: mem("2G"),
                    vcpus: Some(3),
                },
                2048,
                3,
            ),
            (
                VmSizeOpts {
                    itype: Some(InstanceType::U1Small),
                    memory: mem("8G"),
                    vcpus: Some(7),
                },
                InstanceType::U1Small.memory_mb(),
                InstanceType::U1Small.vcpus(),
            ),
        ] {
            assert_eq!(opts.memory_mb().unwrap(), memory_mb, "{opts:?}");
            assert_eq!(opts.vcpus(), vcpus, "{opts:?}");
        }
        let unset = VmSizeOpts {
            memory: mem("1G"),
            ..Default::default()
        };
        assert_eq!(unset.vcpus(), default_vcpus());
        assert_eq!(unset.vcpus_or(2), 2);
        assert!(default_vcpus() >= 1);
    }
}
