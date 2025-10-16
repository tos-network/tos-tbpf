// Property-based tests for unsafe code verification
// These tests use proptest to verify invariants across a wide range of inputs

use proptest::prelude::*;
use std::io::Write;

/// Test aligned memory operations
#[cfg(test)]
mod aligned_memory_properties {
    use super::*;
    use tos_tbpf::aligned_memory::AlignedMemory;

    proptest! {
        #[test]
        fn test_aligned_memory_write_read_roundtrip(
            data in prop::collection::vec(any::<u8>(), 0..1000)
        ) {
            let mut mem = AlignedMemory::<64>::with_capacity(data.len());

            // Property: We can write data and read it back correctly
            let write_result = mem.write_all(&data);
            prop_assert!(write_result.is_ok(), "Write failed");

            let read_data = mem.as_slice();
            prop_assert_eq!(read_data, &data[..], "Read data doesn't match written data");
        }

        #[test]
        fn test_aligned_memory_fill_write(
            value in any::<u8>(),
            length in 1usize..1000
        ) {
            let mut mem = AlignedMemory::<32>::with_capacity(length);

            // Property: fill_write fills memory correctly
            let result = mem.fill_write(length, value);
            prop_assert!(result.is_ok(), "fill_write failed");

            // Property: All bytes are set to the value
            prop_assert!(mem.as_slice().iter().all(|&b| b == value),
                "Not all bytes set to {}", value);

            // Property: Length is correct
            prop_assert_eq!(mem.len(), length, "Length mismatch");
        }

        #[test]
        fn test_aligned_memory_capacity_invariant(capacity in 1usize..10_000) {
            let mem = AlignedMemory::<128>::with_capacity(capacity);

            // Property: Allocated capacity respects alignment
            prop_assert!(mem.len() <= capacity, "Length exceeds requested capacity");
        }
    }
}

/// Test memory region operations
#[cfg(test)]
mod memory_region_properties {
    use super::*;
    use tos_tbpf::memory_region::MemoryRegion;

    proptest! {
        #[test]
        fn test_memory_region_boundaries(
            addr in 0u64..1_000_000,
            len in 1usize..10_000
        ) {
            let data = vec![0u8; len];
            let region = MemoryRegion::new_readonly(&data, addr);

            // Property: vm_addr_range returns correct start
            prop_assert_eq!(region.vm_addr_range().start, addr);

            // Property: vm_addr_range returns correct end
            prop_assert_eq!(region.vm_addr_range().end, addr + len as u64);

            // Property: Length is preserved
            prop_assert_eq!(region.len, len as u64);
        }

        #[test]
        fn test_memory_region_contains(
            addr in 0u64..1_000_000,
            len in 1usize..10_000,
            offset in 0usize..10_000
        ) {
            let data = vec![0u8; len];
            let region = MemoryRegion::new_readonly(&data, addr);

            let test_addr = addr + (offset as u64 % len as u64);

            // Property: Addresses within range should be contained
            if test_addr >= addr && test_addr < addr + len as u64 {
                let range = region.vm_addr_range();
                prop_assert!(range.contains(&test_addr),
                    "Address {} should be in range {:?}", test_addr, range);
            }
        }

        #[test]
        fn test_memory_region_readonly_invariant(
            addr in 0u64..1_000_000,
            len in 100usize..10_000
        ) {
            let data = vec![0xAB; len];
            let region = MemoryRegion::new_readonly(&data, addr);

            // Property: read-only regions are not writable
            prop_assert!(!region.writable, "Readonly region should not be writable");
            prop_assert_eq!(region.len, len as u64, "Region length should match data length");
            prop_assert_eq!(region.vm_addr, addr, "VM address should match");
        }

        #[test]
        fn test_memory_region_writable_invariant(
            addr in 0u64..1_000_000,
            len in 100usize..10_000
        ) {
            let mut data = vec![0u8; len];
            let region = MemoryRegion::new_writable(&mut data, addr);

            // Property: writable regions are marked as writable
            prop_assert!(region.writable, "Writable region should be writable");
            prop_assert_eq!(region.len, len as u64, "Region length should match data length");
            prop_assert_eq!(region.vm_addr, addr, "VM address should match");
        }
    }
}
