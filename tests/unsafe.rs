// Integration and verification tests for unsafe code paths
// These tests verify that unsafe operations work correctly in realistic scenarios
// and use various techniques to verify the safety of unsafe code:
// - Explicit invariant checking
// - Memory safety validation
// - Edge case testing

use std::io::Write;
use tos_tbpf::{
    aligned_memory::AlignedMemory,
    memory_region::{MemoryMapping, MemoryRegion},
    program::TBPFVersion,
    vm::Config,
};

/// Test aligned memory operations with various patterns
#[test]
fn test_aligned_memory_comprehensive() {
    // Test writing and reading various data patterns
    let patterns = vec![
        vec![0x00; 1000],                                            // All zeros
        vec![0xFF; 1000],                                            // All ones
        (0usize..1000).map(|i| (i % 256) as u8).collect::<Vec<_>>(), // Sequential
        vec![0xAA; 1000],                                            // Alternating pattern
    ];

    for pattern in patterns {
        let mut mem = AlignedMemory::<64>::with_capacity(pattern.len());

        // Write pattern
        mem.write_all(&pattern).expect("Write should succeed");

        // Verify read-back
        assert_eq!(mem.as_slice(), &pattern[..], "Pattern mismatch");

        // Verify length
        assert_eq!(mem.len(), pattern.len(), "Length mismatch");
    }
}

/// Test memory region boundary conditions
#[test]
fn test_memory_region_boundaries() {
    let data = vec![0xAB; 1000];
    let vm_addr = 0x1000;
    let region = MemoryRegion::new_readonly(&data, vm_addr);

    // Test boundary addresses
    let start = region.vm_addr_range().start;
    let end = region.vm_addr_range().end;

    assert_eq!(start, vm_addr, "Start address mismatch");
    assert_eq!(end, vm_addr + 1000, "End address mismatch");

    // Test that range contains expected addresses
    assert!(
        region.vm_addr_range().contains(&vm_addr),
        "Should contain start"
    );
    assert!(
        region.vm_addr_range().contains(&(vm_addr + 500)),
        "Should contain middle"
    );
    assert!(
        !region.vm_addr_range().contains(&(vm_addr + 1000)),
        "Should not contain end (exclusive)"
    );
}

/// Test write-read roundtrip for aligned memory
#[test]
fn test_aligned_memory_roundtrip() {
    const SIZE: usize = 4096;
    let mut mem = AlignedMemory::<128>::with_capacity(SIZE);

    // Write test data
    let test_data: Vec<u8> = (0usize..SIZE).map(|i| (i % 256) as u8).collect();
    mem.write_all(&test_data).expect("Write failed");

    // Read back and verify
    let read_back = mem.as_slice();
    assert_eq!(
        read_back.len(),
        test_data.len(),
        "Length mismatch after roundtrip"
    );

    for (i, (&expected, &actual)) in test_data.iter().zip(read_back.iter()).enumerate() {
        assert_eq!(expected, actual, "Mismatch at offset {i}");
    }
}

/// Test that fill_write correctly fills memory
#[test]
fn test_fill_write_correctness() {
    let mut mem = AlignedMemory::<32>::with_capacity(1000);

    // Fill with pattern
    let fill_value = 0x42;
    mem.fill_write(1000, fill_value).expect("fill_write failed");

    // Verify all bytes are set
    for (i, &byte) in mem.as_slice().iter().enumerate() {
        assert_eq!(byte, fill_value, "Byte at offset {i} not filled correctly");
    }
}

/// Test multiple memory regions with different properties
#[test]
fn test_multiple_memory_regions() {
    // Create readonly region
    let readonly_data = vec![1u8; 100];
    let readonly_region = MemoryRegion::new_readonly(&readonly_data, 0x1000);

    // Create writable region
    let mut writable_data = vec![2u8; 100];
    let writable_region = MemoryRegion::new_writable(&mut writable_data, 0x2000);

    // Verify readonly properties
    assert!(
        !readonly_region.writable,
        "Readonly region should not be writable"
    );
    assert_eq!(readonly_region.len, 100);
    assert_eq!(readonly_region.vm_addr, 0x1000);

    // Verify writable properties
    assert!(
        writable_region.writable,
        "Writable region should be writable"
    );
    assert_eq!(writable_region.len, 100);
    assert_eq!(writable_region.vm_addr, 0x2000);

    // Verify ranges don't overlap
    let readonly_range = readonly_region.vm_addr_range();
    let writable_range = writable_region.vm_addr_range();
    assert!(
        !readonly_range.contains(&writable_range.start),
        "Ranges should not overlap"
    );
    assert!(
        !writable_range.contains(&readonly_range.start),
        "Ranges should not overlap"
    );
}

/// Test aligned memory with various alignment values
#[test]
fn test_various_alignments() {
    // Test different alignment values
    let alignments = [8, 16, 32, 64, 128, 256];

    for &size in &[100, 500, 1000, 5000] {
        for &_alignment in &alignments {
            // Note: The alignment is part of the type, so we test each separately
            let mut mem_8 = AlignedMemory::<8>::with_capacity(size);
            let mut mem_16 = AlignedMemory::<16>::with_capacity(size);
            let mut mem_32 = AlignedMemory::<32>::with_capacity(size);
            let mut mem_64 = AlignedMemory::<64>::with_capacity(size);
            let mut mem_128 = AlignedMemory::<128>::with_capacity(size);

            // Write test pattern
            let pattern: Vec<u8> = (0usize..size).map(|i| (i % 256) as u8).collect();

            mem_8.write_all(&pattern).expect("Write failed");
            mem_16.write_all(&pattern).expect("Write failed");
            mem_32.write_all(&pattern).expect("Write failed");
            mem_64.write_all(&pattern).expect("Write failed");
            mem_128.write_all(&pattern).expect("Write failed");

            // Verify all alignments work correctly
            assert_eq!(mem_8.as_slice(), &pattern[..]);
            assert_eq!(mem_16.as_slice(), &pattern[..]);
            assert_eq!(mem_32.as_slice(), &pattern[..]);
            assert_eq!(mem_64.as_slice(), &pattern[..]);
            assert_eq!(mem_128.as_slice(), &pattern[..]);
        }
    }
}

/// Test memory region with edge case addresses
#[test]
fn test_memory_region_edge_cases() {
    let data = vec![0; 1];

    // Test with address 0
    let region_zero = MemoryRegion::new_readonly(&data, 0);
    assert_eq!(region_zero.vm_addr, 0);
    assert_eq!(region_zero.len, 1);

    // Test with maximum reasonable address
    let max_addr = u64::MAX - 1000;
    let region_max = MemoryRegion::new_readonly(&data, max_addr);
    assert_eq!(region_max.vm_addr, max_addr);
    assert_eq!(region_max.len, 1);
}

/// Test concurrent writes to aligned memory (single-threaded but sequential)
#[test]
fn test_sequential_writes() {
    let mut mem = AlignedMemory::<64>::with_capacity(3000);

    // Write in chunks
    let chunk1: Vec<u8> = (0usize..1000).map(|i| (i % 256) as u8).collect();
    let chunk2: Vec<u8> = (0usize..1000).map(|i| ((i + 100) % 256) as u8).collect();
    let chunk3: Vec<u8> = (0usize..1000).map(|i| ((i + 200) % 256) as u8).collect();

    mem.write_all(&chunk1).expect("Chunk 1 write failed");
    mem.write_all(&chunk2).expect("Chunk 2 write failed");
    mem.write_all(&chunk3).expect("Chunk 3 write failed");

    // Verify all chunks
    let slice = mem.as_slice();
    assert_eq!(&slice[0..1000], &chunk1[..]);
    assert_eq!(&slice[1000..2000], &chunk2[..]);
    assert_eq!(&slice[2000..3000], &chunk3[..]);
}

/// Test that memory regions correctly report their length
#[test]
fn test_memory_region_length_invariant() {
    for len in [1, 10, 100, 1000, 10000] {
        let data = vec![0u8; len];
        let region = MemoryRegion::new_readonly(&data, 0x1000);

        assert_eq!(region.len, len as u64, "Length should match data size");
        assert_eq!(
            region.vm_addr_range().end - region.vm_addr_range().start,
            len as u64,
            "Address range should match length"
        );
    }
}

// ============================================================================
// Verification tests for unsafe code blocks
// ============================================================================

/// Test memory region find_region with various addresses
#[test]
fn test_memory_region_find_region_invariants() {
    let config = Config {
        aligned_memory_mapping: false,
        ..Config::default()
    };
    let tbpf_version = TBPFVersion::V3; // V3 uses unaligned mapping

    let region1 = MemoryRegion::new_readonly(&[0u8; 100], 0x1000);
    let region2 = MemoryRegion::new_readonly(&[0u8; 200], 0x2000);
    let region3 = MemoryRegion::new_readonly(&[0u8; 300], 0x3000);

    let mapping =
        MemoryMapping::new(vec![region1, region2, region3], &config, tbpf_version).unwrap();

    // Test: Valid addresses should be found
    assert!(mapping.find_region(0x1000).is_some());
    assert!(mapping.find_region(0x1050).is_some());
    assert!(mapping.find_region(0x2000).is_some());
    assert!(mapping.find_region(0x3000).is_some());

    // Test: Invalid addresses should not be found
    assert!(mapping.find_region(0x0000).is_none());
    assert!(mapping.find_region(0x0FFF).is_none()); // Just before region1

    // Test: Boundary conditions
    assert!(mapping.find_region(0x1063).is_some()); // Last byte of region1 (0x1000 + 100 - 1)
    assert!(mapping.find_region(0x10C7).is_some()); // Last byte of region2 (0x2000 + 200 - 1)
    assert!(mapping.find_region(0x312B).is_some()); // Last byte of region3 (0x3000 + 300 - 1)
}

/// Test that AlignedMemory operations maintain invariants
#[test]
fn test_aligned_memory_basic_operations() {
    let mut mem = AlignedMemory::<8>::with_capacity(32);

    // Test write operations
    unsafe {
        mem.write_unchecked::<u8>(1);
        mem.write_unchecked::<u16>(2);
        mem.write_unchecked::<u32>(3);
        mem.write_unchecked::<u64>(4);
    }

    // Verify length
    assert_eq!(mem.len(), 1 + 2 + 4 + 8);

    // Test write_all
    unsafe {
        mem.write_all_unchecked(b"test");
    }

    assert_eq!(mem.len(), 1 + 2 + 4 + 8 + 4);
}

/// Test that AlignedMemory detects overflows in debug mode
#[test]
#[should_panic]
#[cfg(debug_assertions)]
fn test_aligned_memory_write_unchecked_overflow() {
    let mut mem = AlignedMemory::<8>::with_capacity(8);

    unsafe {
        mem.write_unchecked::<u64>(42);
        // This should trigger assertion in debug mode
        mem.write_unchecked::<u64>(24);
    }
}

/// Test that AlignedMemory write_all detects overflows
#[test]
#[should_panic]
#[cfg(debug_assertions)]
fn test_aligned_memory_write_all_overflow() {
    let mut mem = AlignedMemory::<8>::with_capacity(5);

    unsafe {
        mem.write_all_unchecked(b"hello");
        // This should trigger assertion
        mem.write_all_unchecked(b"world");
    }
}

/// Test AlignedMemory with zero-filled memory
#[test]
fn test_aligned_memory_zero_filled() {
    let mem = AlignedMemory::<8>::zero_filled(100);
    assert_eq!(mem.len(), 100);
    assert_eq!(mem.as_slice(), &[0u8; 100]);
}

/// Test AlignedMemory fill_write operation
#[test]
fn test_aligned_memory_fill_write() {
    let mut mem = AlignedMemory::<8>::with_capacity_zeroed(20);

    mem.fill_write(5, 0).unwrap();
    mem.fill_write(3, 1).unwrap();
    mem.fill_write(2, 2).unwrap();

    let expected = [0, 0, 0, 0, 0, 1, 1, 1, 2, 2];
    assert_eq!(mem.as_slice(), &expected);
}

/// Test memory mapping with multiple regions
#[test]
fn test_memory_mapping_multiple_regions() {
    let config = Config {
        aligned_memory_mapping: false,
        ..Config::default()
    };
    let tbpf_version = TBPFVersion::V3;

    // Create several memory regions
    let regions = vec![
        MemoryRegion::new_readonly(&[1u8; 50], 0x1000),
        MemoryRegion::new_readonly(&[2u8; 100], 0x2000),
        MemoryRegion::new_readonly(&[3u8; 150], 0x3000),
        MemoryRegion::new_readonly(&[4u8; 200], 0x4000),
    ];

    let mapping = MemoryMapping::new(regions, &config, tbpf_version).unwrap();

    // Test finding each region
    for (base_addr, expected_idx) in [(0x1000, 0), (0x2000, 1), (0x3000, 2), (0x4000, 3)] {
        let result = mapping.find_region(base_addr);
        assert!(result.is_some(), "Should find region at {:#x}", base_addr);
        let (idx, _) = result.unwrap();
        assert_eq!(idx, expected_idx);
    }
}

/// Test memory mapping caching behavior
#[test]
fn test_memory_mapping_cache() {
    let config = Config {
        aligned_memory_mapping: false,
        ..Config::default()
    };
    let tbpf_version = TBPFVersion::V3;

    let region = MemoryRegion::new_readonly(&[0u8; 1000], 0x1000);
    let mapping = MemoryMapping::new(vec![region], &config, tbpf_version).unwrap();

    // Access the same address multiple times (tests caching)
    for _ in 0..10 {
        let result = mapping.find_region(0x1200);
        assert!(result.is_some());
    }
}

/// Test aligned memory alignment guarantees
#[test]
fn test_aligned_memory_alignment() {
    let mem = AlignedMemory::<32>::with_capacity(100);
    let ptr = mem.as_slice().as_ptr() as usize;
    assert_eq!(ptr % 32, 0, "Memory should be aligned to 32 bytes");

    let mem = AlignedMemory::<4096>::with_capacity(100);
    let ptr = mem.as_slice().as_ptr() as usize;
    assert_eq!(ptr % 4096, 0, "Memory should be aligned to 4096 bytes");
}

/// Test AlignedMemory capacity limits
#[test]
fn test_aligned_memory_capacity_limits() {
    let mut mem = AlignedMemory::<8>::with_capacity(10);

    // Should succeed
    let result = mem.write(&[1, 2, 3, 4, 5]);
    assert!(result.is_ok());

    // Should succeed
    let result = mem.write(&[6, 7, 8, 9, 10]);
    assert!(result.is_ok());

    // Should fail - exceeds capacity
    let result = mem.write(&[11]);
    assert!(result.is_err());
}

/// Test memory region with writable regions
#[test]
fn test_memory_region_writable() {
    let config = Config {
        aligned_memory_mapping: false,
        ..Config::default()
    };
    let tbpf_version = TBPFVersion::V3;

    let mut data = vec![0u8; 100];
    let region = MemoryRegion::new_writable(data.as_mut_slice(), 0x1000);

    let mapping = MemoryMapping::new(vec![region], &config, tbpf_version).unwrap();

    let result = mapping.find_region(0x1050);
    assert!(result.is_some());
}

/// Test AlignedMemory clone maintains alignment
#[test]
fn test_aligned_memory_clone() {
    let mut mem = AlignedMemory::<64>::with_capacity(100);
    mem.write_all(b"hello world").unwrap();

    let cloned = mem.clone();

    // Check alignment of clone
    let ptr = cloned.as_slice().as_ptr() as usize;
    assert_eq!(ptr % 64, 0, "Cloned memory should maintain alignment");

    // Check content
    assert_eq!(cloned.as_slice(), b"hello world");
}

/// Test memory mapping with empty regions list
#[test]
fn test_memory_mapping_empty() {
    let config = Config::default();
    let tbpf_version = TBPFVersion::V3;

    let result = MemoryMapping::new(vec![], &config, tbpf_version);
    // Should fail or succeed depending on implementation
    // Just verify it doesn't panic
    let _ = result;
}

/// Test that debug assertions are enabled in debug builds
#[test]
#[cfg(debug_assertions)]
fn test_debug_assertions_enabled() {
    let result = std::panic::catch_unwind(|| {
        let mut mem = AlignedMemory::<8>::with_capacity(1);
        unsafe {
            mem.write_unchecked::<u64>(1);
            mem.write_unchecked::<u64>(2); // Should panic
        }
    });

    assert!(result.is_err(), "Debug assertions should be enabled");
}

/// Test overall memory safety integration
#[test]
fn test_overall_memory_safety() {
    // This test combines several unsafe operations to ensure they work together safely
    let config = Config {
        aligned_memory_mapping: false,
        ..Config::default()
    };
    let tbpf_version = TBPFVersion::V3;

    // Create aligned memory
    let mut aligned_mem = AlignedMemory::<32>::with_capacity(1024);
    aligned_mem.write_all(b"test data").unwrap();

    // Create memory regions
    let region1 = MemoryRegion::new_readonly(aligned_mem.as_slice(), 0x1000);
    let region2 = MemoryRegion::new_readonly(&[0u8; 512], 0x2000);

    // Create memory mapping
    let mapping = MemoryMapping::new(vec![region1, region2], &config, tbpf_version).unwrap();

    // Access regions
    assert!(mapping.find_region(0x1000).is_some());
    assert!(mapping.find_region(0x1005).is_some()); // Within region1
    assert!(mapping.find_region(0x2000).is_some());
    assert!(mapping.find_region(0x2100).is_some()); // Within region2
    assert!(mapping.find_region(0x0FFF).is_none()); // Before any region
}

/// Benchmark-style test to ensure safety checks don't have excessive overhead
#[test]
fn test_safety_checks_performance() {
    use std::time::Instant;

    let iterations = 10_000;

    let start = Instant::now();
    for _ in 0..iterations {
        let mut mem = AlignedMemory::<8>::with_capacity(1024);
        unsafe {
            for i in 0..100 {
                mem.write_unchecked::<u64>(i);
            }
        }
    }
    let duration = start.elapsed();

    // Ensure reasonable performance (adjust threshold as needed)
    assert!(
        duration.as_secs() < 10,
        "Safety checks causing excessive overhead: {:?}",
        duration
    );
}

#[test]
fn test_safety_documentation_reminder() {
    // Reminder to maintain safety documentation
    // Run: cargo clippy -- -W clippy::missing-safety-doc
    println!("Reminder: Ensure all unsafe functions have '# Safety' documentation");
    println!("Run: cargo clippy -- -W clippy::missing-safety-doc");
}

// Memory management tests - only available with JIT feature on supported platforms
#[cfg(all(feature = "jit", not(target_os = "windows"), target_arch = "x86_64"))]
mod jit_memory_tests {
    #[test]
    fn test_page_size_is_valid() {
        use tos_tbpf::memory_management::get_system_page_size;

        let page_size = get_system_page_size();
        assert!(page_size > 0, "Page size should be positive");
        assert!(
            page_size.is_power_of_two(),
            "Page size should be power of two"
        );
        assert!(page_size >= 4096, "Page size should be at least 4KB");
    }

    #[test]
    fn test_allocate_and_free_pages() {
        use tos_tbpf::memory_management::{allocate_pages, free_pages, get_system_page_size};

        let page_size = get_system_page_size();

        unsafe {
            // Allocate pages
            let result = allocate_pages(page_size * 2);
            assert!(result.is_ok(), "Should allocate pages successfully");

            let ptr = result.unwrap();
            assert!(!ptr.is_null(), "Allocated pointer should not be null");
            assert_eq!(
                ptr as usize % page_size,
                0,
                "Allocated memory should be page-aligned"
            );

            // Free pages
            let free_result = free_pages(ptr, page_size * 2);
            assert!(free_result.is_ok(), "Should free pages successfully");
        }
    }

    #[test]
    fn test_protect_pages() {
        use tos_tbpf::memory_management::{
            allocate_pages, free_pages, get_system_page_size, protect_pages,
        };

        let page_size = get_system_page_size();

        unsafe {
            let ptr = allocate_pages(page_size).unwrap();

            // Make read-only
            let result = protect_pages(ptr, page_size, false);
            assert!(result.is_ok(), "Should protect pages as read-only");

            // Make executable (read+exec)
            let result = protect_pages(ptr, page_size, true);
            assert!(result.is_ok(), "Should protect pages as executable");

            free_pages(ptr, page_size).unwrap();
        }
    }

    #[test]
    fn test_round_to_page_size() {
        use tos_tbpf::memory_management::{get_system_page_size, round_to_page_size};

        let page_size = get_system_page_size();

        // Test various values
        assert_eq!(round_to_page_size(0, page_size), 0);
        assert_eq!(round_to_page_size(1, page_size), page_size);
        assert_eq!(round_to_page_size(page_size, page_size), page_size);
        assert_eq!(round_to_page_size(page_size + 1, page_size), page_size * 2);
    }
}
