use std::{
    alloc::{GlobalAlloc, Layout, System},
    sync::atomic::{AtomicUsize, Ordering},
};

use maya_scene_kit_edit::scene::stage_remove_script_nodes;
use maya_scene_kit_observe::scene::{LoadOptions, Loader};

struct CountingAllocator;

static MIN_SIZE: AtomicUsize = AtomicUsize::new(usize::MAX);
static SOURCE_SIZED_ALLOCATIONS: AtomicUsize = AtomicUsize::new(0);

fn record(size: usize) {
    if size >= MIN_SIZE.load(Ordering::Relaxed) {
        SOURCE_SIZED_ALLOCATIONS.fetch_add(1, Ordering::Relaxed);
    }
}

unsafe impl GlobalAlloc for CountingAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        record(layout.size());
        unsafe { System.alloc(layout) }
    }

    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        record(layout.size());
        unsafe { System.alloc_zeroed(layout) }
    }

    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, size: usize) -> *mut u8 {
        record(size);
        unsafe { System.realloc(ptr, layout, size) }
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        unsafe { System.dealloc(ptr, layout) }
    }
}

#[global_allocator]
static ALLOCATOR: CountingAllocator = CountingAllocator;

#[test]
fn native_script_clean_allocates_only_source_and_output_buffers() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("Example.ma");
    std::fs::write(&path, b"//Maya ASCII 2026 scene\n").unwrap();
    Loader::new(LoadOptions::default())
        .observe_execution_path(&path)
        .unwrap();

    let mut input = b"//Maya ASCII 2026 scene\n// Example ".to_vec();
    input.resize(32 * 1024 * 1024, b' ');
    input.push(b'\n');
    let kept_len = input.len();
    input.extend_from_slice(b"createNode script -n \"ExampleScript\";\n    setAttr \".b\" -type \"string\" \"print(1);\";\n");
    std::fs::write(&path, &input).unwrap();

    SOURCE_SIZED_ALLOCATIONS.store(0, Ordering::Relaxed);
    MIN_SIZE.store(input.len(), Ordering::Relaxed);
    let staged = stage_remove_script_nodes(&path);
    MIN_SIZE.store(usize::MAX, Ordering::Relaxed);
    let allocations = SOURCE_SIZED_ALLOCATIONS.load(Ordering::Relaxed);

    let staged = staged.unwrap();
    assert_eq!(staged.artifact.bytes, input[..kept_len]);
    assert_eq!(staged.preview.removed_nodes, ["ExampleScript"]);
    assert!(allocations <= 2, "source-sized allocations: {allocations}");
}
