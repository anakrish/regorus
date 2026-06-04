#![deny(clippy::indexing_slicing)]

// Minimal crate to show clippy::indexing_slicing behavior.
fn indexing_panics() -> i32 {
    let values = vec![1, 2, 3];
    values[1]
}

#[allow(clippy::indexing_slicing)]
fn indexing_allowed() -> i32 {
    let values = vec![1, 2, 3];
    values[1]
}

fn safe_access() -> Option<i32> {
    let values = vec![1, 2, 3];
    values.get(1).copied()
}

fn main() {
    // Comment out the next line to let the crate pass clippy without errors.
    let _ = indexing_panics();
    let _ = indexing_allowed();
    let _ = safe_access();
}
