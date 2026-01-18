from pathlib import Path

from zkvm_fuzzer_utils.file import create_file

# ---------------------------------------------------------------------------- #
#                           Fuzzer Util Crate Creator                          #
# ---------------------------------------------------------------------------- #


def create_fuzzer_utils_crate(install_path: Path):
    create_cargo_toml(install_path)
    create_lib_rs(install_path)


# ---------------------------------------------------------------------------- #


def create_cargo_toml(install_path: Path):
    create_file(
        install_path / "fuzzer_utils" / "Cargo.toml",
        """[package]
name = "fuzzer_utils"
version = "1.0.0"
edition = "2021"

[dependencies]
once_cell = "1.18.0"
""",
    )


# ---------------------------------------------------------------------------- #


def create_lib_rs(install_path: Path):
    create_file(
        install_path / "fuzzer_utils" / "src" / "lib.rs",
        """use std::sync::atomic::{AtomicBool, Ordering};
use once_cell::sync::Lazy;
use std::sync::Mutex;

////////////////
// ASSERTIONS
/////////

pub static GLOBAL_FUZZING_ASSERTION_FLAG: Lazy<AtomicBool> = Lazy::new(|| AtomicBool::new(true));

pub fn assertions_enabled() -> bool {
    GLOBAL_FUZZING_ASSERTION_FLAG.load(Ordering::Relaxed)
}

pub fn set_assertions_flag(value: bool) {
    GLOBAL_FUZZING_ASSERTION_FLAG.store(value, Ordering::Relaxed);
}

pub fn enable_assertions() {
    GLOBAL_FUZZING_ASSERTION_FLAG.store(true, Ordering::Relaxed);
}

pub fn disable_assertions() {
    GLOBAL_FUZZING_ASSERTION_FLAG.store(false, Ordering::Relaxed);
}

/// Custom assert! macro
#[macro_export]
macro_rules! fuzzer_assert {
    ($cond:expr $(,)?) => {{
        if $crate::assertions_enabled() {
            assert!($cond);
        } else if !$cond {
            println!("Warning: fuzzer_assert! failed: {}", stringify!($cond));
        }
    }};
    ($cond:expr, $($arg:tt)+) => {{
        if $crate::assertions_enabled() {
            assert!($cond, $($arg)+);
        } else if !$cond {
            println!("Warning: fuzzer_assert! failed: {}", format_args!($($arg)+));
        }
    }};
}

/// Custom assert_eq! macro
#[macro_export]
macro_rules! fuzzer_assert_eq {
    ($left:expr, $right:expr $(,)?) => {{
        if $crate::assertions_enabled() {
            assert_eq!($left, $right);
        } else if $left != $right {
            println!(
                "Warning: fuzzer_assert_eq! failed: `{} != {}` (left: `{:?}`, right: `{:?}`)",
                stringify!($left),
                stringify!($right),
                &$left,
                &$right,
            );
        }
    }};
    ($left:expr, $right:expr, $($arg:tt)+) => {{
        if $crate::assertions_enabled() {
            assert_eq!($left, $right, $($arg)+);
        } else if $left != $right {
            println!(
                "Warning: fuzzer_assert_eq! failed: `{} != {}` (left: `{:?}`, right: `{:?}`): {}",
                stringify!($left),
                stringify!($right),
                &$left,
                &$right,
                format_args!($($arg)+),
            );
        }
    }};
}

////////////////
// SEED
/////////

static GLOBAL_SEED: Lazy<Mutex<u64>> = Lazy::new(|| Mutex::new(0));

pub fn set_seed(value: u64) {
    let mut state = GLOBAL_SEED.lock().unwrap();
    *state = value;
}

pub fn get_seed() -> u64 {
    let state = GLOBAL_SEED.lock().unwrap();
    *state
}

////////////////
// FAULT INJECTION
/////////

pub static GLOBAL_INJECTION_FLAG: Lazy<AtomicBool> = Lazy::new(|| AtomicBool::new(false));

pub fn injection_enabled() -> bool {
    GLOBAL_INJECTION_FLAG.load(Ordering::Relaxed)
}

pub fn set_injection(value: bool) {
    GLOBAL_INJECTION_FLAG.store(value, Ordering::Relaxed);
}

pub fn enable_injection() {
    GLOBAL_INJECTION_FLAG.store(true, Ordering::Relaxed);
}

pub fn disable_injection() {
    GLOBAL_INJECTION_FLAG.store(false, Ordering::Relaxed);
}

static GLOBAL_INJECTION_KIND: Lazy<Mutex<String>> = Lazy::new(|| Mutex::new(String::new()));

pub fn set_injection_kind(value: String) {
    let mut state = GLOBAL_INJECTION_KIND.lock().unwrap();
    *state = value.clone();
}

pub fn get_injection_kind() -> String {
    let state = GLOBAL_INJECTION_KIND.lock().unwrap();
    (*state).clone()
}

static GLOBAL_INJECTION_STEP: Lazy<Mutex<u64>> = Lazy::new(|| Mutex::new(0));

pub fn set_injection_step(value: u64) {
    let mut state = GLOBAL_INJECTION_STEP.lock().unwrap();
    *state = value;
}

pub fn get_injection_step() -> u64 {
    let state = GLOBAL_INJECTION_STEP.lock().unwrap();
    *state
}

////////////////
// TRACE LOGGING
/////////

pub static GLOBAL_TRACE_LOG_FLAG: Lazy<AtomicBool> = Lazy::new(|| AtomicBool::new(false));

pub fn trace_log_enabled() -> bool {
    GLOBAL_TRACE_LOG_FLAG.load(Ordering::Relaxed)
}

pub fn set_trace_logging(value: bool) {
    GLOBAL_TRACE_LOG_FLAG.store(value, Ordering::Relaxed);
}

pub fn enable_trace_logging() {
    GLOBAL_TRACE_LOG_FLAG.store(true, Ordering::Relaxed);
}

pub fn disable_trace_logging() {
    GLOBAL_TRACE_LOG_FLAG.store(false, Ordering::Relaxed);
}
""",
    )


# ---------------------------------------------------------------------------- #
