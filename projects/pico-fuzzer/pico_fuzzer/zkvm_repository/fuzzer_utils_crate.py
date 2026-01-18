from pathlib import Path

from zkvm_fuzzer_utils.file import create_file


def create_cargo_toml(root: Path):
    create_file(
        root / "fuzzer_utils" / "Cargo.toml",
        """[package]
name = "fuzzer_utils"
version = "1.0.0"
edition = "2021"

[dependencies]
lazy_static = "1.4"
rand.workspace = true
""",
    )


def create_lib_rs(root: Path):
    create_file(
        root / "fuzzer_utils" / "src" / "lib.rs",
        """use std::sync::Mutex;
use lazy_static::lazy_static;

use rand::rngs::StdRng;
use rand::{Rng, SeedableRng};
use rand::seq::SliceRandom;

////////////////
// GLOBAL STATE
/////////

#[derive(Debug, Clone)]
pub struct GlobalState {
    pub trace_logging: bool,
    pub injection: bool,
    pub assertions: bool,
    pub seed: u64,
    pub step: u64,
    pub injection_kind: String,
    pub injection_step: u64,
    pub rng: StdRng,
    pub hint_instruction: String,  // the default is an empty string
    pub hint_assembly: String,  // the default is an empty string
    pub hint_pc: u32,  // the default is an empty string
}

impl GlobalState {
    fn new() -> Self {
        Self {
            trace_logging: false,
            injection: false,
            assertions: true,
            seed: 0,
            injection_kind: String::new(),
            step: 0,
            injection_step: 0,
            rng: StdRng::seed_from_u64(0),
            hint_instruction: String::new(),
            hint_assembly: String::new(),
            hint_pc: 0,
        }
    }
}

lazy_static! {
    static ref GLOBAL_STATE: Mutex<GlobalState> = Mutex::new(GlobalState::new());
}

pub fn is_trace_logging() -> bool {
    GLOBAL_STATE.lock().unwrap().trace_logging
}

pub fn set_trace_logging(value: bool) {
    let mut state = GLOBAL_STATE.lock().unwrap();
    state.trace_logging = value;
}

pub fn enable_trace_logging() {
    set_trace_logging(true);
}

pub fn disable_trace_logging() {
    set_trace_logging(false);
}

pub fn is_injection() -> bool {
    GLOBAL_STATE.lock().unwrap().injection
}

pub fn set_injection(value: bool) {
    let mut state = GLOBAL_STATE.lock().unwrap();
    state.injection = value;
}

pub fn enable_injection() {
    set_injection(true);
}

pub fn disable_injection() {
    set_injection(false);
}

pub fn is_assertions() -> bool {
    GLOBAL_STATE.lock().unwrap().assertions
}

pub fn set_assertions(value: bool) {
    let mut state = GLOBAL_STATE.lock().unwrap();
    state.assertions = value;
}

pub fn enable_assertions() {
    set_assertions(true);
}

pub fn disable_assertions() {
    set_assertions(false);
}

pub fn set_seed(value: u64) {
    let mut state = GLOBAL_STATE.lock().unwrap();
    state.rng = StdRng::seed_from_u64(value);
    state.seed = value;
}

pub fn get_seed() -> u64 {
    GLOBAL_STATE.lock().unwrap().seed
}

pub fn is_injection_kind(value: &str) -> bool {
    GLOBAL_STATE.lock().unwrap().injection_kind == value
}

pub fn set_injection_kind(value: String) {
    let mut state = GLOBAL_STATE.lock().unwrap();
    state.injection_kind = value.clone();
}

pub fn get_injection_kind() -> String {
    GLOBAL_STATE.lock().unwrap().injection_kind.clone()
}

pub fn inc_step() {
    let mut state = GLOBAL_STATE.lock().unwrap();
    state.step += 1;

    // TODO: in the future this should be either dynamic or a setting
    if state.step > 1000000 {
        panic!("Endless loop detection step bound triggered! Bound: 1000000 steps");
    }
}

pub fn get_step() -> u64 {
    GLOBAL_STATE.lock().unwrap().step
}

pub fn get_injection_step() -> u64 {
    GLOBAL_STATE.lock().unwrap().injection_step
}

pub fn set_injection_step(value: u64) {
    let mut state = GLOBAL_STATE.lock().unwrap();
    state.injection_step = value;
}

pub fn is_injection_at_step(kind: &str) -> bool {
    let state = GLOBAL_STATE.lock().unwrap();
    state.injection &&
        state.step == state.injection_step &&
        state.injection_kind == kind
}

pub fn set_hint_instruction(value: &String) {
    let mut state = GLOBAL_STATE.lock().unwrap();
    state.hint_instruction = value.clone();
}

pub fn get_hint_instruction() -> String {
    let state = GLOBAL_STATE.lock().unwrap();
    state.hint_instruction.clone()
}

pub fn set_hint_assembly(value: &String) {
    let mut state = GLOBAL_STATE.lock().unwrap();
    state.hint_assembly = value.clone();
}

pub fn get_hint_assembly() -> String {
    let state = GLOBAL_STATE.lock().unwrap();
    state.hint_assembly.clone()
}

pub fn set_hint_pc(value: u32) {
    let mut state = GLOBAL_STATE.lock().unwrap();
    state.hint_pc = value;
}

pub fn get_hint_pc() -> u32 {
    let state = GLOBAL_STATE.lock().unwrap();
    state.hint_pc
}

pub fn update_hints(pc: u32, instruction: &String, assembly: &String) {
    let mut state = GLOBAL_STATE.lock().unwrap();
    state.hint_pc = pc;
    state.hint_instruction = instruction.clone();
    state.hint_assembly = assembly.clone();
}

////////////////
// CUSTOM ASSERTION MACROS
/////////

/// Custom assert! macro
#[macro_export]
macro_rules! fuzzer_assert {
    ($cond:expr $(,)?) => {{
        if $crate::is_assertions() {
            assert!($cond);
        } else if !$cond {
            println!("Warning: fuzzer_assert! failed: {}", stringify!($cond));
        }
    }};
    ($cond:expr, $($arg:tt)+) => {{
        if $crate::is_assertions() {
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
        if $crate::is_assertions() {
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
        if $crate::is_assertions() {
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

/// Custom assert_ne! macro
#[macro_export]
macro_rules! fuzzer_assert_ne {
    ($left:expr, $right:expr $(,)?) => {{
        if $crate::is_assertions() {
            assert_ne!($left, $right);
        } else if $left == $right {
            println!(
                "Warning: fuzzer_assert_ne! failed: `{} == {}` (left: `{:?}`, right: `{:?}`)",
                stringify!($left),
                stringify!($right),
                &$left,
                &$right,
            );
        }
    }};
    ($left:expr, $right:expr, $($arg:tt)+) => {{
        if $crate::is_assertions() {
            assert_ne!($left, $right, $($arg)+);
        } else if $left == $right {
            println!(
                "Warning: fuzzer_assert_ne! failed: `{} == {}` (left: `{:?}`, right: `{:?}`): {}",
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
// LOGGING
/////////

pub fn print_injection_info(
    inject_kind: &str,
    info: &String,
) {
    let state = GLOBAL_STATE.lock().unwrap();
    if state.trace_logging {
        println!(
            "<fault>{{\\
                \\"step\\":{}, \\
                \\"pc\\":{}, \\
                \\"instruction\\":\\"{}\\", \\
                \\"assembly\\":\\"{}\\", \\
                \\"kind\\":\\"{}\\", \\
                \\"info\\":\\"{}\\"\\
            }}</fault>",
            state.step,
            state.hint_pc,
            state.hint_instruction,
            state.hint_assembly,
            inject_kind,
            info,
        );
    }
}

pub fn print_trace_info() {
    let state = GLOBAL_STATE.lock().unwrap();
    if state.trace_logging {
        println!(
            "<trace>{{\\
                \\"step\\":{}, \\
                \\"pc\\":{}, \\
                \\"instruction\\":\\"{}\\", \\
                \\"assembly\\":\\"{}\\"\\
            }}</trace>",
            state.step,
            state.hint_pc,
            state.hint_instruction,
            state.hint_assembly,
        );
    }
}


////////////////
// RANDOMNESS
/////////

pub fn random_bool() -> bool {
    let mut state = GLOBAL_STATE.lock().unwrap();
    state.rng.gen::<bool>()
}

pub fn random_u8() -> u8 {
    let mut state = GLOBAL_STATE.lock().unwrap();
    state.rng.gen::<u8>()
}

pub fn random_u32() -> u32 {
    let mut state = GLOBAL_STATE.lock().unwrap();
    state.rng.gen::<u32>()
}

pub fn random_from_choices<T>(choices: Vec<T>) -> T
    where T : Clone
{
    let mut state = GLOBAL_STATE.lock().unwrap();
    choices.choose(&mut state.rng).unwrap().clone()
}

fn internal_random_mod_of_u32(element: u32, rng: &mut StdRng) -> u32 {
    let mut new_element = element;
    while new_element == element {
        let selector: u32 = rng.gen_range(0..=7);
        new_element = match selector {
            0 => { 0 },
            1 => { 1 },
            2 => { 0xffffffff },
            3 => { 0xfffffffe },
            4 => {
                let n = rng.gen_range(1..=31);
                let bits_to_flip = rand::seq::index::sample(rng, 31, n).into_vec();
                let mut flipped_element = element;
                for bit_to_flip in bits_to_flip {
                    flipped_element ^= 1 << bit_to_flip;
                }
                flipped_element
            },
            5 => { element.saturating_add(1) },
            6 => { element.saturating_sub(1) },
            7 => { rng.gen::<u32>() },
            _ => unreachable!(),
        };
    }
    new_element
}

pub fn random_mod_of_u32(element: u32) -> u32 {
    let mut state = GLOBAL_STATE.lock().unwrap();
    internal_random_mod_of_u32(element, &mut state.rng)
}

pub fn random_mod_of_u32_array<const LEN: usize>(elements: &[u32; LEN]) -> [u32; LEN] {
    let mut state = GLOBAL_STATE.lock().unwrap();

    let mut new_elements = *elements;
    let mut indices: Vec<usize> = (0..LEN).collect();
    indices.shuffle(&mut state.rng);
    let num_to_modify = state.rng.gen_range(1..=LEN);

    for &i in indices.iter().take(num_to_modify) {
        new_elements[i] = internal_random_mod_of_u32(elements[i], &mut state.rng);
    }

    new_elements
}

pub fn random_multiple_from_choices<T>(choices: Vec<T>) -> Vec<T>
    where T : Clone
{
    let mut state = GLOBAL_STATE.lock().unwrap();

    // pick the fields to updated and how many should be modified
    let update_fields = state.rng.gen_range(1..=choices.len());
    let mut update_options = choices.clone();

    // pick random choices from the available options
    update_options.shuffle(&mut state.rng);
    update_options.truncate(update_fields);

    update_options
}

""",  # noqa: E501
    )


def create_fuzzer_utils_crate(root: Path):
    create_cargo_toml(root)
    create_lib_rs(root)
