from pathlib import Path

from zkvm_fuzzer_utils.file import create_file


def create_cargo_toml(root: Path):
    create_file(
        root / "crates" / "fuzzer_utils" / "Cargo.toml",
        """[package]
name = "fuzzer_utils"
version = "1.0.0"
edition = "2021"

[dependencies]
lazy_static = "1.4"
rand = "0.9.1"

openvm-instructions = { path = "../toolchain/instructions" }
openvm-rv32im-transpiler = { path = "../../extensions/rv32im/transpiler" }

openvm-stark-backend.workspace = true
""",
    )


def create_lib_rs(root: Path):
    create_file(
        root / "crates" / "fuzzer_utils" / "src" / "lib.rs",
        """use std::sync::Mutex;
use lazy_static::lazy_static;
use openvm_stark_backend::p3_field::{Field, PrimeField32};

use rand::rngs::StdRng;
use rand::{Rng, SeedableRng};
use rand::seq::SliceRandom;
use rand::seq::IndexedRandom;

use openvm_rv32im_transpiler::{
    BaseAluOpcode,
    ShiftOpcode,
    LessThanOpcode,
    Rv32LoadStoreOpcode,
    BranchEqualOpcode,
    BranchLessThanOpcode,
    Rv32JalLuiOpcode,
    Rv32JalrOpcode,
    Rv32AuipcOpcode,
    MulOpcode,
    MulHOpcode,
    DivRemOpcode,
    Rv32HintStoreOpcode,
    // Rv32Phantom,
};

use openvm_instructions::{
    VmOpcode,
    LocalOpcode,
    SystemOpcode,
    PublishOpcode,
    instruction::Instruction,
};


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
    state.rng.random::<bool>()
}

pub fn random_from_choices<T>(choices: Vec<T>) -> T
    where T : Clone
{
    let mut state = GLOBAL_STATE.lock().unwrap();
    choices.choose(&mut state.rng).unwrap().clone()
}

pub fn random_opcode(rng: &mut StdRng) ->  VmOpcode {
    match rng.random_range(0..=40) {
         0 => BaseAluOpcode::ADD.global_opcode(),
         1 => BaseAluOpcode::SUB.global_opcode(),
         2 => BaseAluOpcode::XOR.global_opcode(),
         3 => BaseAluOpcode::OR.global_opcode(),
         4 => BaseAluOpcode::AND.global_opcode(),
         5 => ShiftOpcode::SLL.global_opcode(),
         6 => ShiftOpcode::SRL.global_opcode(),
         7 => ShiftOpcode::SRA.global_opcode(),
         8 => LessThanOpcode::SLT.global_opcode(),
         9 => LessThanOpcode::SLTU.global_opcode(),
        10 => Rv32LoadStoreOpcode::LOADW.global_opcode(),
        11 => Rv32LoadStoreOpcode::LOADBU.global_opcode(),
        12 => Rv32LoadStoreOpcode::LOADHU.global_opcode(),
        13 => Rv32LoadStoreOpcode::STOREW.global_opcode(),
        14 => Rv32LoadStoreOpcode::STOREH.global_opcode(),
        15 => Rv32LoadStoreOpcode::STOREB.global_opcode(),
        16 => Rv32LoadStoreOpcode::LOADB.global_opcode(),
        17 => Rv32LoadStoreOpcode::LOADH.global_opcode(),
        18 => BranchEqualOpcode::BEQ.global_opcode(),
        19 => BranchEqualOpcode::BNE.global_opcode(),
        20 => BranchLessThanOpcode::BLT.global_opcode(),
        21 => BranchLessThanOpcode::BLTU.global_opcode(),
        22 => BranchLessThanOpcode::BGE.global_opcode(),
        23 => BranchLessThanOpcode::BGEU.global_opcode(),
        24 => Rv32JalLuiOpcode::JAL.global_opcode(),
        25 => Rv32JalLuiOpcode::LUI.global_opcode(),
        26 => Rv32JalrOpcode::JALR.global_opcode(),
        27 => Rv32AuipcOpcode::AUIPC.global_opcode(),
        28 => MulOpcode::MUL.global_opcode(),
        29 => MulHOpcode::MULH.global_opcode(),
        30 => MulHOpcode::MULHSU.global_opcode(),
        31 => MulHOpcode::MULHU.global_opcode(),
        32 => DivRemOpcode::DIV.global_opcode(),
        33 => DivRemOpcode::DIVU.global_opcode(),
        34 => DivRemOpcode::REM.global_opcode(),
        35 => DivRemOpcode::REMU.global_opcode(),
        36 => Rv32HintStoreOpcode::HINT_STOREW.global_opcode(),
        37 => Rv32HintStoreOpcode::HINT_BUFFER.global_opcode(),
        38 => SystemOpcode::TERMINATE.global_opcode(),
        39 => SystemOpcode::PHANTOM.global_opcode(),
        40 => PublishOpcode::PUBLISH.global_opcode(),
        // ? => Rv32Phantom::HintInput.global_opcode(),
        // ? => Rv32Phantom::PrintStr.global_opcode(),
        // ? => Rv32Phantom::HintRandom.global_opcode(),
        // ? => Rv32Phantom::HintLoadByKey.global_opcode(),
        _  => panic!("selector value was out of bounds!"),
    }
}

pub fn random_new_opcode(opcode: VmOpcode, rng: &mut StdRng) -> VmOpcode {
    loop {
        let new_opcode = random_opcode(rng);
        if new_opcode != opcode {
            return new_opcode;
        }
    }
}

fn internal_random_mod_of_u32(element: u32, rng: &mut StdRng) -> u32 {
    let mut new_element = element;
    while new_element == element {
        let selector: u32 = rng.random_range(0..=7);
        new_element = match selector {
            0 => { 0 },
            1 => { 1 },
            2 => { 0xffffffff },
            3 => { 0xfffffffe },
            4 => {
                let n = rng.random_range(1..=31);
                let bits_to_flip = rand::seq::index::sample(rng, 31, n).into_vec();
                let mut flipped_element = element;
                for bit_to_flip in bits_to_flip {
                    flipped_element ^= 1 << bit_to_flip;
                }
                flipped_element
            },
            5 => { element.saturating_add(1) },
            6 => { element.saturating_sub(1) },
            7 => { rng.random::<u32>() },
            _ => unreachable!(),
        };
    }
    new_element
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

pub fn random_mutate_field_element<F: Field + PrimeField32>(element: F, rng: &mut StdRng) -> F {
    F::from_canonical_u32(internal_random_mod_of_u32(element.as_canonical_u32(), rng))
}

pub fn random_mutate_instruction<F: Field + PrimeField32>(instruction: &Instruction<F>) ->  Instruction<F> {
    let mut state = GLOBAL_STATE.lock().unwrap();

    // create a mutable copy of the old instruction
    let mut new_instruction = instruction.clone();

    // pick the fields to updated and how many should be modified
    let update_fields = state.rng.random_range(1..=8);
    let mut update_options: Vec<u8> = vec![0, 1, 2, 3, 4, 5, 6, 7];

    // pick random selection from the available options
    update_options.shuffle(&mut state.rng);
    update_options.truncate(update_fields);

    // sort the options such that we first pick the new opcode if it is there
    update_options.sort();

    // execute the picked modifications
    for option in update_options {
        match option {
            0 => {
                new_instruction = Instruction::default(); // full reset
                new_instruction.opcode = random_new_opcode(instruction.opcode, &mut state.rng);
            },
            1 => { new_instruction.a = random_mutate_field_element(new_instruction.a, &mut state.rng); },
            2 => { new_instruction.b = random_mutate_field_element(new_instruction.b, &mut state.rng); },
            3 => { new_instruction.c = random_mutate_field_element(new_instruction.c, &mut state.rng); },
            4 => { new_instruction.d = random_mutate_field_element(new_instruction.d, &mut state.rng); },
            5 => { new_instruction.e = random_mutate_field_element(new_instruction.e, &mut state.rng); },
            6 => { new_instruction.f = random_mutate_field_element(new_instruction.f, &mut state.rng); },
            7 => { new_instruction.g = random_mutate_field_element(new_instruction.g, &mut state.rng); },
            _ => unreachable!(),
        };
    }

    new_instruction
}

""",  # noqa: E501
    )


def create_fuzzer_utils_crate(root: Path):
    create_cargo_toml(root)
    create_lib_rs(root)
