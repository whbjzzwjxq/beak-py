use std::sync::Arc;

use openvm_build::GuestOptions;
use openvm_sdk::{
    config::{AppConfig, SdkVmConfig},
    Sdk, StdIn,
};
use openvm_stark_sdk::config::FriParameters;

use clap::Parser;
use std::time::Instant;

#[derive(Parser, Debug)]
#[clap(author, version, about, long_about = None)]
struct Args {
}

fn main() {
    let args = Args::parse();

    println!(
        "<record>{{\
            \"context\":\"Setup\", \
            \"status\":\"start\"\
        }}</record>"
    );
    let timer = Instant::now();

    // SDK VM Config
    let vm_config = SdkVmConfig::builder()
       .system(Default::default())
       .rv32i(Default::default())
       .rv32m(Default::default())
       .io(Default::default())
       .build();

    let sdk = Sdk::new();

    let guest_opts = GuestOptions::default();
    let target_path = "guest";
    let elf = sdk.build(
        guest_opts,
        &vm_config,
        target_path,
        &Default::default(),
        None // If None, "openvm-init.rs" is used
    ).expect("guest build");

    let exe = sdk.transpile(elf, vm_config.transpiler()).expect("guest transpile");

    let mut stdin = StdIn::default();

    // 1. Inject initial register values
    stdin.write(&3210664456u32);
    stdin.write(&2570323987u32);
    stdin.write(&1788707139u32);

    let app_log_blowup = 2;
    let app_fri_params = FriParameters::standard_with_100_bits_conjectured_security(app_log_blowup);
    let app_config = AppConfig::new(app_fri_params, vm_config);

    let app_committed_exe = sdk.commit_app_exe(app_fri_params, exe).expect("commit app exe");

    let app_pk = Arc::new(sdk.app_keygen(app_config).expect("app keygen"));

    println!(
        "<record>{{\
            \"context\":\"Setup\", \
            \"status\":\"success\", \
            \"time\":\"{:.2?}\"\
        }}</record>",
        timer.elapsed()
    );

    println!(
        "<record>{{\
            \"context\":\"Prover\", \
            \"status\":\"start\"\
        }}</record>"
    );
    let timer = Instant::now();

    let proof = sdk.generate_app_proof(
        app_pk.clone(),
        app_committed_exe.clone(),
        stdin.clone()
    ).expect("prove");

    println!(
        "<record>{{\
            \"context\":\"Prover\", \
            \"status\":\"success\",\
            \"output\":\"{:?}\", \
            \"time\":\"{:.2?}\"\
        }}</record>",
        proof.user_public_values.public_values,
        timer.elapsed()
    );


    println!(
        "<record>{{\
            \"context\":\"Verifier\", \
            \"status\":\"start\"\
        }}</record>"
    );
    let timer = Instant::now();

    let app_vk = app_pk.get_app_vk();
    sdk.verify_app_proof(&app_vk, &proof).expect("verify");

    println!(
        "<record>{{\
            \"context\":\"Verifier\", \
            \"status\":\"success\", \
            \"time\":\"{:.2?}\"\
        }}</record>",
        timer.elapsed()
    );
}