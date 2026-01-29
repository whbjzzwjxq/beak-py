import logging
from pathlib import Path

from zkvm_fuzzer_utils.file import replace_in_file

logger = logging.getLogger("fuzzer")


def pico_bool_domain_is_real_fault_injection(pico_install_path: Path) -> None:
    """
    Patch Pico so a malicious prover can set MemoryLocalChip's `is_real` witness column
    to a non-boolean value (e.g. 2) for a chosen local memory event.

    This is meant to exercise the `bool_domain` bucket (Pico-IsReal-01 in beak-scopes).

    Control via env vars (read during proving):
      - BEAK_PICO_INJECT_BOOL_DOMAIN_IS_REAL=1
      - BEAK_PICO_INJECT_BOOL_DOMAIN_IS_REAL_ADDR=<u32>
      - BEAK_PICO_INJECT_BOOL_DOMAIN_IS_REAL_VALUE=<u32>   (default: 2)
    """

    traces_rs = (
        pico_install_path / "vm" / "src" / "chips" / "chips" / "riscv_memory" / "local" / "traces.rs"
    )

    if not traces_rs.exists():
        raise FileNotFoundError(f"pico MemoryLocal traces.rs not found at {traces_rs}")

    content = traces_rs.read_text()
    if "BEAK_PICO_INJECT_BOOL_DOMAIN_IS_REAL" in content:
        logger.info("pico bool_domain/is_real injection already present; skipping patch")
        return

    # Insert deterministic target selection before the parallel trace fill.
    # Match the `values` init line, but do NOT consume indentation from the next line.
    insert_after = (
        r"([ \t]*let mut values = zeroed_f_vec\(padded_nb_rows \* NUM_MEMORY_LOCAL_INIT_COLS\);\n)"
    )
    injection_prelude = r"""\1

        // --- beak-fuzz fault injection (bool_domain / Pico-IsReal-01) ---
        // Allow setting MemoryLocalChip's `is_real` to a non-boolean value (e.g. 2) on a chosen
        // local memory event. This intentionally models an under-constrained boolean domain.
        let beak_inject_enabled = std::env::var("BEAK_PICO_INJECT_BOOL_DOMAIN_IS_REAL")
            .ok()
            .map(|v| {
                let v = v.trim().to_ascii_lowercase();
                v == "1" || v == "true" || v == "yes"
            })
            .unwrap_or(false);
        let beak_inject_addr: Option<u32> =
            std::env::var("BEAK_PICO_INJECT_BOOL_DOMAIN_IS_REAL_ADDR")
                .ok()
                .and_then(|v| v.trim().parse::<u32>().ok());
        let beak_inject_value: u32 = std::env::var("BEAK_PICO_INJECT_BOOL_DOMAIN_IS_REAL_VALUE")
            .ok()
            .and_then(|v| v.trim().parse::<u32>().ok())
            .unwrap_or(2);

        // Pick the *first* matching event index deterministically (avoid rayon scheduling nondeterminism).
        let beak_inject_event_idx: Option<usize> = if beak_inject_enabled {
            if let Some(addr) = beak_inject_addr {
                events.iter().position(|e| e.addr == addr)
            } else if !events.is_empty() {
                // Default: inject the first local memory event to make smoke-testing easy.
                Some(0)
            } else {
                None
            }
        } else {
            None
        };
"""

    updated = replace_in_file(traces_rs, [(insert_after, injection_prelude)], flags=0)
    if not updated:
        raise RuntimeError(
            "Unable to patch pico MemoryLocal traces.rs (prelude insertion did not match). "
            "Upstream file likely changed."
        )

    # Replace the concrete witness assignment.
    # Replace only the assignment line (including its newline), without consuming indentation
    # from the following line.
    # Capture only indentation (no newlines), otherwise backreferences can inject extra blank lines.
    replace_pattern = r"([ \t]*)cols\.is_real\s*=\s*F::ONE;\n"
    replace_with = r"""\1cols.is_real = if beak_inject_event_idx == Some(base_event_idx + k) {
\1    F::from_canonical_u32(beak_inject_value)
\1} else {
\1    F::ONE
\1};
"""
    updated = replace_in_file(traces_rs, [(replace_pattern, replace_with)], flags=0)
    if not updated:
        raise RuntimeError(
            "Unable to patch pico MemoryLocal traces.rs (is_real assignment replacement did not match). "
            "Upstream file likely changed."
        )

    logger.info("applied pico bool_domain/is_real fault injection patch")
