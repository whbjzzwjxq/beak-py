#![allow(unused_unsafe)]
#![allow(unconditional_panic)]
#![allow(arithmetic_overflow)]
#![no_main]

use openvm::io::{read, reveal_u32};
use core::arch::asm;

openvm::entry!(main);

#[no_mangle]
pub fn main() {
    // 1. Inject initial register states from Host (excluding x0)
    let mut x7: u32 = read();
    let mut x12: u32 = read();
    let mut x13: u32 = read();
    let mut x22: u32 = read();
    let mut x27: u32 = read();

    // Variable to capture final x0 value (to check if it's still 0)
    let mut final_x0: u32 = 0;

    // 2. Execute random instruction sequence
    unsafe {
        asm!(
            // Fuzzing instruction sequence
            "div x13, x7, x22",
            "sltiu x12, x27, 1807",
            "lui x22, 299409",

            // Manually capture x0 into a temporary register that's mapped to final_x0
            "mv {final_x0}, x0",

            // Bind to physical registers (excluding x0 from operands)
            inout("x7") x7,
            inout("x12") x12,
            inout("x13") x13,
            inout("x22") x22,
            inout("x27") x27,
            
            final_x0 = out(reg) final_x0,
            
            options(nostack, nomem)
        );
    }

    // 3. Reveal final results back to Host using stream 0
    reveal_u32(7, 0); 
    reveal_u32(x7, 0); 
    reveal_u32(12, 0); 
    reveal_u32(x12, 0); 
    reveal_u32(13, 0); 
    reveal_u32(x13, 0); 
    reveal_u32(22, 0); 
    reveal_u32(x22, 0); 
    reveal_u32(27, 0); 
    reveal_u32(x27, 0); 
}