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
    let mut x13: u32 = read();
    let mut x15: u32 = read();
    let mut x19: u32 = read();
    let mut x22: u32 = read();
    let mut x24: u32 = read();
    let mut x27: u32 = read();
    let mut x30: u32 = read();

    // Variable to capture final x0 value (to check if it's still 0)
    let mut final_x0: u32 = 0;

    // 2. Execute random instruction sequence
    unsafe {
        asm!(
            // Fuzzing instruction sequence
            "xor x19, x13, x19",
            "lui x24, 522652",
            "mulhu x27, x30, x19",
            "slli x22, x24, 1",
            "sltu x13, x30, x15",

            // Manually capture x0 into a temporary register that's mapped to final_x0
            "mv {final_x0}, x0",

            // Bind to physical registers (excluding x0 from operands)
            inout("x13") x13,
            inout("x15") x15,
            inout("x19") x19,
            inout("x22") x22,
            inout("x24") x24,
            inout("x27") x27,
            inout("x30") x30,
            
            final_x0 = out(reg) final_x0,
            
            options(nostack, nomem)
        );
    }

    // 3. Reveal final results back to Host using stream 0
    reveal_u32(13, 0); 
    reveal_u32(x13, 0); 
    reveal_u32(15, 0); 
    reveal_u32(x15, 0); 
    reveal_u32(19, 0); 
    reveal_u32(x19, 0); 
    reveal_u32(22, 0); 
    reveal_u32(x22, 0); 
    reveal_u32(24, 0); 
    reveal_u32(x24, 0); 
    reveal_u32(27, 0); 
    reveal_u32(x27, 0); 
    reveal_u32(30, 0); 
    reveal_u32(x30, 0); 
}