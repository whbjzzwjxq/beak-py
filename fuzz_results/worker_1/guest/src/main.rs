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
    let mut x1: u32 = read();
    let mut x11: u32 = read();
    let mut x15: u32 = read();
    let mut x17: u32 = read();
    let mut x21: u32 = read();
    let mut x23: u32 = read();

    // Variable to capture final x0 value (to check if it's still 0)
    let mut final_x0: u32 = 0;

    // 2. Execute random instruction sequence
    unsafe {
        asm!(
            // Fuzzing instruction sequence
            "remu x11, x15, x23",
            "mulhsu x21, x1, x17",

            // Manually capture x0 into a temporary register that's mapped to final_x0
            "mv {final_x0}, x0",

            // Bind to physical registers (excluding x0 from operands)
            inout("x1") x1,
            inout("x11") x11,
            inout("x15") x15,
            inout("x17") x17,
            inout("x21") x21,
            inout("x23") x23,
            
            final_x0 = out(reg) final_x0,
            
            options(nostack, nomem)
        );
    }

    // 3. Reveal final results back to Host using stream 0
    reveal_u32(1, 0); 
    reveal_u32(x1, 0); 
    reveal_u32(11, 0); 
    reveal_u32(x11, 0); 
    reveal_u32(15, 0); 
    reveal_u32(x15, 0); 
    reveal_u32(17, 0); 
    reveal_u32(x17, 0); 
    reveal_u32(21, 0); 
    reveal_u32(x21, 0); 
    reveal_u32(23, 0); 
    reveal_u32(x23, 0); 
}