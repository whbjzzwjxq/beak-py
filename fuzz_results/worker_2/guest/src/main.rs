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
    let mut x24: u32 = read();
    let mut x29: u32 = read();
    let mut x31: u32 = read();

    // Variable to capture final x0 value (to check if it's still 0)
    let mut final_x0: u32 = 0;

    // 2. Execute random instruction sequence
    unsafe {
        asm!(
            // Fuzzing instruction sequence
            "sltu x31, x29, x24",

            // Manually capture x0 into a temporary register that's mapped to final_x0
            "mv {final_x0}, x0",

            // Bind to physical registers (excluding x0 from operands)
            inout("x24") x24,
            inout("x29") x29,
            inout("x31") x31,
            
            final_x0 = out(reg) final_x0,
            
            options(nostack, nomem)
        );
    }

    // 3. Reveal final results back to Host using stream 0
    reveal_u32(24, 0); 
    reveal_u32(x24, 0); 
    reveal_u32(29, 0); 
    reveal_u32(x29, 0); 
    reveal_u32(31, 0); 
    reveal_u32(x31, 0); 
}