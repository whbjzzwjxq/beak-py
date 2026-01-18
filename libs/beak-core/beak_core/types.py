from dataclasses import dataclass, field

@dataclass
class FuzzingInstSeqInstance:
    """Container for a single fuzzing instance"""
    instructions: list[str]  # Assembly instruction sequence, e.g., ["add x1, x2, x3", "sub x4, x1, x5"]
    initial_regs: dict[int, int] = field(default_factory=dict)  # Initial register values {reg_index: value}
    expected_results: dict[int, int] = field(default_factory=dict)  # Expected register values after execution
    
    def to_asm_block(self) -> str:
        return "\n".join(self.instructions)

