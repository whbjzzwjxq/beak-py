import re
from pathlib import Path

from zkvm_fuzzer_utils.file import create_file, replace_in_file


def generate_test_file(name: str, content: str) -> Path:
    filename = Path("out") / "zkvm-fuzzer-utils" / "test" / name
    create_file(filename, content)
    return filename


def compare_test_file_to_content(testfile, content: str):
    file_content = testfile.read_text()
    if testfile.read_text() != content:
        raise ValueError(
            f"{testfile} does not match expected content!"
            "\n\n"
            f"{content}"
            "\n-----------------------------------\n"
            f"{file_content}"
        )


def test_replace_in_file():

    testfile = generate_test_file(
        "test_replace_in_file.cpp",
        """
std::array<Val, 5> extern_getMemoryTxn(ExecContext& ctx, Val addrElem) {
  uint32_t addr = addrElem.asUInt32();
  size_t txnIdx = ctx.preflight.cycles[ctx.cycle].txnIdx++;
  const MemoryTransaction& txn = ctx.preflight.txns[txnIdx];
  if (txn.cycle / 2 != ctx.cycle) {
    printf("txn.cycle: %u, ctx.cycle: %zu\\n", txn.cycle, ctx.cycle);
    throw std::runtime_error("txn cycle mismatch");
  }

  if (txn.addr != addr) {
    printf("[%lu]: txn.addr: 0x%08x, addr: 0x%08x\\n", ctx.cycle, txn.addr, addr);
    throw std::runtime_error("memory peek not in preflight");
  }

  assert(txn.addr != addr);

  return {
      txn.prevCycle,
      txn.prevWord & 0xffff,
      txn.prevWord >> 16,
      txn.word & 0xffff,
      txn.word >> 16,
  };
}
""",
    )

    replace_in_file(
        testfile.absolute(),
        [
            (
                r'^([^\n]*)throw\s+std::runtime_error\s*\(\s*"([^"]*)"\s*\)\s*;',
                r"""
\1// <----------------------- START OF FAULT INJECTION ----------------------->
\1if (const char* env_flag_ptr = std::getenv("ENABLE_INJECTION")) {
\1    auto env_flag_string = std::string(env_flag_ptr);
\1    if (env_flag_string == "1") {
\1        printf("SKIP THROW: %s @ %s:%d\\n", "Warning: fuzzer_assert! failed: \2", __FILE__, __LINE__);
\1    } else { throw std::runtime_error("\2"); }
\1} else { throw std::runtime_error("\2"); }
\1// <------------------------ END OF FAULT INJECTION ------------------------>
""",  # noqa: E501
            ),
            (
                r"^([^\n]*)assert\(\s*([^\)]*)\s*\)\s*;",
                r"""
\1// <----------------------- START OF FAULT INJECTION ----------------------->
\1if (const char* env_flag_ptr = std::getenv("ENABLE_INJECTION")) {
\1    auto env_flag_string = std::string(env_flag_ptr);
\1    if (env_flag_string == "1") {
\1        printf("SKIP ASSERT: %s @ %s:%d\\n", "Warning: fuzzer_assert! failed: \2", __FILE__, __LINE__);
\1    } else { assert(\2); }
\1} else { assert(\2); }
\1// <------------------------ END OF FAULT INJECTION ------------------------>
""",  # noqa: E501
            ),
        ],
        flags=re.MULTILINE,
    )

    compare_test_file_to_content(
        testfile,
        """
std::array<Val, 5> extern_getMemoryTxn(ExecContext& ctx, Val addrElem) {
  uint32_t addr = addrElem.asUInt32();
  size_t txnIdx = ctx.preflight.cycles[ctx.cycle].txnIdx++;
  const MemoryTransaction& txn = ctx.preflight.txns[txnIdx];
  if (txn.cycle / 2 != ctx.cycle) {
    printf("txn.cycle: %u, ctx.cycle: %zu\\n", txn.cycle, ctx.cycle);

    // <----------------------- START OF FAULT INJECTION ----------------------->
    if (const char* env_flag_ptr = std::getenv("ENABLE_INJECTION")) {
        auto env_flag_string = std::string(env_flag_ptr);
        if (env_flag_string == "1") {
            printf("SKIP THROW: %s @ %s:%d\\n", "Warning: fuzzer_assert! failed: txn cycle mismatch", __FILE__, __LINE__);
        } else { throw std::runtime_error("txn cycle mismatch"); }
    } else { throw std::runtime_error("txn cycle mismatch"); }
    // <------------------------ END OF FAULT INJECTION ------------------------>

  }

  if (txn.addr != addr) {
    printf("[%lu]: txn.addr: 0x%08x, addr: 0x%08x\\n", ctx.cycle, txn.addr, addr);

    // <----------------------- START OF FAULT INJECTION ----------------------->
    if (const char* env_flag_ptr = std::getenv("ENABLE_INJECTION")) {
        auto env_flag_string = std::string(env_flag_ptr);
        if (env_flag_string == "1") {
            printf("SKIP THROW: %s @ %s:%d\\n", "Warning: fuzzer_assert! failed: memory peek not in preflight", __FILE__, __LINE__);
        } else { throw std::runtime_error("memory peek not in preflight"); }
    } else { throw std::runtime_error("memory peek not in preflight"); }
    // <------------------------ END OF FAULT INJECTION ------------------------>

  }


  // <----------------------- START OF FAULT INJECTION ----------------------->
  if (const char* env_flag_ptr = std::getenv("ENABLE_INJECTION")) {
      auto env_flag_string = std::string(env_flag_ptr);
      if (env_flag_string == "1") {
          printf("SKIP ASSERT: %s @ %s:%d\\n", "Warning: fuzzer_assert! failed: txn.addr != addr", __FILE__, __LINE__);
      } else { assert(txn.addr != addr); }
  } else { assert(txn.addr != addr); }
  // <------------------------ END OF FAULT INJECTION ------------------------>


  return {
      txn.prevCycle,
      txn.prevWord & 0xffff,
      txn.prevWord >> 16,
      txn.word & 0xffff,
      txn.word >> 16,
  };
}
""",  # noqa: E501
    )
