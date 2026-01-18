from jolt_fuzzer.zkvm_repository.injection_sources.cpu_rs_20ac6eb import (
    cpu_rs as cpu_rs_20ac6eb,
)
from jolt_fuzzer.zkvm_repository.injection_sources.cpu_rs_42de0ca import (
    cpu_rs as cpu_rs_42de0ca,
)
from jolt_fuzzer.zkvm_repository.injection_sources.cpu_rs_55b9830 import (
    cpu_rs as cpu_rs_55b9830,
)
from jolt_fuzzer.zkvm_repository.injection_sources.cpu_rs_57ea518 import (
    cpu_rs as cpu_rs_57ea518,
)
from jolt_fuzzer.zkvm_repository.injection_sources.cpu_rs_70c7733 import (
    cpu_rs as cpu_rs_70c7733,
)
from jolt_fuzzer.zkvm_repository.injection_sources.cpu_rs_85bf51d import (
    cpu_rs as cpu_rs_85bf51d,
)
from jolt_fuzzer.zkvm_repository.injection_sources.cpu_rs_0582b2a import (
    cpu_rs as cpu_rs_0582b2a,
)
from jolt_fuzzer.zkvm_repository.injection_sources.cpu_rs_0369981 import (
    cpu_rs as cpu_rs_0369981,
)
from jolt_fuzzer.zkvm_repository.injection_sources.cpu_rs_1687134 import (
    cpu_rs as cpu_rs_1687134,
)
from jolt_fuzzer.zkvm_repository.injection_sources.cpu_rs_d59219a import (
    cpu_rs as cpu_rs_d59219a,
)
from jolt_fuzzer.zkvm_repository.injection_sources.cpu_rs_e9caa23 import (
    cpu_rs as cpu_rs_e9caa23,
)


def jolt_tracer_src_emulator_cpu_rs(commit_or_branch: str) -> str:
    match commit_or_branch:
        case "main":
            return cpu_rs_1687134()
        case "1687134d117a19d1f6c6bd03fd23191013c53d1b":
            return cpu_rs_1687134()
        case "0369981446471c2ed2c4a4d2f24d61205a2d0853":
            return cpu_rs_0369981()
        case "d59219a0633d91dc5dbe19ade5f66f179c27c834":
            return cpu_rs_d59219a()
        case "0582b2aa4a33944506d75ce891db7cf090814ff6":
            return cpu_rs_0582b2a()
        case "57ea518d6d9872fb221bf6ac97df1456a5494cf2":
            return cpu_rs_57ea518()
        case "20ac6eb526af383e7b597273990b5e4b783cc2a6":
            return cpu_rs_20ac6eb()
        case "70c77337426615b67191b301e9175e2bb093830d":
            return cpu_rs_70c7733()
        case "55b9830a3944dde55d33a55c42522b81dd49f87a":
            return cpu_rs_55b9830()
        case "42de0ca1f581dd212dda7ff44feee806556531d2":
            return cpu_rs_42de0ca()
        case "85bf51da10efa9c679c35ffc1a8d45cc6cb1c788":
            return cpu_rs_85bf51d()
        case "e9caa23565dbb13019afe61a2c95f51d1999e286":
            return cpu_rs_e9caa23()
        case _:
            raise NotImplementedError(f"unknown commit or branch '{commit_or_branch}'")
