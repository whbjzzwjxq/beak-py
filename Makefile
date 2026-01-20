# ---------------------------------------------------------------------------- #
#                                 Project Files                                #
# ---------------------------------------------------------------------------- #

ROOT=$(shell pwd)
VIRTUALENV=$(ROOT)/.venv
export UV_CACHE_DIR ?= $(ROOT)/.uv-cache
UV_RUN=uv run
BLACK=$(UV_RUN) black
FLAKE8=$(UV_RUN) flake8
ISORT=$(UV_RUN) isort
PYRIGHT=$(UV_RUN) pyright
PYTEST=$(UV_RUN) pytest
PYRIGHTCONFIG=$(ROOT)/pyrightconfig.json

# ---------------------------------------------------------------------------- #
#                                Command Section                               #
# ---------------------------------------------------------------------------- #

.PHONY: check clean format install ship test venv install-openvm run-openvm-loop1 install-sp1 run-sp1-loop1 run-sp1-loop1-7f643da run-sp1-loop1-f3326e6 run-sp1-loop1-811a3f2 install-risc0 run-risc0-loop1 install-pico run-pico-loop1 install-jolt run-jolt-loop1 install-nexus run-nexus-loop1 \
	docker-build fuzz-start fuzz-stop fuzz-logs

$(VIRTUALENV):
	uv venv

venv: $(VIRTUALENV)

clean:
	rm -rf $(VIRTUALENV) $(PYRIGHTCONFIG) uv.lock
	find . -type d -name "__pycache__" -exec rm -rf {} +

install: $(VIRTUALENV)
	uv sync

install-openvm: $(VIRTUALENV)
	uv sync --package openvm-fuzzer
	$(UV_RUN) openvm-fuzzer install ./openvm-src --zkvm-modification --commit-or-branch ca36de3803213da664b03d111801ab903d55e360

run-openvm-loop1:
	$(UV_RUN) openvm-fuzzer generate --seed 123 --out ./output --zkvm ./openvm-src

install-sp1: $(VIRTUALENV)
	uv sync --package sp1-fuzzer
	# NOTE: The install step will reset/clean the repo at the given path.
	# Use a dedicated repo checkout at `./sp1-src` (do NOT point at a working copy with changes).
	$(UV_RUN) sp1-fuzzer install ./sp1-src --commit-or-branch 7f643da16813af4c0fbaad4837cd7409386cf38c

run-sp1-loop1:
	$(UV_RUN) sp1-fuzzer run --seed 123 --out ./output --zkvm ./sp1-src --commit-or-branch all

run-sp1-loop1-7f643da:
	$(UV_RUN) sp1-fuzzer run --seed 123 --out ./output --zkvm ./sp1-src --commit-or-branch 7f643da16813af4c0fbaad4837cd7409386cf38c

run-sp1-loop1-f3326e6:
	$(UV_RUN) sp1-fuzzer run --seed 123 --out ./output --zkvm ./sp1-src --commit-or-branch f3326e6d0bf78d6b4650ea1e26c501d72fb3c90b

run-sp1-loop1-811a3f2:
	$(UV_RUN) sp1-fuzzer run --seed 123 --out ./output --zkvm ./sp1-src --commit-or-branch 811a3f2c03914088c7c9e1774266934a3f9f5359

install-risc0: $(VIRTUALENV)
	uv sync --package risc0-fuzzer
	# NOTE: The install step will reset/clean the repo at the given path.
	$(UV_RUN) risc0-fuzzer install ./risc0-src --commit-or-branch ebd64e43e7d953e0edcee2d4e0225b75458d80b5

run-risc0-loop1:
	$(UV_RUN) risc0-fuzzer run --seed 123 --out ./output --zkvm ./risc0-src --commit-or-branch all

install-pico: $(VIRTUALENV)
	uv sync --package pico-fuzzer
	# NOTE: The install step will reset/clean the repo at the given path.
	$(UV_RUN) pico-fuzzer install ./pico-src --commit-or-branch dd5b7d1f4e164d289d110f1688509a22af6b241c

run-pico-loop1:
	$(UV_RUN) pico-fuzzer run --seed 123 --out ./output --zkvm ./pico-src --commit-or-branch all

install-jolt: $(VIRTUALENV)
	uv sync --package jolt-fuzzer
	# NOTE: The install step will reset/clean the repo at the given path.
	$(UV_RUN) jolt-fuzzer install ./jolt-src --commit-or-branch main

run-jolt-loop1:
	$(UV_RUN) jolt-fuzzer run --seed 123 --out ./output --zkvm ./jolt-src --commit-or-branch all

install-nexus: $(VIRTUALENV)
	uv sync --package nexus-fuzzer
	# NOTE: The install step will reset/clean the repo at the given path.
	$(UV_RUN) nexus-fuzzer install ./nexus-src --commit-or-branch main

run-nexus-loop1:
	$(UV_RUN) nexus-fuzzer run --seed 123 --out ./output --zkvm ./nexus-src --commit-or-branch all

docker-build:
	docker build -t openvm-fuzzer -f projects/openvm-fuzzer/Dockerfile .

fuzz-start: docker-build
	chmod +x run_parallel.sh
	./run_parallel.sh

fuzz-stop:
	docker ps -a --filter "name=beak_worker_" -q | xargs -r docker rm -f
	@echo "All fuzzing workers stopped."

fuzz-logs:
	docker logs -f beak_worker_1

$(PYRIGHTCONFIG):
	@echo "Generating $(PYRIGHTCONFIG) for pyright ..."
	echo '{'                                  >  $(PYRIGHTCONFIG)
	echo '    "extraPaths" : ['               >> $(PYRIGHTCONFIG)
	echo '        "./libs/circil",'           >> $(PYRIGHTCONFIG)
	echo '        "./libs/zkvm-fuzzer-utils",' >> $(PYRIGHTCONFIG)
	echo '        "./libs/beak-core"'         >> $(PYRIGHTCONFIG)
	echo '    ]'                              >> $(PYRIGHTCONFIG)
	echo '}'                                  >> $(PYRIGHTCONFIG)

ship: format check test

check: $(PYRIGHTCONFIG)
	$(BLACK) --check .
	$(FLAKE8) .
	$(ISORT) --check-only .
	$(PYRIGHT) .

format:
	$(BLACK) .
	$(ISORT) .

test:
	FUZZER_TEST=1 $(PYTEST) -v

kill-all-fuzzer:
	killall python3 -9; killall cargo -9
