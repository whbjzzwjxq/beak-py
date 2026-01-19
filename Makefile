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

.PHONY: check clean format install ship test venv install-openvm run-openvm-loop1 install-sp1 run-sp1-loop1 install-risc0 run-risc0-loop1 \
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

install-risc0: $(VIRTUALENV)
	uv sync --package risc0-fuzzer
	# NOTE: The install step will reset/clean the repo at the given path.
	$(UV_RUN) risc0-fuzzer install ./risc0-src --commit-or-branch ebd64e43e7d953e0edcee2d4e0225b75458d80b5

run-risc0-loop1:
	$(UV_RUN) risc0-fuzzer run --seed 123 --out ./output --zkvm ./risc0-src --commit-or-branch all

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
