# ---------------------------------------------------------------------------- #
#                                 Project Files                                #
# ---------------------------------------------------------------------------- #

ROOT=$(shell pwd)
VIRTUALENV=$(ROOT)/.venv
PYTHON=$(VIRTUALENV)/bin/python3
BLACK=$(VIRTUALENV)/bin/black
FLAKE8=$(VIRTUALENV)/bin/flake8
ISORT=$(VIRTUALENV)/bin/isort
PYRIGHT=$(VIRTUALENV)/bin/pyright
PYTEST=$(VIRTUALENV)/bin/pytest
PYRIGHTCONFIG=$(ROOT)/pyrightconfig.json

# ---------------------------------------------------------------------------- #
#                                Command Section                               #
# ---------------------------------------------------------------------------- #

.PHONY: check clean format install ship test venv

$(VIRTUALENV):
	python3 -m venv $(VIRTUALENV)

$(PYTHON):
	python3 -m venv $(VIRTUALENV)

$(BLACK): $(PYTHON)
	make install-dev

$(FLAKE8): $(PYTHON)
	make install-dev

$(ISORT): $(PYTHON)
	make install-dev

$(PYRIGHT): $(PYTHON)
	make install-dev

$(PYTEST): $(PYTHON)
	make install-dev

$(PYRIGHTCONFIG):
	@echo "Generating $(PYRIGHTCONFIG) for pyright ..."
	echo '{'                                  >  $(PYRIGHTCONFIG)
	echo '    "extraPaths" : ['               >> $(PYRIGHTCONFIG)
	echo '        "./libs/circil",'           >> $(PYRIGHTCONFIG)
	echo '        "./libs/zkvm-fuzzer-utils"' >> $(PYRIGHTCONFIG)
	echo '    ]'                              >> $(PYRIGHTCONFIG)
	echo '}'                                  >> $(PYRIGHTCONFIG)

venv: $(VIRTUALENV)

clean:
	rm -rf $(VIRTUALENV) $(PYRIGHTCONFIG)

install-dev: $(PYTHON) $(PYRIGHTCONFIG)
	$(PYTHON) -m pip install -r pip-requirements.txt
	$(PYTHON) -m pip install -r dev-requirements.txt

install-fuzzer-dependencies: $(PYTHON)
	cd libs/zkvm-fuzzer-utils && $(PYTHON) -m pip install -r requirements.txt
	cd projects/nexus-fuzzer && $(PYTHON) -m pip install -r requirements.txt
	cd projects/jolt-fuzzer && $(PYTHON) -m pip install -r requirements.txt
	cd projects/risc0-fuzzer && $(PYTHON) -m pip install -r requirements.txt
	cd projects/sp1-fuzzer && $(PYTHON) -m pip install -r requirements.txt
	cd projects/openvm-fuzzer && $(PYTHON) -m pip install -r requirements.txt
	cd projects/pico-fuzzer && $(PYTHON) -m pip install -r requirements.txt

install-plotting-helpers: $(PYTHON)
	cd scripts && $(PYTHON) -m pip install -r requirements.txt

install: install-dev install-fuzzer-dependencies install-plotting-helpers

ship: format check test

check: $(BLACK) $(FLAKE8) $(ISORT) $(PYRIGHT) $(PYRIGHTCONFIG)
	$(BLACK) --check .
	$(FLAKE8) .
	$(ISORT) --check-only .
	$(PYRIGHT) .

format: $(BLACK) $(ISORT)
	$(BLACK) .
	$(ISORT) .

test: $(PYTEST)
	FUZZER_TEST=1 $(PYTEST) -v

kill-all-fuzzer:
	killall python3 -9; killall podman -9; killall r0vm -9; killall cargo -9

stop-all-fuzzer:
	podman stop --all

# ---------------------------------------------------------------------------- #
#                                  Experiments                                 #
# ---------------------------------------------------------------------------- #

# ---------------------------------- Explore --------------------------------- #

.tmux-all-explore-template:
	tmux new-window -n "$(ZKVM_TARGET)-explore-default" 'bash -c "make $(ZKVM_TARGET)-explore-default"; exec bash'
	tmux new-window -n "$(ZKVM_TARGET)-explore-no-inline" 'bash -c "make $(ZKVM_TARGET)-explore-no-inline"; exec bash'
	tmux new-window -n "$(ZKVM_TARGET)-explore-no-schedular" 'bash -c "make $(ZKVM_TARGET)-explore-no-schedular"; exec bash'
	tmux new-window -n "$(ZKVM_TARGET)-explore-no-modification" 'bash -c "make $(ZKVM_TARGET)-explore-no-modification"; exec bash'

tmux-all-explore:
	$(MAKE) .tmux-all-explore-template ZKVM_TARGET=jolt
	$(MAKE) .tmux-all-explore-template ZKVM_TARGET=nexus
	$(MAKE) .tmux-all-explore-template ZKVM_TARGET=openvm
	$(MAKE) .tmux-all-explore-template ZKVM_TARGET=pico
	$(MAKE) .tmux-all-explore-template ZKVM_TARGET=risc0
	$(MAKE) .tmux-all-explore-template ZKVM_TARGET=sp1

# ---------------------------------- Refind ---------------------------------- #

.tmux-all-refind-template:
	tmux new-window -n "$(ZKVM_TARGET)-refind-default" 'bash -c "make $(ZKVM_TARGET)-refind-default"; exec bash'
	tmux new-window -n "$(ZKVM_TARGET)-refind-no-inline" 'bash -c "make $(ZKVM_TARGET)-refind-no-inline"; exec bash'
	tmux new-window -n "$(ZKVM_TARGET)-refind-no-schedular" 'bash -c "make $(ZKVM_TARGET)-refind-no-schedular"; exec bash'
	tmux new-window -n "$(ZKVM_TARGET)-refind-no-modification" 'bash -c "make $(ZKVM_TARGET)-refind-no-modification"; exec bash'

tmux-refind-default:
	tmux new-window -n "jolt-refind-default" 'bash -c "make jolt-refind-default"; exec bash'
	tmux new-window -n "nexus-refind-default" 'bash -c "make nexus-refind-default"; exec bash'
	tmux new-window -n "risc0-refind-default" 'bash -c "make risc0-refind-default"; exec bash'

tmux-refind-no-modification:
	tmux new-window -n "jolt-refind-no-modification" 'bash -c "make jolt-refind-no-modification"; exec bash'
	tmux new-window -n "nexus-refind-no-modification" 'bash -c "make nexus-refind-no-modification"; exec bash'
	tmux new-window -n "risc0-refind-no-modification" 'bash -c "make risc0-refind-no-modification"; exec bash'

tmux-all-refind:
	$(MAKE) .tmux-all-refind-template ZKVM_TARGET=jolt
	$(MAKE) .tmux-all-refind-template ZKVM_TARGET=nexus
	$(MAKE) .tmux-all-refind-template ZKVM_TARGET=risc0

tmux-jolt-all-refind:
	$(MAKE) .tmux-all-refind-template ZKVM_TARGET=jolt

tmux-nexus-all-refind:
	$(MAKE) .tmux-all-refind-template ZKVM_TARGET=nexus

tmux-risc0-all-refind:
	$(MAKE) .tmux-all-refind-template ZKVM_TARGET=risc0

# ---------------------------------- Check ---------------------------------- #

.tmux-all-check-template:
	tmux new-window -n "jolt-check-default" 'bash -c "make $(ZKVM_TARGET)-check-default"; exec bash'
	tmux new-window -n "jolt-check-no-inline" 'bash -c "make $(ZKVM_TARGET)-check-no-inline"; exec bash'
	tmux new-window -n "jolt-check-no-schedular" 'bash -c "make $(ZKVM_TARGET)-check-no-schedular"; exec bash'
	tmux new-window -n "jolt-check-no-modification" 'bash -c "make $(ZKVM_TARGET)-check-no-modification"; exec bash'

tmux-all-check:
	$(MAKE) .tmux-all-check-template ZKVM_TARGET=jolt
	$(MAKE) .tmux-all-check-template ZKVM_TARGET=nexus
	$(MAKE) .tmux-all-check-template ZKVM_TARGET=risc0

tmux-check-default:
	tmux new-window -n "jolt-check-default" 'bash -c "make jolt-check-default"; exec bash'
	tmux new-window -n "nexus-check-default" 'bash -c "make nexus-check-default"; exec bash'
	tmux new-window -n "risc0-check-default" 'bash -c "make risc0-check-default"; exec bash'

tmux-check-no-modification:
	tmux new-window -n "jolt-check-no-modification" 'bash -c "make jolt-check-no-modification"; exec bash'
	tmux new-window -n "nexus-check-no-modification" 'bash -c "make nexus-check-no-modification"; exec bash'
	tmux new-window -n "risc0-check-no-modification" 'bash -c "make risc0-check-no-modification"; exec bash'

tmux-jolt-all-check:
	$(MAKE) .tmux-all-check-template ZKVM_TARGET=jolt

tmux-nexus-all-check:
	$(MAKE) .tmux-all-check-template ZKVM_TARGET=nexus

tmux-risc0-all-check:
	$(MAKE) .tmux-all-check-template ZKVM_TARGET=risc0

# ---------------------------------------------------------------------------- #
#                              Generic ZKVM Control                            #
# ---------------------------------------------------------------------------- #

.zkvm-explore-default:
	NAMESPACE_POSTFIX="-explore-default" \
	./projects/$(ZKVM_TARGET)-fuzzer/scripts/explore.sh

.zkvm-explore-no-inline:
	NAMESPACE_POSTFIX="-explore-no-inline" \
	NO_INLINE_ASSEMBLY=true \
	./projects/$(ZKVM_TARGET)-fuzzer/scripts/explore.sh

.zkvm-explore-no-schedular:
	NAMESPACE_POSTFIX="-explore-no-schedular" \
	NO_SCHEDULAR=true \
	./projects/$(ZKVM_TARGET)-fuzzer/scripts/explore.sh

.zkvm-explore-no-modification:
	NAMESPACE_POSTFIX="-explore-no-modification" \
	TRACE_COLLECTION=false \
	FAULT_INJECTION=false \
	ZKVM_MODIFICATION=false \
	./projects/$(ZKVM_TARGET)-fuzzer/scripts/explore.sh

.zkvm-refind-default:
	NAMESPACE_POSTFIX="-refind-default" \
	./projects/$(ZKVM_TARGET)-fuzzer/scripts/refind.sh

.zkvm-check-default:
	NAMESPACE_POSTFIX="-check-default" \
	FINDINGS_NAMESPACE_POSTFIX="-refind-default" \
	./projects/$(ZKVM_TARGET)-fuzzer/scripts/check.sh

.zkvm-refind-no-schedular:
	NAMESPACE_POSTFIX="-refind-no-schedular" \
	NO_SCHEDULAR=true \
	./projects/$(ZKVM_TARGET)-fuzzer/scripts/refind.sh

.zkvm-check-no-schedular:
	NAMESPACE_POSTFIX="-check-no-schedular" \
	NO_SCHEDULAR=true \
	FINDINGS_NAMESPACE_POSTFIX="-refind-no-schedular" \
	./projects/$(ZKVM_TARGET)-fuzzer/scripts/check.sh

.zkvm-refind-no-inline:
	NAMESPACE_POSTFIX="-refind-no-inline" \
	NO_INLINE_ASSEMBLY=true \
	./projects/$(ZKVM_TARGET)-fuzzer/scripts/refind.sh

.zkvm-check-no-inline:
	NAMESPACE_POSTFIX="-check-no-inline" \
	NO_INLINE_ASSEMBLY=true \
	FINDINGS_NAMESPACE_POSTFIX="-refind-no-inline" \
	./projects/$(ZKVM_TARGET)-fuzzer/scripts/check.sh

.zkvm-refind-no-modification:
	NAMESPACE_POSTFIX="-refind-no-modification" \
	TRACE_COLLECTION=false \
	FAULT_INJECTION=false \
	ZKVM_MODIFICATION=false \
	./projects/$(ZKVM_TARGET)-fuzzer/scripts/refind.sh

.zkvm-check-no-modification:
	NAMESPACE_POSTFIX="-check-no-modification" \
	TRACE_COLLECTION=false \
	FAULT_INJECTION=false \
	ZKVM_MODIFICATION=false \
	FINDINGS_NAMESPACE_POSTFIX="-refind-no-modification" \
	./projects/$(ZKVM_TARGET)-fuzzer/scripts/check.sh

# ---------------------------------------------------------------------------- #
#                                 Risc0 Control                                #
# ---------------------------------------------------------------------------- #

risc0-explore-default:
	$(MAKE) .zkvm-explore-default ZKVM_TARGET=risc0

risc0-explore-no-inline:
	$(MAKE) .zkvm-explore-no-inline ZKVM_TARGET=risc0

risc0-explore-no-schedular:
	$(MAKE) .zkvm-explore-no-schedular ZKVM_TARGET=risc0

risc0-explore-no-modification:
	$(MAKE) .zkvm-explore-no-modification ZKVM_TARGET=risc0

risc0-refind-default:
	$(MAKE) .zkvm-refind-default ZKVM_TARGET=risc0

risc0-check-default:
	$(MAKE) .zkvm-check-default ZKVM_TARGET=risc0

risc0-refind-no-schedular:
	$(MAKE) .zkvm-refind-no-schedular ZKVM_TARGET=risc0

risc0-check-no-schedular:
	$(MAKE) .zkvm-check-no-schedular ZKVM_TARGET=risc0

risc0-refind-no-inline:
	$(MAKE) .zkvm-refind-no-inline ZKVM_TARGET=risc0

risc0-check-no-inline:
	$(MAKE) .zkvm-check-no-inline ZKVM_TARGET=risc0

risc0-refind-no-modification:
	$(MAKE) .zkvm-refind-no-modification ZKVM_TARGET=risc0

risc0-check-no-modification:
	$(MAKE) .zkvm-check-no-modification ZKVM_TARGET=risc0

# ---------------------------------------------------------------------------- #
#                                 Nexus Control                                #
# ---------------------------------------------------------------------------- #

nexus-explore-default:
	$(MAKE) .zkvm-explore-default ZKVM_TARGET=nexus

nexus-explore-no-inline:
	$(MAKE) .zkvm-explore-no-inline ZKVM_TARGET=nexus

nexus-explore-no-schedular:
	$(MAKE) .zkvm-explore-no-schedular ZKVM_TARGET=nexus

nexus-explore-no-modification:
	$(MAKE) .zkvm-explore-no-modification ZKVM_TARGET=nexus

nexus-refind-default:
	$(MAKE) .zkvm-refind-default ZKVM_TARGET=nexus

nexus-check-default:
	$(MAKE) .zkvm-check-default ZKVM_TARGET=nexus

nexus-refind-no-schedular:
	$(MAKE) .zkvm-refind-no-schedular ZKVM_TARGET=nexus

nexus-check-no-schedular:
	$(MAKE) .zkvm-check-no-schedular ZKVM_TARGET=nexus

nexus-refind-no-inline:
	$(MAKE) .zkvm-refind-no-inline ZKVM_TARGET=nexus

nexus-check-no-inline:
	$(MAKE) .zkvm-check-no-inline ZKVM_TARGET=nexus

nexus-refind-no-modification:
	$(MAKE) .zkvm-refind-no-modification ZKVM_TARGET=nexus

nexus-check-no-modification:
	$(MAKE) .zkvm-check-no-modification ZKVM_TARGET=nexus

# ---------------------------------------------------------------------------- #
#                                  SP1 Control                                 #
# ---------------------------------------------------------------------------- #

sp1-explore-default:
	$(MAKE) .zkvm-explore-default ZKVM_TARGET=sp1

sp1-explore-no-inline:
	$(MAKE) .zkvm-explore-no-inline ZKVM_TARGET=sp1

sp1-explore-no-schedular:
	$(MAKE) .zkvm-explore-no-schedular ZKVM_TARGET=sp1

sp1-explore-no-modification:
	$(MAKE) .zkvm-explore-no-modification ZKVM_TARGET=sp1

# ---------------------------------------------------------------------------- #
#                                 Jolt Control                                 #
# ---------------------------------------------------------------------------- #

jolt-explore-default:
	$(MAKE) .zkvm-explore-default ZKVM_TARGET=jolt

jolt-explore-no-inline:
	$(MAKE) .zkvm-explore-no-inline ZKVM_TARGET=jolt

jolt-explore-no-schedular:
	$(MAKE) .zkvm-explore-no-schedular ZKVM_TARGET=jolt

jolt-explore-no-modification:
	$(MAKE) .zkvm-explore-no-modification ZKVM_TARGET=jolt

jolt-refind-default:
	$(MAKE) .zkvm-refind-default ZKVM_TARGET=jolt

jolt-check-default:
	$(MAKE) .zkvm-check-default ZKVM_TARGET=jolt

jolt-refind-no-schedular:
	$(MAKE) .zkvm-refind-no-schedular ZKVM_TARGET=jolt

jolt-check-no-schedular:
	$(MAKE) .zkvm-check-no-schedular ZKVM_TARGET=jolt

jolt-refind-no-inline:
	$(MAKE) .zkvm-refind-no-inline ZKVM_TARGET=jolt

jolt-check-no-inline:
	$(MAKE) .zkvm-check-no-inline ZKVM_TARGET=jolt

jolt-refind-no-modification:
	$(MAKE) .zkvm-refind-no-modification ZKVM_TARGET=jolt

jolt-check-no-modification:
	$(MAKE) .zkvm-check-no-modification ZKVM_TARGET=jolt

# ---------------------------------------------------------------------------- #
#                                OpenVM Control                                #
# ---------------------------------------------------------------------------- #

openvm-explore-default:
	$(MAKE) .zkvm-explore-default ZKVM_TARGET=openvm

openvm-explore-no-inline:
	$(MAKE) .zkvm-explore-no-inline ZKVM_TARGET=openvm

openvm-explore-no-schedular:
	$(MAKE) .zkvm-explore-no-schedular ZKVM_TARGET=openvm

openvm-explore-no-modification:
	$(MAKE) .zkvm-explore-no-modification ZKVM_TARGET=openvm

# ---------------------------------------------------------------------------- #
#                                Pico Control                                  #
# ---------------------------------------------------------------------------- #

pico-explore-default:
	$(MAKE) .zkvm-explore-default ZKVM_TARGET=pico

pico-explore-no-inline:
	$(MAKE) .zkvm-explore-no-inline ZKVM_TARGET=pico

pico-explore-no-schedular:
	$(MAKE) .zkvm-explore-no-schedular ZKVM_TARGET=pico

pico-explore-no-modification:
	$(MAKE) .zkvm-explore-no-modification ZKVM_TARGET=pico
