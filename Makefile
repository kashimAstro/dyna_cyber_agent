# dyna_cyber_agent - convenience wrapper around CMake.  `make help` lists the targets.
BUILD_DIR  ?= build
BUILD_TYPE ?= Release
PREFIX     ?= /usr/local
JOBS       ?= $(shell nproc 2>/dev/null || echo 2)
CONFIG     ?= config/agent.example.yaml
GENERATOR  ?= $(if $(shell command -v ninja 2>/dev/null),-G Ninja,)
BIN         = $(BUILD_DIR)/dyna_cyber_agent

CMAKE_FLAGS = -DCMAKE_BUILD_TYPE=$(BUILD_TYPE) -DCMAKE_INSTALL_PREFIX=$(PREFIX) $(CMAKE_EXTRA)

.DEFAULT_GOAL := build
.PHONY: help configure build debug test test-slow ui-check check install uninstall package version clean distclean

help: ## show this help
	@awk 'BEGIN{FS=":.*## "} /^[a-zA-Z_-]+:.*## /{printf "  make %-11s %s\n",$$1,$$2}' $(MAKEFILE_LIST)
	@echo ""
	@echo "Variables: BUILD_DIR=$(BUILD_DIR) BUILD_TYPE=$(BUILD_TYPE) PREFIX=$(PREFIX) JOBS=$(JOBS) CONFIG=$(CONFIG)"
	@echo "Missing libraries (yaml-cpp, nlohmann_json, Catch2) are fetched by CMake; spdlog, sqlite3, libcurl and zlib come from the system."

configure: ## run CMake (done automatically by build)
	cmake -S . -B $(BUILD_DIR) $(GENERATOR) $(CMAKE_FLAGS)

$(BUILD_DIR)/CMakeCache.txt:
	@$(MAKE) --no-print-directory configure

build: $(BUILD_DIR)/CMakeCache.txt ## compile the agent (and the tests)
	cmake --build $(BUILD_DIR) -j $(JOBS)
	@echo "built: $(BIN)"

debug: ## compile with debug info in build-debug/
	$(MAKE) --no-print-directory BUILD_DIR=build-debug BUILD_TYPE=Debug build

test: build ## run the test suite (fast: about 20 s, no network)
	cd $(BUILD_DIR) && ctest --output-on-failure

test-slow: build ## also run the slow tests
	$(BUILD_DIR)/tests/agent_tests "[.slow]"

ui-check: ## syntax-check the JavaScript of the web console (needs node)
	@command -v node >/dev/null || { echo "node not installed: skipped"; exit 0; }
	@python3 -I -c "import re;s=open('web/index.html').read().replace('/*WORLD_DATA*/',open('web/world_data.js').read());open('$(BUILD_DIR)/ui_check.js','w').write(re.search(r'<script>(.*)</script>',s,re.S).group(1))"
	@node --check $(BUILD_DIR)/ui_check.js && echo "web console JavaScript: ok"

check: build ## validate CONFIG and the rules (no collection, no network)
	$(BIN) --config $(CONFIG) --check

install: build ## install into PREFIX (default /usr/local); use DESTDIR for staging
	cmake --install $(BUILD_DIR)

uninstall: ## remove what `make install` installed
	@test -f $(BUILD_DIR)/install_manifest.txt || { echo "no install manifest: nothing to remove"; exit 1; }
	xargs -d '\n' rm -fv < $(BUILD_DIR)/install_manifest.txt

package: build ## build the .tar.gz and .deb packages in the build directory
	cd $(BUILD_DIR) && cpack

version: build ## print the version
	@$(BIN) --version

clean: ## remove compiled files, keep the CMake configuration
	-cmake --build $(BUILD_DIR) --target clean

distclean: ## remove the build directories
	rm -rf $(BUILD_DIR) build-debug
