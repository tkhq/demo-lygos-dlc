HOST ?= 127.0.0.1
PORT ?= 44020
LOCAL_ENCLAVE_DIR ?= /tmp/tvc-template-local-enclave
EPHEMERAL_FILE ?= $(LOCAL_ENCLAVE_DIR)/qos.ephemeral.key
QUORUM_FILE ?= $(LOCAL_ENCLAVE_DIR)/qos.quorum.key

.PHONY: all
all: build

.PHONY: build
build:
	cargo build --all

.PHONY: test
test: build
	cargo test --all-targets

.PHONY: fmt
fmt:
	cargo fmt

.PHONY: lint
lint:
	cargo clippy --version
	cargo clippy --all-targets -- -D warnings

# Generate keys to simulate QOS control.
.PHONY: local-keys
local-keys:
	mkdir -p $(LOCAL_ENCLAVE_DIR)
	test -f $(EPHEMERAL_FILE) || openssl rand -hex 32 > $(EPHEMERAL_FILE)
	test -f $(QUORUM_FILE) || openssl rand -hex 32 > $(QUORUM_FILE)

.PHONY: run
run: local-keys
	cargo run --bin dlc-verify -- \
	--host $(HOST) \
	--port $(PORT) \
	--ephemeral-file $(EPHEMERAL_FILE) \
	--quorum-file $(QUORUM_FILE)

out/dlc-verify/index.json: \
	Cargo.lock Cargo.toml rust-toolchain.toml $(shell find images/dlc-verify crates -type f ! -path '*/target/*')
	$(call build,dlc-verify)

define build_context
$$( \
	mkdir -p out; \
	self=$(1); \
	for each in $$(find out/ -maxdepth 2 -name index.json); do \
    	package=$$(basename $$(dirname $${each})); \
    	if [ "$${package}" = "$${self}" ]; then continue; fi; \
    	printf -- ' --build-context %s=oci-layout://./out/%s' "$${package}" "$${package}"; \
	done; \
)
endef

,:=,
define build
	$(eval NAME := $(1))
	$(eval TYPE := $(if $(2),$(2),dir))
	$(eval REGISTRY := tkhq-tvc-dlc-verify)
	$(eval PLATFORM := linux/amd64)
	DOCKER_BUILDKIT=1 \
	SOURCE_DATE_EPOCH=1 \
	BUILDKIT_MULTIPLATFORM=1 \
	docker build \
		--build-arg VERSION=$(VERSION) \
		--tag $(REGISTRY)/$(NAME) \
		--progress=plain \
		--platform=$(PLATFORM) \
		--label "org.opencontainers.image.source=https://github.com/tkhq/lygos-dlc-demo" \
		$(if $(filter common,$(NAME)),,$(call build_context,$(1))) \
		$(if $(filter 1,$(NOCACHE)),--no-cache) \
		--output "\
			type=oci,\
			$(if $(filter dir,$(TYPE)),tar=false$(,)) \
			rewrite-timestamp=true,\
			force-compression=true,\
			name=$(NAME),\
			$(if $(filter tar,$(TYPE)),dest=$@") \
			$(if $(filter dir,$(TYPE)),dest=out/$(NAME)") \
		-f images/$(NAME)/Containerfile \
		.
endef
