# Deception Shield
#
# `make help` lists every target. Targets are grouped by the layer they act on:
# infrastructure, the sensor stack, and the analysis toolkit.

SHELL := /bin/bash
.DEFAULT_GOAL := help

TERRAFORM_DIR := infra/terraform
ANALYSIS_DIR  := analysis
STACK_DIR     := stack
VENV          := $(ANALYSIS_DIR)/.venv
PYTHON        := $(VENV)/bin/python
PIP           := $(VENV)/bin/pip

.PHONY: help
help: ## List the available targets
	@grep -hE '^[a-zA-Z_-]+:.*?## ' $(MAKEFILE_LIST) \
		| awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-22s\033[0m %s\n", $$1, $$2}'

# --------------------------------------------------------------- infrastructure
.PHONY: tf-init
tf-init: ## Initialise the Terraform working directory
	cd $(TERRAFORM_DIR) && terraform init

.PHONY: tf-validate
tf-validate: ## Check the Terraform configuration
	cd $(TERRAFORM_DIR) && terraform fmt -check -recursive && terraform validate

.PHONY: tf-plan
tf-plan: ## Show what applying would change
	cd $(TERRAFORM_DIR) && terraform plan -out=tfplan

.PHONY: tf-apply
tf-apply: ## Deploy the sensor network
	cd $(TERRAFORM_DIR) && terraform apply tfplan

.PHONY: tf-destroy
tf-destroy: ## Tear the sensor network down
	cd $(TERRAFORM_DIR) && terraform destroy

.PHONY: inventory
inventory: ## Write ansible/inventory.ini from the Terraform outputs
	cd $(TERRAFORM_DIR) && terraform output -raw ansible_inventory > ../../ansible/inventory.ini
	@echo "wrote ansible/inventory.ini"

# ----------------------------------------------------------------- provisioning
.PHONY: provision
provision: ## Run the Ansible playbook against every sensor
	cd ansible && ansible-playbook site.yml

.PHONY: provision-check
provision-check: ## Dry run the playbook
	cd ansible && ansible-playbook site.yml --check --diff

.PHONY: ping
ping: ## Confirm Ansible can reach the sensors
	cd ansible && ansible sensors -m ping

# ------------------------------------------------------------------------ stack
.PHONY: stack-up
stack-up: ## Start the full sensor stack locally
	cd $(STACK_DIR) && docker compose --profile all up -d

.PHONY: analysis-up
analysis-up: ## Start only Elasticsearch, Logstash and Kibana
	cd $(STACK_DIR) && docker compose --profile analysis up -d

.PHONY: stack-down
stack-down: ## Stop the stack, keeping volumes
	cd $(STACK_DIR) && docker compose --profile all down

.PHONY: stack-logs
stack-logs: ## Follow the stack logs
	cd $(STACK_DIR) && docker compose --profile all logs -f --tail=100

.PHONY: stack-config
stack-config: ## Validate the compose definition
	cd $(STACK_DIR) && docker compose config --quiet && echo "compose configuration is valid"

.PHONY: dashboards
dashboards: ## Import the Kibana saved objects
	./scripts/load-dashboards.sh

.PHONY: templates
templates: ## Apply the index templates and ILM policies
	./scripts/apply-templates.sh

# --------------------------------------------------------------------- analysis
$(VENV):
	python3 -m venv $(VENV)
	$(PIP) install --quiet --upgrade pip

.PHONY: install
install: $(VENV) ## Install the analysis toolkit with its development extras
	$(PIP) install --quiet -e "$(ANALYSIS_DIR)[dev]"
	@echo "installed; run '$(PYTHON) -m deception_shield.cli --help'"

.PHONY: test
test: $(VENV) ## Run the test suite
	$(PIP) install --quiet pytest pytest-cov
	cd $(ANALYSIS_DIR) && .venv/bin/python -m pytest tests/ -q

.PHONY: coverage
coverage: $(VENV) ## Run the test suite with a coverage report
	$(PIP) install --quiet pytest pytest-cov
	cd $(ANALYSIS_DIR) && .venv/bin/python -m pytest tests/ -q \
		--cov=deception_shield --cov-report=term-missing

.PHONY: replay
replay: ## Dissect a capture and print a report: make replay CAPTURE=path.pcap
	@test -n "$(CAPTURE)" || { echo "usage: make replay CAPTURE=path/to/file.pcap"; exit 2; }
	cd $(ANALYSIS_DIR) && .venv/bin/python -m deception_shield.cli replay "$(CURDIR)/$(CAPTURE)"

.PHONY: report
report: ## Generate a report from indexed telemetry
	cd $(ANALYSIS_DIR) && .venv/bin/python -m deception_shield.cli analyse \
		--since $${SINCE:-24h} --format $${FORMAT:-markdown}

# ------------------------------------------------------------------------ checks
.PHONY: validate
validate: stack-config ## Validate every configuration file in the repository
	@echo "--- JSON ---"
	@for f in $$(find stack -name '*.json'); do \
		jq -e . "$$f" > /dev/null && echo "ok   $$f" || exit 1; done
	@echo "--- NDJSON ---"
	@while IFS= read -r line; do echo "$$line" | jq -e . > /dev/null || exit 1; done \
		< stack/kibana/dashboards/deception-shield-overview.ndjson
	@echo "ok   kibana saved objects"
	@echo "--- YAML ---"
	@python3 -c "import yaml,glob,sys; \
		[list(yaml.safe_load_all(open(f))) for f in glob.glob('ansible/**/*.yml', recursive=True)]; \
		print('ok   ansible playbooks')"
	@echo "--- shell ---"
	@bash -n capture/capture.sh && echo "ok   capture/capture.sh"
	@for f in scripts/*.sh; do bash -n "$$f" && echo "ok   $$f"; done

.PHONY: clean
clean: ## Remove build artefacts and the virtualenv
	rm -rf $(VENV) $(ANALYSIS_DIR)/.pytest_cache $(ANALYSIS_DIR)/*.egg-info
	find . -type d -name __pycache__ -prune -exec rm -rf {} +
	find . -type d -name .coverage -prune -exec rm -rf {} +
