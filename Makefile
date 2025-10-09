help:
	@fgrep -h "##" $(MAKEFILE_LIST) | fgrep -v fgrep | sed -e 's/\\$$//' | sed -e 's/##//'

# Default virtual env location
UV_PROJECT_ENVIRONMENT ?= .venv
export UV_PROJECT_ENVIRONMENT

.PHONY: install
install:  ## Create a new environment with uv and install with pre-commit hooks
	uv sync --dev --all-extras --python 3.9  # lowest supported version

.PHONY: test
test:  ## Run the test suite using pytest with coverage
	uv run pytest --cov flask_cognito_lib --cov-report term-missing --cov-report=xml -ra -vv

.PHONY: lint
lint:  ## Run linting checks with ruff
	uv run ruff check .
	uv run ruff format --check .
	uv run mypy --check src/ tests/

.PHONY: format
format:  ## Run ruff to format the code
	uv run ruff check --fix .
	uv run ruff format .

.PHONY: example
example:  ## Run the example Flask app locally
	uv run python example/app.py

.PHONY: docs
docs:  ## Run mkdocs locally
	uv run mkdocs serve

.PHONY: build-docs
build-docs:  ## Build the mkdocs documentation
	uv run mkdocs build --strict

# Note - in most cases CI/CD will handle releases automatically
# These targets are for manual "break-glass" releases only
.PHONY: test-release
test-release:  ## Build & upload to TestPyPI (manual)
	uv build
	uv publish --publish-url https://test.pypi.org/legacy/ --token $${TEST_PYPI_TOKEN}

.PHONY: release
release:  ## Build & upload to PyPI (manual)
	uv build
	uv publish --publish-url https://upload.pypi.org/legacy/ --token $${PYPI_API_TOKEN}
