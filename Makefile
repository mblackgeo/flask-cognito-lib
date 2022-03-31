help:
	@fgrep -h "##" $(MAKEFILE_LIST) | fgrep -v fgrep | sed -e 's/\\$$//' | sed -e 's/##//'

.PHONY: install
install:  ## Create a new environment with poetry and install with pre-commit hooks
	poetry install
	pre-commit install --hook-type commit-msg

.PHONY: test
test:  ## Run the test suite using pytest
	poetry run pytest --cov flask_cognito_lib --cov-report term-missing --cov-report=xml

.PHONY: lint
lint:  ## Run linting checks with flake8, isort, and black
	poetry run flake8 .
	poetry run black --check .
	poetry run isort -c .

.PHONY: format
format:  ## Run black and isort to format the code
	poetry run black .
	poetry run isort .

.PHONY: example
example:  ## Run the example application locally
	poetry run python example/app.py

.PHONY: docs
docs:  ## Run mkdocs locally
	poetry run mkdocs serve

.PHONY: build-docs
build-docs:  ## Build the docs
	poetry run mkdocs build --strict

.PHONY: test-release
test-release:  ## Build the package and release to test-PyPI
	poetry config repositories.testpypi https://test.pypi.org/legacy/
	poetry publish --build -r testpypi

.PHONY: release
release:  ## Build the package and release to PyPI
	poetry publish