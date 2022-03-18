help:
	@fgrep -h "##" $(MAKEFILE_LIST) | fgrep -v fgrep | sed -e 's/\\$$//' | sed -e 's/##//'

install:  ## Create a new environment with poetry and install with pre-commit hooks
	poetry install
	pre-commit install

test:  ## Run the test suite using pytest
	poetry run pytest --cov flask_cognito_lib

lint:  ## Run linting checks with flake8, isort, and black
	poetry run flake8 .
	poetry run black --check .
	poetry run isort -c .

format:  ## Run black and isort to format the code
	poetry run black .
	poetry run isort .
