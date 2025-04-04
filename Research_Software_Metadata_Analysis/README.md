# Research Software Metadata Analyzer (RSMA)

RSMA is a command-line tool designed to analyze software metadata files within GitHub repositories. It currently focuses on fetching and analyzing `codemeta.json` files to assess their presence, validity against the official schema, and completeness based on the CodeMeta standard.

The tool processes a list of repositories provided via CSV, fetches repository details and the `codemeta.json` file using the GitHub API, parses the file content, validates its structure, and performs completeness analysis. Results are saved in both detailed JSON Lines format and a flattened CSV format suitable for broader analysis.

## Features

* Analyzes `codemeta.json` files in specified GitHub repositories.
* Fetches relevant repository metadata (stars, forks, language, license, dates, description, etc.).
* Parses `codemeta.json` content.
* Validates `codemeta.json` against the official v3.0.0 JSON Schema (can be skipped).
* Performs two levels of completeness analysis:
  * **Basic:** Checks for a core set of recommended CodeMeta fields.
  * **Comprehensive:** Checks for core fields plus a wider range of extended CodeMeta fields.
* Outputs detailed results in JSON Lines (`.jsonl`) format.
* Outputs flattened, analysis-ready results in CSV (`.csv`) format.
* Configurable logging levels for debugging.
* Handles GitHub API rate limits gracefully (logs remaining requests and reset times).

## Prerequisites

* **Python:** Version 3.9 or higher recommended (as specified in `pyproject.toml`).
* **GitHub Personal Access Token (PAT):** Required to interact with the GitHub API and avoid strict rate limiting. The token needs appropriate permissions (e.g., `public_repo` for public repositories). See [GitHub Docs: Creating a personal access token](https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/creating-a-personal-access-token).
* **Input CSV File:** A CSV file containing the list of repositories to analyze. It must have a header row with a column named `repo_full_name` (case-insensitive) containing entries like `owner/repository_name`. Invalid formats or empty rows will be skipped.

## Installation

1. **Clone the repository:**
   ```bash
   # Replace 'your-username/rsma' with the actual repository URL
   git clone https://github.com/your-username/rsma.git
   cd rsma
   ```

2. **Create and activate a virtual environment (recommended):**
   ```bash
   # Ensure you have Python 3.9+ available
   python3 -m venv venv
   source venv/bin/activate  # On Windows use `venv\Scripts\activate`
   ```

3. **Install dependencies:**
   The project uses `pyproject.toml` for dependency management. Install the package and its dependencies using pip:
   ```bash
   # Ensure pip is up-to-date
   pip install --upgrade pip
   # Install the rsma package from the current directory
   pip install .
   ```
   Alternatively, for development purposes (installs in editable mode):
   ```bash
   # Installs the package such that changes in src/ are reflected without reinstalling
   # Also installs dependencies listed under [project.optional-dependencies] dev
   pip install -e .[dev]
   ```

## Configuration: GitHub Token

The tool requires a GitHub Personal Access Token (PAT) to interact with the GitHub API effectively.

1. **Create a `.env` file:** In the root directory of the project (the same directory as `pyproject.toml`), create a file named `.env`.
2. **Add your token:** Add the following line to the `.env` file, replacing `<YOUR_GITHUB_PAT>` with your actual GitHub Personal Access Token:
   ```dotenv
   GITHUB_TOKEN=<YOUR_GITHUB_PAT>
   ```
   **Security Note:** Ensure this `.env` file is listed in your project's `.gitignore` file to prevent accidentally committing your sensitive token to version control. A typical `.gitignore` entry would be simply `.env`.

The tool will automatically load the `GITHUB_TOKEN` from this `.env` file. Alternatively, the token can be set as an environment variable named `GITHUB_TOKEN` (which takes precedence over the `.env` file).

## Usage

Once installed, the tool provides a command-line script named `rsma` (defined in `pyproject.toml`).

```bash
rsma --input-csv <path/to/your/repos.csv> \
     --target-metadata-file codemeta.json \
     --output-jsonl <path/to/output/results.jsonl> \
     [--output-csv <path/to/output/results.csv>] \
     [--comprehensive] \
     [--skip-schema-validation] \
     [--verbose]
```

### Arguments:

* `--input-csv PATH` (Required): Path to the input CSV file listing repository full names under the repo_full_name header.
* `--target-metadata-file NAME` (Required): The metadata file to target. Currently must be codemeta.json.
* `--output-jsonl PATH` (Required): Path where the detailed JSON Lines output file will be saved. Directories will be created if they don't exist.
* `--output-csv PATH` (Optional): Path where the flattened CSV output file will be saved. Directories will be created if they don't exist.
* `--comprehensive` (Optional Flag): Perform comprehensive analysis (core + extended fields) instead of basic completeness checks. This adds more columns to the CSV output.
* `--skip-schema-validation` (Optional Flag): Disable the CodeMeta JSON schema validation step. Useful if the bundled schema causes issues or is not needed.
* `--verbose` or `-v` (Optional Flag): Enable verbose (DEBUG level) logging output for detailed progress and troubleshooting information.

### Example:

```bash
rsma --input-csv data/input_repositories.csv \
     --target-metadata-file codemeta.json \
     --output-jsonl results/analysis_details.jsonl \
     --output-csv results/analysis_summary.csv \
     --comprehensive \
     --verbose
```

(If you installed without using the script entry point, you can run it via `python -m rsma.cli ...` instead of `rsma ...`)

## Output Files

The tool generates one required output file (`.jsonl`) and one optional output file (`.csv`).

### JSON Lines (`.jsonl`) File: (Specified by `--output-jsonl`)

* Contains the full, detailed, nested results for each repository processed.
* Each line is a self-contained JSON object representing one repository's analysis.
* Structure per line includes:
  * `repo_full_name`: (String) The repository name (owner/repo).
  * `repo_metadata`: (Object|Null) A dictionary containing metadata fetched from GitHub API (description, stars, forks, dates, language, license details, topics, etc.), or null if the repository fetch failed.
  * `repo_metadata_error`: (String|Null) An error message if fetching repository metadata failed or if errors occurred during file processing, otherwise null.
  * `metadata_files`: (Object) A dictionary where the key is the `target_metadata_file` (e.g., `codemeta.json`). The value is an object containing:
    * `fetch_status`: (String) Status of fetching the target file: 'found', 'not_found', 'error', 'skipped'.
    * `fetch_error`: (String|Null) Error message if `fetch_status` is 'error' or 'skipped'.
    * `parse_status`: (Boolean|Null) true if parsing succeeded, false if failed, null if not attempted.
    * `parse_error`: (String|Null) Error message if parsing failed.
    * `completeness_score`: (Float|Null) The calculated basic completeness score (0.0-1.0).
    * `completeness_missing_keys`: (List[String]|Null) List of missing basic keys.
    * `schema_valid`: (Boolean|String|Null) true, false, "skipped", or null.
    * `schema_errors`: (List[String]|Null) List of validation error strings if invalid.
    * (If `--comprehensive`): Includes additional fields: `core_score`, `core_missing`, `extended_score`, `extended_missing`, `present_fields` (list), `present_fields_count` (int), `all_fields_count` (int).

### CSV (`.csv`) File: (Specified by `--output-csv`)

* Provides a flattened representation of the analysis results, suitable for spreadsheets or data analysis tools where each row corresponds to one repository.
* Columns include selected repository metadata fields, fetch status/error, parse status/error, schema validity/errors, completeness scores, and missing key lists (joined by ';').
* If `--comprehensive` is used, additional columns for core/extended scores, missing field lists, present field counts, and the list of present fields are included.
* Refer to `BASIC_CSV_FIELDNAMES` and `COMPREHENSIVE_CSV_FIELDNAMES` lists in `src/rsma/file_io.py` for the exact column headers in each mode.

## Development

To set up the project for development:

1. Follow the Installation steps, using `pip install -e .[dev]` to install in editable mode with development dependencies (like testing tools, linters).

2. Run unit tests using Python's unittest module:
   ```bash
   python -m unittest discover -s tests/ -v
   ```

3. Consider using pre-commit hooks for automated code formatting and linting before commits.
   * Install pre-commit: `pip install pre-commit`
   * Set up hooks (requires a `.pre-commit-config.yaml` file): `pre-commit install`

## License

This project is licensed under the MIT License - see the LICENSE file for details.