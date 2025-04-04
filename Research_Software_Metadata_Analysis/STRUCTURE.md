# STRUCTURE.md
# Project File and Directory Structure: RSMA

This file outlines the file and directory structure of the Research Software Metadata Analyzer (RSMA) project.

rsma/
│
├── .gitignore             # Specifies intentionally untracked files that Git should ignore.
├── LICENSE                # Contains the full text of the project's license.
├── README.md              # Provides a comprehensive overview, installation, and usage instructions.
├── STRUCTURE.md           # This file - Defines the project structure.
│
├── pyproject.toml         # Defines project metadata, dependencies, build system config, and tool settings.
│
├── src/                   # Contains the main source code for the package.
│   └── rsma/              # The installable Python package directory.
│       ├── __init__.py      # Marks the directory as a Python package; can contain package-level info.
│       ├── analysis.py     # Implements metadata completeness analysis and schema validation logic.
│       ├── cli.py          # Defines the command-line interface entry point and orchestrates the workflow.
│       ├── file_io.py      # Contains functions for reading input CSV and writing output JSONL/CSV files.
│       ├── github_client.py# Handles interactions with the GitHub API via PyGithub.
│       ├── parsing.py      # Implements logic for parsing metadata file content (currently JSON).
│       ├── settings.py     # Handles loading configuration settings, such as the GitHub token.
│       └── schemas/        # Directory containing data files bundled with the package.
│           └── codemeta_schema_3.0.0.json # The JSON schema used for CodeMeta validation.
│
└── tests/                 # Contains unit and potentially integration tests for the package.
    ├── __init__.py          # Marks the directory as a Python package.
    ├── test_analysis.py    # Tests for functions in analysis.py.
    ├── test_cli.py         # Tests for the command-line interface argument parsing and basic flow.
    ├── test_file_io.py     # Tests for functions in file_io.py.
    ├── test_github_client.py# Tests for functions in github_client.py (using mocks).
    ├── test_parsing.py     # Tests for functions in parsing.py.
    └── test_settings.py    # Tests for functions in settings.py.