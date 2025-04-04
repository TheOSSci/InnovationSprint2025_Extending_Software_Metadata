# src/rsma/cli.py

import argparse
import logging
import sys
import os
from typing import List, Dict, Any, Optional
from datetime import datetime

from . import settings
from . import github_client
from . import file_io
from . import parsing
from . import analysis
from github import Github, GithubException, RateLimitExceededException

# Set up logging configuration
# Messages with level INFO and above will be shown by default
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(name)s - %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger(__name__)

# Maps specific metadata filenames to their parsing functions
PARSER_MAP = {
    'codemeta.json': parsing.parse_codemeta,
}

# Maps filenames to their analysis functions (set dynamically based on args)
ANALYSIS_MAP = {
    'codemeta.json': None, # Dynamically set in main()
}

# Maps filenames to their schema validation functions
VALIDATOR_MAP = {
    'codemeta.json': analysis.validate_codemeta_schema,
}

# Defines the metadata files currently supported by the tool
SUPPORTED_TARGET_FILES = list(PARSER_MAP.keys())


def main():
    """Main function for the RSMA command-line interface."""
    parser = argparse.ArgumentParser(
        description="Research Software Metadata Analyzer (RSMA) - Analyzes codemeta.json across repositories from an input CSV."
    )
    # --- Define Command Line Arguments ---
    parser.add_argument(
        "--input-csv", type=str, required=True,
        help="Path to the input CSV file containing repository full names (expects 'repo_full_name' header)."
    )
    parser.add_argument(
        "--target-metadata-file", type=str, required=True,
        choices=SUPPORTED_TARGET_FILES, # Use choices to restrict input
        help=f"The specific metadata filename to analyze. Currently supports: {', '.join(SUPPORTED_TARGET_FILES)}"
    )
    parser.add_argument(
        "--output-jsonl", type=str, required=True,
        help="Path to the output JSON Lines file where detailed results will be saved."
    )
    parser.add_argument(
        "--output-csv", type=str, required=False, default=None,
        help="Optional: Path to the output CSV file where flattened results will be saved."
    )
    parser.add_argument(
        '-v', '--verbose', action='store_true',
        help="Enable debug level logging for more detailed output."
    )
    parser.add_argument(
        '--comprehensive', action='store_true',
        help="Perform comprehensive analysis of standard CodeMeta fields (not just core fields)."
    )
    parser.add_argument(
        '--skip-schema-validation', action='store_true',
        help="Skip CodeMeta JSON schema validation (useful if schema file is missing or causes issues)."
    )

    # --- Parse Arguments ---
    try:
        args = parser.parse_args()
    except SystemExit as e:
        # Catch argument parsing errors (like missing required args or invalid choices)
        # Argparse typically prints help message and exits; allow this behavior but log it.
        logger.error("Argument parsing error. Please check command-line arguments.")
        sys.exit(e.code) # Propagate the exit code from argparse

    input_csv_path = args.input_csv
    target_metadata_file = args.target_metadata_file
    output_jsonl_path = args.output_jsonl
    output_csv_path = args.output_csv
    verbose = args.verbose
    comprehensive = args.comprehensive
    skip_schema_validation = args.skip_schema_validation

    # --- Configure Analysis and Logging ---
    # Set the appropriate CodeMeta analysis function based on the comprehensive flag
    if comprehensive:
        ANALYSIS_MAP[target_metadata_file] = analysis.analyze_codemeta_comprehensive
        analysis_mode = "Comprehensive"
    else:
        ANALYSIS_MAP[target_metadata_file] = analysis.analyze_codemeta_completeness
        analysis_mode = "Basic"
    logger.info(f"Using {analysis_mode} CodeMeta analysis.")

    log_level = logging.DEBUG if verbose else logging.INFO
    logging.getLogger().setLevel(log_level) # Set root logger level
    logger.setLevel(log_level) # Set this module's logger level

    logger.info(f"RSMA CLI started (Mode: CodeMeta {analysis_mode}).")
    logger.debug(f"Log level set to: {logging.getLevelName(log_level)}")
    logger.info(f"Input CSV file: {os.path.abspath(input_csv_path)}")
    logger.info(f"Target Metadata File: {target_metadata_file}")
    logger.info(f"Output JSON Lines file: {os.path.abspath(output_jsonl_path)}")
    if output_csv_path:
        logger.info(f"Output CSV file: {os.path.abspath(output_csv_path)}")
    if skip_schema_validation:
        logger.info("Schema validation is DISABLED.")
    else:
        logger.info("Schema validation is ENABLED.")


    # --- Step 1: Load GitHub Token ---
    logger.info("Loading GitHub Token...")
    github_token = settings.load_github_token()
    if not github_token:
        logger.critical("GitHub token not found or invalid. Please configure via .env file or GITHUB_TOKEN environment variable. See README. Exiting.")
        sys.exit(1)
    logger.info("GitHub token status: Loaded successfully.")

    # --- Step 2: Read Repository List ---
    logger.info(f"Reading repository list from {input_csv_path}...")
    repo_list = file_io.read_repo_list_csv(input_file=input_csv_path)
    if not repo_list:
        logger.critical(f"No valid repositories found in '{input_csv_path}'. Check file format (CSV, 'repo_full_name' header) and content. Exiting.")
        sys.exit(1)
    logger.info(f"Successfully read {len(repo_list)} repository names.")
    total_repos = len(repo_list)

    # --- Step 3: Initialize GitHub Client ---
    logger.info("Initializing GitHub client...")
    gh_client: Github
    try:
        # Increase timeout and add basic retry mechanism for robustness
        gh_client = Github(github_token, timeout=30, retry=3)
        user = gh_client.get_user() # Verify authentication by fetching user info
        logger.info(f"Successfully initialized GitHub client and authenticated as '{user.login}'.")

        # Check initial rate limit status for immediate feedback
        rate_limit = gh_client.get_rate_limit()
        core_limit = rate_limit.core
        # Convert reset time (Unix timestamp) to human-readable format
        reset_time = datetime.fromtimestamp(core_limit.reset.timestamp())
        logger.info(
            f"GitHub API Rate Limit Status: {core_limit.remaining}/{core_limit.limit} requests remaining. "
            f"Resets at {reset_time.strftime('%Y-%m-%d %H:%M:%S %Z')}."
        )
        # Provide a warning if remaining requests seem low compared to the number of repos
        if core_limit.remaining < total_repos * 2: # Estimate ~2 API calls per repo (meta + file)
             logger.warning(
                 f"Low GitHub API requests remaining ({core_limit.remaining}). "
                 f"Analysis of {total_repos} repositories might be interrupted by rate limits."
             )
    except RateLimitExceededException as e:
         # Extract rate limit details from headers if available
         reset_time_ts = e.headers.get("x-ratelimit-reset", 0)
         reset_time_dt = datetime.fromtimestamp(int(reset_time_ts))
         limit = e.headers.get('x-ratelimit-limit')
         logger.critical(
             f"GitHub rate limit exceeded immediately upon connection. Limit: {limit}. "
             f"Try again after {reset_time_dt.strftime('%Y-%m-%d %H:%M:%S %Z')}. Exiting."
         )
         sys.exit(1)
    except GithubException as e:
        # Handle other specific GitHub errors during initialization
        logger.critical(f"GitHub error during client initialization: {e.status} {e.data}. Check token validity and network connection.", exc_info=log_level <= logging.DEBUG)
        sys.exit(1)
    except Exception as e:
        # Catch any other unexpected errors
        logger.critical(f"Unexpected error during GitHub client initialization: {e}", exc_info=True)
        sys.exit(1)

    # --- Step 4: Iterate through Repositories & Analyze ---
    results_collector: List[Dict[str, Any]] = []
    processed_count = 0
    repos_with_errors_or_validation_failures = 0

    logger.info(f"Starting analysis for {total_repos} repositories, focusing on '{target_metadata_file}'...")

    for i, repo_name in enumerate(repo_list):
        logger.info(f"--- Processing repo {i+1}/{total_repos}: {repo_name} ---")
        # Flag to track if any step *related to this repo's processing* failed
        # (includes repo meta fetch, file fetch, parse, analysis, validation)
        repo_had_error_flag = False
        # Initialize result structure for the current repository
        repo_result: Dict[str, Any] = {
            "repo_full_name": repo_name,
            "repo_metadata": None,
            "repo_metadata_error": None, # Stores repo-level errors (404, rate limit) or a summary of file processing errors
            "metadata_files": {
                # Initialize structure for the target file
                target_metadata_file: {"fetch_status": "not_processed"}
            }
        }
        # Get a direct reference to the dictionary holding results for the target file
        file_result_dict = repo_result["metadata_files"][target_metadata_file]

        # Pre-populate file result keys with None to ensure they exist in the output JSONL/CSV
        file_keys = [
            "fetch_error", "parse_status", "parse_error",
            "completeness_score", "completeness_missing_keys", "schema_valid", "schema_errors"
        ]
        if comprehensive:
            file_keys.extend([
                "core_score", "core_missing", "extended_score", "extended_missing",
                "present_fields", "all_fields_count", "present_fields_count"
            ])
        for key in file_keys:
            file_result_dict[key] = None

        # --- Step 4.1: Fetch Repository Metadata ---
        logger.info(f"  Fetching repository metadata for {repo_name}...")
        repo_meta_result: Optional[Dict[str, Any]] = None
        try:
            repo_meta_result = github_client.get_repository_metadata(repo_name, gh_client)
            if repo_meta_result and repo_meta_result.get('error'):
                error_msg = repo_meta_result['error']
                logger.warning(f"  -> Failed to fetch repository metadata: {error_msg}")
                repo_result['repo_metadata_error'] = error_msg # Store the specific repo error
                repo_had_error_flag = True
            elif repo_meta_result and repo_meta_result.get('data'):
                logger.info(f"  -> Successfully fetched repository metadata.")
                repo_result['repo_metadata'] = repo_meta_result['data']
            else:
                # Defensive check for unexpected empty result from the client function
                logger.error(f"  -> Unexpected empty result fetching repository metadata for {repo_name}.")
                repo_result['repo_metadata_error'] = "Unexpected empty result from metadata fetch"
                repo_had_error_flag = True
        except Exception as e:
            # Catch unexpected errors during the call itself
            logger.error(f"  -> Unexpected error during repository metadata fetch call: {e}", exc_info=log_level <= logging.DEBUG)
            repo_result['repo_metadata_error'] = f"Unexpected error during metadata fetch: {e}"
            repo_had_error_flag = True

        # --- Step 4.2: Fetch Target Metadata File (e.g., codemeta.json) ---
        logger.info(f"  Fetching target file '{target_metadata_file}' for {repo_name}...")
        content: Optional[str] = None
        fetch_status = 'not_processed'
        # Check if a critical repo error prevents even attempting file fetching
        repo_error = repo_result['repo_metadata_error']
        # Define critical errors that preclude file access
        is_critical_repo_error = repo_error and (
            "not found (404)" in repo_error
            or "Rate limit exceeded" in repo_error
            or "API error accessing repository" in repo_error # Covers 5xx etc.
            or "Bad Credentials" in repo_error # Auth error
        )

        if is_critical_repo_error:
            logger.warning(f"  -> Skipping target file fetching due to critical repository access error: {repo_error}")
            file_result_dict['fetch_status'] = 'skipped'
            file_result_dict['fetch_error'] = f'Skipped due to repository error: {repo_error}'
            fetch_status = 'skipped'
            # The error is already recorded at the repo level
        else:
            # Proceed with fetching the file if repo access seemed okay
            try:
                fetched_files_data = github_client.get_metadata_files(repo_name, [target_metadata_file], gh_client)
                # Safely get the result for the specific target file
                file_fetch_result = fetched_files_data.get(target_metadata_file, {})

                fetch_status = file_fetch_result.get('status', 'error') # Default to error if key missing
                content = file_fetch_result.get('content') # Will be None if not found/error
                fetch_error = file_fetch_result.get('error') # Will be message if not found/error

                file_result_dict['fetch_status'] = fetch_status
                file_result_dict['fetch_error'] = fetch_error

                if fetch_status == 'found':
                    logger.info(f"  -> Successfully fetched '{target_metadata_file}'.")
                elif fetch_status == 'not_found':
                    logger.info(f"  -> Target file '{target_metadata_file}' not found in repository.")
                    # Not finding the file isn't an error in processing the *repo*, just means no analysis.
                elif fetch_status == 'skipped':
                     # This case might happen if get_metadata_files itself encounters a repo error after initial check
                     logger.warning(f"  -> Fetch skipped for '{target_metadata_file}': {fetch_error}")
                     repo_had_error_flag = True
                else: # status == 'error' (e.g., decode error, permissions on file)
                    logger.warning(f"  -> Failed to fetch/process '{target_metadata_file}': {fetch_error}")
                    repo_had_error_flag = True # An actual fetch/processing error for the file counts

            except Exception as e:
                # Catch unexpected errors during the get_metadata_files call
                logger.error(f"  -> Unexpected error during target file fetch call: {e}", exc_info=log_level <= logging.DEBUG)
                file_result_dict['fetch_status'] = 'error'
                file_result_dict['fetch_error'] = f"Unexpected error during file fetch: {e}"
                fetch_status = 'error'
                repo_had_error_flag = True

        # --- Step 4.3: Process Metadata File Content if Found ---
        if fetch_status == 'found' and content is not None:
            parser_func = PARSER_MAP.get(target_metadata_file)
            analyzer_func = ANALYSIS_MAP.get(target_metadata_file) # Chosen based on --comprehensive
            validator_func = None if skip_schema_validation else VALIDATOR_MAP.get(target_metadata_file)
            parsed_data: Optional[Dict[Any, Any]] = None # Initialize variable

            # --- 4.3.1 Parse ---
            if parser_func:
                logger.info(f"  Parsing '{target_metadata_file}'...")
                try:
                    parse_result = parser_func(content)
                    file_result_dict['parse_error'] = parse_result['parse_error']
                    if parse_result['parse_error'] is None:
                        file_result_dict['parse_status'] = True
                        logger.info(f"  -> Successfully parsed.")
                        parsed_data = parse_result['parsed_data']

                        # Crucial check: Ensure parsed data is a dictionary for analysis/validation
                        if not isinstance(parsed_data, dict):
                            logger.warning(f"  -> Parsing succeeded but result is not a dictionary (type: {type(parsed_data).__name__}). Skipping analysis & validation.")
                            file_result_dict['parse_status'] = False # Treat non-dict as parse failure for downstream
                            file_result_dict['parse_error'] = f"Parsed data is not a dictionary (type: {type(parsed_data).__name__})"
                            repo_had_error_flag = True
                            parsed_data = None # Prevent further processing

                    else: # Parsing reported an error
                        logger.warning(f"  -> Parsing failed: {parse_result['parse_error']}")
                        file_result_dict['parse_status'] = False
                        repo_had_error_flag = True
                        parsed_data = None

                except Exception as e:
                    # Catch unexpected errors *within* the parser function call
                    logger.error(f"  -> Unexpected error during parser execution: {e}", exc_info=log_level <= logging.DEBUG)
                    file_result_dict['parse_status'] = False
                    file_result_dict['parse_error'] = f"Unexpected parser error: {e}"
                    repo_had_error_flag = True
                    parsed_data = None
            else:
                 # This case should not happen due to choices validation, but handle defensively
                 logger.error(f"  -> Internal Error: No parser function found for '{target_metadata_file}' in PARSER_MAP.")
                 repo_had_error_flag = True
                 parsed_data = None


            # --- 4.3.2 Analyze Completeness (only if parsed_data is a valid dict) ---
            if parsed_data and analyzer_func:
                logger.info(f"    Analyzing completeness ({analysis_mode} mode)...")
                try:
                    analysis_result = analyzer_func(parsed_data)
                    # Populate results dictionary based on analysis mode
                    if comprehensive:
                        file_result_dict['core_score'] = analysis_result.get('core_score')
                        file_result_dict['core_missing'] = analysis_result.get('core_missing')
                        file_result_dict['extended_score'] = analysis_result.get('extended_score')
                        file_result_dict['extended_missing'] = analysis_result.get('extended_missing')
                        file_result_dict['present_fields'] = analysis_result.get('present_fields')
                        file_result_dict['all_fields_count'] = analysis_result.get('all_fields_count')
                        file_result_dict['present_fields_count'] = analysis_result.get('present_fields_count')
                        # Also populate basic fields for backward/CSV consistency
                        file_result_dict['completeness_score'] = analysis_result.get('core_score')
                        file_result_dict['completeness_missing_keys'] = analysis_result.get('core_missing')
                        logger.info(f"    -> Core Score: {analysis_result.get('core_score', 'N/A'):.2f}, Extended Score: {analysis_result.get('extended_score', 'N/A'):.2f}, Present: {analysis_result.get('present_fields_count', 'N/A')}/{analysis_result.get('all_fields_count', 'N/A')}")
                    else: # Basic analysis mode
                        file_result_dict['completeness_score'] = analysis_result.get('score')
                        file_result_dict['completeness_missing_keys'] = analysis_result.get('missing_keys')
                        logger.info(f"    -> Completeness score: {analysis_result.get('score', 'N/A'):.2f}, Missing keys: {analysis_result.get('missing_keys', [])}")

                except Exception as e:
                    # Catch unexpected errors during analysis function execution
                    logger.error(f"    -> Error during completeness analysis execution: {e}", exc_info=log_level <= logging.DEBUG)
                    repo_had_error_flag = True # Analysis error counts towards repo error flag

            # --- 4.3.3 Validate Schema (only if parsed_data is valid dict and not skipped) ---
            if parsed_data and validator_func:
                logger.info(f"    Validating schema against CodeMeta v3.0.0...")
                try:
                    validation_result = validator_func(parsed_data)
                    is_valid = validation_result.get('valid')
                    errors = validation_result.get('errors') # This is None or a list of strings
                    file_result_dict['schema_valid'] = is_valid
                    file_result_dict['schema_errors'] = errors
                    validity_msg = "Valid" if is_valid else f"Invalid"
                    if is_valid:
                        logger.info(f"    -> Schema is {validity_msg}.")
                    else:
                        # Log the validation errors clearly
                        error_str = '; '.join(errors) if errors else "No specific errors reported."
                        logger.warning(f"    -> Schema is {validity_msg}. Validation Errors: {error_str}")
                        repo_had_error_flag = True # Invalid schema counts as an issue/error
                except Exception as e:
                    # Catch unexpected errors during validator function execution
                    logger.error(f"    -> Error during schema validation execution: {e}", exc_info=log_level <= logging.DEBUG)
                    file_result_dict['schema_valid'] = False
                    file_result_dict['schema_errors'] = [f"Unexpected validation error: {e}"]
                    repo_had_error_flag = True
            elif skip_schema_validation:
                # Only log skipping message if we actually had data that *could* have been validated
                if parsed_data:
                    logger.info("    Skipping schema validation as requested.")
                file_result_dict['schema_valid'] = "skipped"
                file_result_dict['schema_errors'] = None


        # --- Log Repo Completion Status ---
        # Determine final status message based on the error flag
        completion_status = "completed successfully" if not repo_had_error_flag else "completed with errors or validation failures"
        # Add a general error summary at the repo level if specific file errors occurred but no repo-level error was set yet
        if repo_had_error_flag and not repo_result['repo_metadata_error']:
            repo_result['repo_metadata_error'] = "Errors occurred during metadata file processing (fetch, parse, analysis, or validation). See file results."

        logger.info(f"--- Finished processing {repo_name}: {completion_status} ---")

        # --- Collect Results and Update Counts ---
        results_collector.append(repo_result)
        processed_count += 1
        if repo_had_error_flag:
            repos_with_errors_or_validation_failures += 1

    # --- Final Summary ---
    logger.info(f"\n=============== ANALYSIS SUMMARY ===============")
    logger.info(f"Finished processing {processed_count}/{total_repos} repositories.")
    logger.info(f"Encountered errors or validation failures in {repos_with_errors_or_validation_failures} repositories.")
    logger.info(f"==============================================")

    # --- Step 5: Save JSON Lines Results ---
    logger.info(f"Saving detailed results to {output_jsonl_path}...")
    jsonl_save_error = False
    try:
        file_io.save_results_jsonl(results_data=results_collector, output_file=output_jsonl_path)
        logger.info(f"-> Successfully saved detailed JSON Lines results.")
    except Exception as e:
        # Log critical error and set flag, but allow CSV saving attempt if specified
        logger.critical(f"-> CRITICAL ERROR saving JSONL results to '{output_jsonl_path}': {e}", exc_info=True)
        jsonl_save_error = True

    # --- Step 6: Save CSV Results (Optional) ---
    csv_save_error = False
    if output_csv_path:
        logger.info(f"Saving flattened results to {output_csv_path}...")
        try:
            file_io.save_results_csv(
                results_data=results_collector,
                target_metadata_file=target_metadata_file,
                output_file=output_csv_path,
                comprehensive=comprehensive # Pass flag for correct headers/flattening
            )
            logger.info(f"-> Successfully saved flattened CSV results.")
        except Exception as e:
            # Log as error, don't exit program, but flag for exit code
            logger.error(f"-> ERROR saving CSV results to '{output_csv_path}': {e}", exc_info=log_level <= logging.DEBUG)
            csv_save_error = True

    # --- Final Exit ---
    logger.info("RSMA CLI finished.")
    # Determine final exit code: 1 if any repo processing failed, or if JSONL/CSV saving failed. 0 otherwise.
    final_exit_code = 1 if repos_with_errors_or_validation_failures > 0 or jsonl_save_error or csv_save_error else 0
    logger.info(f"Exiting with status code: {final_exit_code}")
    sys.exit(final_exit_code)


if __name__ == "__main__":
    main()