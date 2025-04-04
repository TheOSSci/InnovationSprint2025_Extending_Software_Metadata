# src/rsma/file_io.py

import csv
import logging
import os
import json
from typing import List, Dict, Any, Optional

logger = logging.getLogger(__name__)

# Expected header in the input CSV file for repository names
EXPECTED_CSV_HEADER = "repo_full_name"

# --- Define CSV Output Headers ---
# Headers for the basic analysis CSV output
BASIC_CSV_FIELDNAMES = [
    'repo_full_name',
    'repo_metadata_error', # Summary of errors encountered for the repo (fetch, parse, validate)
    'repo_html_url',
    'repo_description',
    'repo_stargazers_count',
    'repo_forks_count',
    'repo_watchers_count',
    'repo_open_issues_count',
    'repo_created_at',
    'repo_pushed_at',
    'repo_updated_at',
    'repo_size',
    'repo_language',
    'repo_topics', # Semicolon-separated list
    'repo_license_spdx_id',
    'repo_is_fork',
    'repo_is_archived',
    'repo_is_disabled',
    'target_metadata_filename', # e.g., 'codemeta.json'
    'fetch_status', # ('found', 'not_found', 'error', 'skipped')
    'fetch_error', # Error message if fetch_status is 'error'/'skipped'
    'parse_status', # Boolean or None/empty string
    'parse_error', # Error message if parse_status is False
    'completeness_score', # Basic score (0.0-1.0) or None/empty string
    'completeness_missing_keys', # Semicolon-separated list or empty string
    'schema_valid', # Boolean, 'skipped', or None/empty string
    'schema_errors', # Semicolon-separated list of errors or empty string
]

# Additional headers for the comprehensive analysis CSV output
COMPREHENSIVE_CSV_FIELDNAMES = BASIC_CSV_FIELDNAMES + [
    'core_score', # Score for core fields (0.0-1.0) or None/empty string
    'core_missing', # Semicolon-separated list
    'extended_score', # Score for extended fields (0.0-1.0) or None/empty string
    'extended_missing', # Semicolon-separated list
    'present_fields_count', # Count of fields present in the file
    'all_fields_count', # Total number of fields checked (core + extended)
    'present_fields', # Semicolon-separated list of present field names
]


def _ensure_output_directory_exists(output_file: str) -> bool:
    """
    Checks if the output directory for a file exists and creates it if necessary.

    Args:
        output_file: The full path to the intended output file.

    Returns:
        True if the directory exists or was successfully created, False otherwise.
    """
    output_dir = os.path.dirname(output_file)
    # Only create if output_dir is specified (not the current directory)
    if output_dir and not os.path.exists(output_dir):
        try:
            # exist_ok=True prevents error if directory is created between check and makedirs call
            os.makedirs(output_dir, exist_ok=True)
            logger.info(f"Created output directory: {output_dir}")
            return True
        except OSError as e:
            logger.error(f"Failed to create output directory '{output_dir}': {e}")
            return False
        except Exception as e:
             logger.error(f"Unexpected error creating directory '{output_dir}': {e}")
             return False
    # Directory already exists or is the current directory ('.')
    return True


def read_repo_list_csv(input_file: str) -> List[str]:
    """
    Reads a list of repository full names from a CSV file.
    Expects a header row with 'repo_full_name' (case-insensitive).
    Skips rows with missing or invalidly formatted repository names.

    Args:
        input_file: Path to the input CSV file.

    Returns:
        A list of valid repository full name strings (e.g., 'owner/repo').
        Returns an empty list if the file cannot be read, is empty,
        lacks the required header, or contains no valid repo names.
    """
    repo_list: List[str] = []
    if not os.path.isfile(input_file): # Check if it's a file specifically
        logger.error(f"Input CSV path is not a file or does not exist: {input_file}")
        return []

    line_num = 0 # Initialize line number for error reporting
    try:
        # Use utf-8-sig to handle potential Byte Order Mark (BOM) from Excel
        with open(input_file, 'r', newline='', encoding='utf-8-sig') as csvfile:
            reader = csv.reader(csvfile)

            # --- Read Header ---
            try:
                header = next(reader)
                line_num = 1
                logger.debug(f"CSV header found: {header}")
            except StopIteration:
                logger.warning(f"Input CSV file is empty (no header row): {input_file}")
                return []

            # --- Find Required Column Index ---
            try:
                # Normalize headers for case-insensitive matching
                header_normalized = [str(h).strip().lower() for h in header]
                repo_col_index = header_normalized.index(EXPECTED_CSV_HEADER.lower())
                logger.debug(f"Found '{EXPECTED_CSV_HEADER}' column at index {repo_col_index}.")
            except ValueError:
                logger.error(f"Input CSV file '{input_file}' missing required header '{EXPECTED_CSV_HEADER}'. Found headers: {header}")
                return []
            except AttributeError: # Handle case where header contains non-string elements
                 logger.error(f"Invalid header format (contains non-string elements) in CSV file '{input_file}': {header}")
                 return []

            # --- Read Rows ---
            processed_count = 0
            skipped_count = 0
            for row in reader:
                line_num += 1
                # Check if row is long enough and has content in the target column
                if row and len(row) > repo_col_index:
                    repo_name_raw = row[repo_col_index]
                    if isinstance(repo_name_raw, str):
                        repo_name = repo_name_raw.strip()
                        # Basic validation: check for typical owner/repo format (non-empty, contains '/', no leading/trailing slashes/spaces)
                        if repo_name and '/' in repo_name and not repo_name.startswith('/') and not repo_name.endswith('/') and ' ' not in repo_name:
                            repo_list.append(repo_name)
                            processed_count += 1
                        elif repo_name: # Log non-empty but invalid formats
                             logger.warning(f"Skipping invalid repo format '{repo_name}' in {input_file} at line {line_num}")
                             skipped_count += 1
                        else: # Log empty value in column
                             logger.warning(f"Skipping empty repo name in '{EXPECTED_CSV_HEADER}' column in {input_file} at line {line_num}")
                             skipped_count += 1
                    else: # Log if value is not a string
                         logger.warning(f"Skipping non-string value ('{repo_name_raw}') in '{EXPECTED_CSV_HEADER}' column in {input_file} at line {line_num}")
                         skipped_count += 1
                elif row: # Log rows that are too short
                    logger.warning(f"Skipping row {line_num} in {input_file}: Row is shorter than expected (length {len(row)}, needed index {repo_col_index}).")
                    skipped_count += 1
                # Silently skip completely empty rows

        log_suffix = f" from {input_file}" + (f" (skipped {skipped_count} invalid entries)." if skipped_count else ".")
        logger.info(f"Successfully read {processed_count} valid repository names{log_suffix}")
        return repo_list

    except IOError as e:
        logger.error(f"Failed to read input CSV file {input_file}: {e}")
        return []
    except csv.Error as e:
        # csv.Error can occur during reading if the file is malformed
        logger.error(f"Error parsing CSV file {input_file} near line {line_num}: {e}")
        return []
    except Exception as e:
        logger.error(f"An unexpected error occurred while reading CSV {input_file}: {e}", exc_info=True)
        return []


def save_results_jsonl(results_data: List[Dict[str, Any]], output_file: str):
    """
    Saves a list of dictionaries (analysis results per repo) to a JSON Lines file.
    Each dictionary is written as a single JSON object on its own line.

    Args:
        results_data: A list of dictionaries containing the analysis results.
        output_file: The path to the output JSON Lines file.

    Raises:
        IOError: If writing to the file fails.
        Exception: If an unexpected error occurs during saving.
    """
    if not _ensure_output_directory_exists(output_file):
        # Log the error but also raise an exception as saving failed
        msg = f"Cannot save JSON Lines results: Output directory for '{output_file}' could not be created or accessed."
        logger.error(msg)
        raise IOError(msg)

    record_count = 0
    skipped_count = 0
    try:
        with open(output_file, 'w', encoding='utf-8') as f:
            for record in results_data:
                try:
                    # Use compact separators and ensure_ascii=False for potentially smaller files
                    # that correctly handle unicode characters.
                    json_string = json.dumps(record, ensure_ascii=False, separators=(',', ':'))
                    f.write(json_string + '\n')
                    record_count += 1
                except TypeError as e:
                    # Log and skip records that cannot be serialized to JSON
                    repo_name = record.get('repo_full_name', 'UNKNOWN')
                    # Log minimally to avoid excessive output, provide repo name for context
                    logger.error(f"Skipping record for repo '{repo_name}' due to JSON serialization error: {e}. Check data types in results.", exc_info=False)
                    skipped_count += 1

        logger.info(f"Successfully saved {record_count} records to JSON Lines file: {output_file}")
        if skipped_count > 0:
            logger.warning(f"Skipped {skipped_count} records due to JSON serialization errors.")

    except IOError as e:
        logger.error(f"Failed to write results to {output_file}: {e}")
        raise # Re-raise IOErrors as they indicate a critical failure
    except Exception as e:
        logger.error(f"An unexpected error occurred saving JSON Lines to {output_file}: {e}", exc_info=True)
        raise # Re-raise unexpected errors


def _clean_value_for_csv(value: Any) -> str:
    """Helper to convert values to strings suitable for CSV, handling lists."""
    if value is None:
        return ''
    if isinstance(value, list):
        # Join list items with semicolon, ensuring items are strings
        # Filter out None values before joining
        return ';'.join(map(str, filter(lambda x: x is not None, value)))
    if isinstance(value, bool):
        # Explicitly convert bools to string 'True'/'False'
        return str(value)
    # Convert other types (int, float, str) to string
    return str(value)


def flatten_result_for_csv(repo_result: Dict[str, Any], target_metadata_file: str, comprehensive: bool = False) -> Dict[str, Any]:
    """
    Flattens a single repository result dictionary into a flat dictionary
    suitable for writing to a CSV row. Handles both basic and comprehensive modes.

    Args:
        repo_result: The nested dictionary containing results for one repo.
        target_metadata_file: The specific metadata file analyzed (e.g., "codemeta.json").
        comprehensive: If True, include comprehensive analysis fields.

    Returns:
        A flat dictionary where keys match the appropriate CSV fieldnames list.
        Values are converted to strings suitable for CSV.
    """
    # Choose the correct field names based on the analysis mode
    fieldnames = COMPREHENSIVE_CSV_FIELDNAMES if comprehensive else BASIC_CSV_FIELDNAMES
    flat_data: Dict[str, Any] = {key: '' for key in fieldnames} # Initialize with empty strings

    # --- Basic Repo Info ---
    flat_data['repo_full_name'] = repo_result.get('repo_full_name', '')
    flat_data['repo_metadata_error'] = repo_result.get('repo_metadata_error', '')

    # --- Detailed Repo Metadata (if available) ---
    repo_meta = repo_result.get('repo_metadata')
    if isinstance(repo_meta, dict):
        flat_data['repo_html_url'] = repo_meta.get('html_url', '')
        flat_data['repo_description'] = repo_meta.get('description', '')
        flat_data['repo_stargazers_count'] = repo_meta.get('stargazers_count', '')
        flat_data['repo_forks_count'] = repo_meta.get('forks_count', '')
        flat_data['repo_watchers_count'] = repo_meta.get('watchers_count', '')
        flat_data['repo_open_issues_count'] = repo_meta.get('open_issues_count', '')
        flat_data['repo_created_at'] = repo_meta.get('created_at', '') # Keep as ISO string
        flat_data['repo_pushed_at'] = repo_meta.get('pushed_at', '') # Keep as ISO string
        flat_data['repo_updated_at'] = repo_meta.get('updated_at', '') # Keep as ISO string
        flat_data['repo_size'] = repo_meta.get('size', '')
        flat_data['repo_language'] = repo_meta.get('language', '')
        flat_data['repo_topics'] = _clean_value_for_csv(repo_meta.get('topics', [])) # Join topics list
        flat_data['repo_is_fork'] = _clean_value_for_csv(repo_meta.get('is_fork'))
        flat_data['repo_is_archived'] = _clean_value_for_csv(repo_meta.get('is_archived'))
        flat_data['repo_is_disabled'] = _clean_value_for_csv(repo_meta.get('is_disabled'))
        # Safely extract license SPDX ID
        repo_license = repo_meta.get('license')
        flat_data['repo_license_spdx_id'] = repo_license.get('spdx_id', '') if isinstance(repo_license, dict) else ''

    # --- Target File Analysis Results ---
    flat_data['target_metadata_filename'] = target_metadata_file
    # Safely access the nested dictionary for the target file's results
    file_results = repo_result.get('metadata_files', {}).get(target_metadata_file)

    if isinstance(file_results, dict):
        flat_data['fetch_status'] = file_results.get('fetch_status', '')
        flat_data['fetch_error'] = file_results.get('fetch_error', '')
        flat_data['parse_status'] = _clean_value_for_csv(file_results.get('parse_status')) # Handle bool/None
        flat_data['parse_error'] = file_results.get('parse_error', '')

        # Basic analysis fields (always present in fieldnames)
        flat_data['completeness_score'] = _clean_value_for_csv(file_results.get('completeness_score'))
        flat_data['completeness_missing_keys'] = _clean_value_for_csv(file_results.get('completeness_missing_keys'))

        flat_data['schema_valid'] = _clean_value_for_csv(file_results.get('schema_valid')) # Handle bool/None/'skipped'
        flat_data['schema_errors'] = _clean_value_for_csv(file_results.get('schema_errors'))

        # Comprehensive analysis fields (only populate if comprehensive=True)
        if comprehensive:
            flat_data['core_score'] = _clean_value_for_csv(file_results.get('core_score'))
            flat_data['core_missing'] = _clean_value_for_csv(file_results.get('core_missing'))
            flat_data['extended_score'] = _clean_value_for_csv(file_results.get('extended_score'))
            flat_data['extended_missing'] = _clean_value_for_csv(file_results.get('extended_missing'))
            flat_data['present_fields_count'] = _clean_value_for_csv(file_results.get('present_fields_count'))
            flat_data['all_fields_count'] = _clean_value_for_csv(file_results.get('all_fields_count'))
            flat_data['present_fields'] = _clean_value_for_csv(file_results.get('present_fields'))

    # Final check: Ensure all values in the final dict corresponding
    # to the chosen fieldnames are strings.
    for key in fieldnames:
        if key in flat_data:
             # Use the helper to ensure consistent string conversion
            flat_data[key] = _clean_value_for_csv(flat_data.get(key))
        else:
            # If a fieldname was somehow missed, ensure it exists with an empty string
            flat_data[key] = ''

    return flat_data


def save_results_csv(
    results_data: List[Dict[str, Any]],
    target_metadata_file: str,
    output_file: str,
    comprehensive: bool = False
):
    """
    Saves the list of processed repository results to a flattened CSV file.

    Args:
        results_data: A list of nested result dictionaries (one per repo).
        target_metadata_file: The specific metadata file that was analyzed.
        output_file: The path to the output CSV file.
        comprehensive: If True, use headers and flattening for comprehensive analysis.

    Raises:
        IOError: If writing to the file fails.
        Exception: If an unexpected error occurs during saving.
    """
    if not _ensure_output_directory_exists(output_file):
        msg = f"Cannot save CSV results: Output directory for '{output_file}' could not be created or accessed."
        logger.error(msg)
        raise IOError(msg)

    # Choose the correct fieldnames list based on the mode
    fieldnames = COMPREHENSIVE_CSV_FIELDNAMES if comprehensive else BASIC_CSV_FIELDNAMES
    record_count = 0
    skipped_count = 0

    try:
        with open(output_file, 'w', newline='', encoding='utf-8') as csvfile:
            # Use QUOTE_MINIMAL for cleaner output, quoting fields only when necessary
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames, quoting=csv.QUOTE_MINIMAL)
            writer.writeheader()

            for repo_result in results_data:
                try:
                    flat_row = flatten_result_for_csv(repo_result, target_metadata_file, comprehensive)
                    # Ensure the row only contains keys defined in fieldnames to avoid DictWriter errors
                    # Default to empty string for any missing keys in the flattened data vs fieldnames
                    filtered_row = {k: flat_row.get(k, '') for k in fieldnames}
                    writer.writerow(filtered_row)
                    record_count += 1
                except Exception as e:
                    # Log error for the specific row but continue processing others
                    repo_name = repo_result.get('repo_full_name', 'UNKNOWN')
                    logger.error(f"Skipping CSV row for repo '{repo_name}' due to flattening/writing error: {e}", exc_info=False) # Avoid stack trace per row
                    skipped_count += 1

        logger.info(f"Successfully saved {record_count} records to CSV file: {output_file}")
        if skipped_count > 0:
             logger.warning(f"Skipped {skipped_count} rows in CSV output due to errors during flattening or writing.")

    except IOError as e:
        logger.error(f"Failed to write CSV results to {output_file}: {e}")
        raise # Re-raise critical IO error
    except Exception as e:
        # Catch unexpected errors during the overall CSV writing process (e.g., header issues)
        logger.error(f"An unexpected error occurred while saving CSV to {output_file}: {e}", exc_info=True)
        raise # Re-raise unexpected error