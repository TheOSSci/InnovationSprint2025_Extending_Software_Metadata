# src/rsma/analysis.py

import logging
import json
import pkgutil
from functools import lru_cache
from typing import Dict, Any, List, Tuple, Optional, Union

import jsonschema
from jsonschema import ValidationError as JsonSchemaValidationError

logger = logging.getLogger(__name__)

# --- Heuristic Completeness Analysis ---

# Fields considered "core" for basic completeness check.
# Format: 'field_name' or ('display_name_for_group', ['actual_key1', 'actual_key2'])
# These represent a minimal set for useful software citation and discovery.
_CORE_CODEMETA_FIELDS: List[Union[str, Tuple[str, List[str]]]] = [
    '@context',
    '@type',
    'name',
    ('author/creator', ['author', 'creator']), # Check if either author or creator exists
    'description',
    'license',
    'version',
    'codeRepository',
    ('datePublished/Modified/Created', ['datePublished', 'dateModified', 'dateCreated']) # Check if any date exists
]

# Fields considered "extended" based on common CodeMeta usage and schema properties.
# This list represents a broader selection for more detailed analysis.
# Plain strings are used here as simple key checks.
_EXTENDED_CODEMETA_FIELDS: List[str] = [
    'identifier', 'keywords', 'programmingLanguage', 'runtimePlatform',
    'operatingSystem', 'applicationCategory', 'releaseNotes', 'funding',
    'funder', 'citation', 'contributor', 'maintainer', 'publisher',
    'relatedLink', 'readme', 'issueTracker', 'developmentStatus',
    'softwareRequirements', 'softwareSuggestions', 'isPartOf', 'hasPart',
    'copyrightHolder', 'copyrightYear', 'downloadUrl', 'installUrl',
    'referencePublication', 'sameAs', 'url', 'encoding', 'fileFormat',
    'fileSize', 'memoryRequirements', 'processorRequirements', 'storageRequirements'
    # Add more fields from the schema if desired for analysis
]


def _check_keys(data: Dict[str, Any], keys_to_check: List[Union[str, Tuple[str, List[str]]]]) -> Tuple[int, List[str]]:
    """
    Helper function to check for the presence and non-emptiness of keys in data.

    Checks if a key exists and its value is not None, empty string, empty list, or empty dict.

    Args:
        data: The dictionary to check.
        keys_to_check: A list of keys or key groups (tuples) to look for.

    Returns:
        A tuple containing:
        - The count of found keys/key groups that have meaningful values.
        - A list of representative names for missing or empty keys/key groups.
    """
    found_count = 0
    missing_keys: List[str] = []
    if not isinstance(data, dict): # Handle non-dict input defensively
        # If data is not a dict, all keys are considered missing
        return 0, [k if isinstance(k, str) else k[0] for k in keys_to_check]

    for key_or_group in keys_to_check:
        found_meaningful_value = False
        representative_name = ""
        keys_in_group: List[str] = []

        if isinstance(key_or_group, str):
            # Single key check
            representative_name = key_or_group
            keys_in_group = [key_or_group]
        elif isinstance(key_or_group, tuple) and len(key_or_group) == 2:
            # Group check: ('display_name', ['key1', 'key2'])
            representative_name, keys_in_group = key_or_group
        else:
            # Invalid format in keys_to_check list
            logger.warning("Invalid format encountered in keys_to_check list: %s", key_or_group)
            continue

        # Check if any key within the group exists and has a meaningful value
        for actual_key in keys_in_group:
            value = data.get(actual_key) # Use .get() for safe access
            # Define "meaningful value" check
            if value is not None and value != '' and value != [] and value != {}:
                found_meaningful_value = True
                break # Found one in the group, no need to check others

        if found_meaningful_value:
            found_count += 1
        else:
            # Add the representative name to missing keys if none in the group had a meaningful value
            missing_keys.append(representative_name)

    return found_count, missing_keys


def analyze_codemeta_completeness(parsed_data: Any) -> Dict[str, Any]:
    """
    Calculates basic heuristic completeness for CodeMeta data based on core fields.

    Args:
        parsed_data: The parsed CodeMeta data, expected to be a dictionary.

    Returns:
        A dictionary containing:
        - 'score': A completeness score (0.0 to 1.0) based on core fields present with values.
        - 'missing_keys': A list of core field names (or group names) that were missing or empty.
    """
    if not isinstance(parsed_data, dict):
        logger.warning("Basic analysis: Input data is not a dictionary (type: %s). Returning 0 score.", type(parsed_data).__name__)
        # Generate list of all representative names for core fields as missing
        missing = [k if isinstance(k, str) else k[0] for k in _CORE_CODEMETA_FIELDS]
        return {'score': 0.0, 'missing_keys': missing}

    found_keys_count, missing_keys = _check_keys(parsed_data, _CORE_CODEMETA_FIELDS)
    total_keys_checked = len(_CORE_CODEMETA_FIELDS)
    score = found_keys_count / total_keys_checked if total_keys_checked > 0 else 0.0

    logger.debug("CodeMeta basic completeness - Found: %d/%d, Score: %.2f, Missing: %s",
                 found_keys_count, total_keys_checked, score, missing_keys)
    return {'score': score, 'missing_keys': missing_keys}


def analyze_codemeta_comprehensive(parsed_data: Any) -> Dict[str, Any]:
    """
    Performs a comprehensive analysis of CodeMeta data, checking core and extended fields.

    Calculates separate scores for core and extended fields based on presence and non-emptiness.
    Also lists all fields actually present in the input data.

    Args:
        parsed_data: The parsed CodeMeta data, expected to be a dictionary.

    Returns:
        A dictionary with detailed completeness metrics:
        - 'core_score': Score based on core fields (0.0-1.0).
        - 'core_missing': List of missing/empty core fields.
        - 'extended_score': Score based on the defined extended fields (0.0-1.0).
        - 'extended_missing': List of missing/empty extended fields from the checked list.
        - 'present_fields': Sorted list of all field names actually present in the data with meaningful values.
        - 'all_fields_count': Total number of unique core + extended fields *checked*.
        - 'present_fields_count': Count of fields present in the input data with meaningful values.
        - 'score': Same as 'core_score' (for backward compatibility).
        - 'missing_keys': Same as 'core_missing' (for backward compatibility).
    """
    if not isinstance(parsed_data, dict):
        logger.warning("Comprehensive analysis: Input data is not a dictionary (type: %s). Returning empty analysis.", type(parsed_data).__name__)
        core_missing = [k if isinstance(k, str) else k[0] for k in _CORE_CODEMETA_FIELDS]
        # Extended fields are just strings in the list _EXTENDED_CODEMETA_FIELDS
        extended_missing = _EXTENDED_CODEMETA_FIELDS
        all_checked_count = len(_CORE_CODEMETA_FIELDS) + len(_EXTENDED_CODEMETA_FIELDS)
        return {
            'score': 0.0, 'missing_keys': core_missing, # Backward compatibility
            'core_score': 0.0, 'core_missing': core_missing,
            'extended_score': 0.0, 'extended_missing': extended_missing,
            'present_fields': [], 'all_fields_count': all_checked_count,
            'present_fields_count': 0
        }

    # --- Check Core Fields ---
    core_found_count, core_missing = _check_keys(parsed_data, _CORE_CODEMETA_FIELDS)
    core_total_checked = len(_CORE_CODEMETA_FIELDS)
    core_score = core_found_count / core_total_checked if core_total_checked > 0 else 0.0
    logger.debug("Comprehensive Core Check - Found: %d/%d, Score: %.2f",
                 core_found_count, core_total_checked, core_score)

    # --- Check Extended Fields ---
    # Treat each extended field as a single key to check
    extended_keys_to_check: List[Union[str, Tuple[str, List[str]]]] = _EXTENDED_CODEMETA_FIELDS
    extended_found_count, extended_missing = _check_keys(parsed_data, extended_keys_to_check)
    extended_total_checked = len(_EXTENDED_CODEMETA_FIELDS)
    extended_score = extended_found_count / extended_total_checked if extended_total_checked > 0 else 0.0
    logger.debug("Comprehensive Extended Check - Found: %d/%d, Score: %.2f",
                 extended_found_count, extended_total_checked, extended_score)

    # --- Identify All Present Fields in the Original Data ---
    # Find keys with meaningful values as defined in _check_keys helper
    present_fields = sorted([
        key for key, value in parsed_data.items()
        if value is not None and value != '' and value != [] and value != {}
    ])
    present_fields_count = len(present_fields)

    # Calculate total unique fields checked (core + extended)
    all_fields_checked_count = core_total_checked + extended_total_checked

    # --- Assemble Results ---
    result = {
        'score': core_score, # Maintain basic score key for compatibility
        'missing_keys': core_missing, # Maintain basic missing keys for compatibility
        'core_score': core_score,
        'core_missing': core_missing,
        'extended_score': extended_score,
        'extended_missing': extended_missing,
        'present_fields': present_fields, # Sorted list of keys with values
        'all_fields_count': all_fields_checked_count, # Total fields *we* checked
        'present_fields_count': present_fields_count # Count of keys with values in *input*
    }

    logger.debug("Present fields count in input: %d", present_fields_count)

    return result


# --- Schema Validation ---

@lru_cache(maxsize=1)
def _load_codemeta_schema() -> Optional[Dict[str, Any]]:
    """
    Loads the bundled CodeMeta JSON schema (codemeta_schema_3.0.0.json) using pkgutil.

    Uses LRU cache to load the schema only once per run. Logs errors if loading fails.

    Returns:
        The loaded schema as a dictionary, or None if loading fails.
    """
    # Path relative to the 'rsma' package directory where this file resides
    schema_path = "schemas/codemeta_schema_3.0.0.json"
    # Determine the package name dynamically (should be 'rsma')
    package_name = __name__.split('.')[0]

    logger.debug("Attempting to load schema '%s' from package '%s'...", schema_path, package_name)
    try:
        # pkgutil.get_data is the standard way to access package data files
        schema_bytes = pkgutil.get_data(package_name, schema_path)

        if schema_bytes is None:
             # This is the most likely error if pyproject.toml (or setup.py) is misconfigured
             logger.error(
                 "Failed to load schema: '%s' not found within package '%s'. "
                 "Ensure schema is included via 'package_data' in pyproject.toml (or setup.py/cfg).",
                 schema_path, package_name
             )
             return None

        # Decode bytes to string assuming UTF-8 encoding
        schema_str = schema_bytes.decode('utf-8')
        # Parse the JSON string into a Python dictionary
        schema = json.loads(schema_str)
        logger.info("Successfully loaded and parsed CodeMeta schema: %s", schema_path)
        return schema

    except FileNotFoundError:
        # pkgutil.get_data should handle this, but catch just in case
        logger.error(
            "Schema file not found at expected package path: %s/%s. "
            "This might indicate an issue with package installation or structure.",
            package_name, schema_path
        )
        return None
    except json.JSONDecodeError as e:
        logger.error("Failed to parse JSON content of schema file %s: %s", schema_path, e)
        return None
    except Exception as e:
        # Catch other unexpected errors (e.g., permission issues, pkgutil internal errors)
        logger.error("An unexpected error occurred loading schema %s: %s", schema_path, e, exc_info=True)
        return None


def validate_codemeta_schema(instance: Any) -> Dict[str, Any]:
    """
    Validates a Python object against the bundled CodeMeta v3.0.0 JSON schema.

    Args:
        instance: The Python object (expected to be a dictionary) to validate.

    Returns:
        A dictionary containing:
        - 'valid': Boolean indicating if the instance is valid against the schema.
        - 'errors': A list of concise validation error message strings if invalid,
                    otherwise None. Returns a specific error message if schema loading
                    fails or the instance is not a dictionary.
    """
    # --- Load Schema ---
    schema = _load_codemeta_schema()
    if schema is None:
        logger.error("Cannot perform CodeMeta validation because schema loading failed.")
        # Provide a distinct error message indicating setup/packaging issue
        return {'valid': False, 'errors': ["Schema Loading Error: Could not load bundled CodeMeta schema."]}

    # --- Validate Input Type ---
    if not isinstance(instance, dict):
        logger.warning("Schema validation input is not a dictionary (type: %s). Validation failed.", type(instance).__name__)
        return {'valid': False, 'errors': ["Validation Input Error: Instance to validate is not a dictionary."]}

    # --- Perform Validation ---
    try:
        # jsonschema.validate() raises ValidationError on failure, returns None on success.
        jsonschema.validate(instance=instance, schema=schema)
        logger.debug("CodeMeta instance is valid against the schema.")
        return {'valid': True, 'errors': None}
    except JsonSchemaValidationError as e:
        # Format a user-friendly summary of the primary validation error
        # Path gives context ($ is root, $.author[0].name etc.), message gives the issue.
        error_path = "$." + ".".join(map(str, e.path)) if e.path else "$"
        # Use the specific message from the validation error
        error_msg = f"Schema Error at {error_path}: {e.message}"
        # For detailed debugging, one might log the full error: logger.debug("Full jsonschema error: %s", e)
        logger.warning("CodeMeta instance failed schema validation: %s", error_msg)
        # Return just the primary error message for simplicity in CSV/JSON output
        # For more detail, consider iterating e.context or using iter_errors
        return {'valid': False, 'errors': [error_msg]}
    except Exception as e:
        # Catch other potential errors during the validation call itself
        error_msg = f"Unexpected error during CodeMeta schema validation execution: {e}"
        logger.error(error_msg, exc_info=True)
        return {'valid': False, 'errors': [error_msg]}