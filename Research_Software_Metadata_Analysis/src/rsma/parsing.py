# src/rsma/parsing.py

import json
import logging
from typing import Dict, Any, Optional

logger = logging.getLogger(__name__)

def parse_codemeta(content_string: Optional[str]) -> Dict[str, Any]:
    """
    Parses a string assumed to be JSON content (typically codemeta.json).

    Args:
        content_string: The string content to parse. Can be None or empty.

    Returns:
        A dictionary with keys:
        - 'parsed_data': The parsed Python dictionary or list if successful,
                         otherwise None. Returns None for empty or invalid JSON.
        - 'parse_error': An error message string if parsing failed,
                         otherwise None.
    """
    # --- Input Validation ---
    if content_string is None:
        logger.debug("parse_codemeta received None input.")
        # Treat None input as an error condition for parsing JSON
        return {'parsed_data': None, 'parse_error': 'Input content string is None'}
    if not isinstance(content_string, str):
         logger.warning("parse_codemeta received non-string input (type: %s).", type(content_string).__name__)
         return {'parsed_data': None, 'parse_error': f'Input content is not a string (type: {type(content_string).__name__})'}
    # An empty string or whitespace is invalid JSON
    trimmed_content = content_string.strip()
    if not trimmed_content:
        logger.debug("parse_codemeta received empty or whitespace-only string.")
        return {'parsed_data': None, 'parse_error': 'Input content string is empty or whitespace'}

    # --- Parsing ---
    try:
        # Use the stripped content to handle leading/trailing whitespace
        parsed_data = json.loads(trimmed_content)
        logger.debug("Successfully parsed JSON content.")
        return {'parsed_data': parsed_data, 'parse_error': None}
    except json.JSONDecodeError as e:
        # Provide a specific error message from the exception
        error_msg = f"Failed to decode JSON: {e.msg} (at line {e.lineno} column {e.colno})"
        logger.warning(error_msg)
        return {'parsed_data': None, 'parse_error': error_msg}
    except Exception as e:
        # Catch any other unexpected errors during parsing
        error_msg = f"Unexpected error during JSON parsing: {e}"
        logger.error(error_msg, exc_info=True)
        return {'parsed_data': None, 'parse_error': error_msg}