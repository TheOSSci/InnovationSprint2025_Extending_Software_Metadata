# src/rsma/settings.py
import os
import logging
from typing import Optional
from dotenv import load_dotenv, find_dotenv

logger = logging.getLogger(__name__)

def load_github_token() -> Optional[str]:
    """
    Loads the GitHub token securely from a .env file or environment variables.

    Prioritizes environment variables over `.env` files. Looks for a variable
    named GITHUB_TOKEN. Searches for `.env` files in the current working
    directory and parent directories.

    Returns:
        The GitHub token string if found and non-empty, otherwise None.
        Logs an error if the token is not found or invalid.
    """
    # Check environment variable first
    token_from_env = os.getenv("GITHUB_TOKEN")

    if token_from_env and isinstance(token_from_env, str) and token_from_env.strip():
        logger.info("GITHUB_TOKEN loaded successfully from environment variable.")
        # Log partial token for debugging confirmation if needed, be cautious
        # logger.debug(f"Token starts: {token_from_env[:4]}...")
        return token_from_env
    elif token_from_env:
         logger.warning("GITHUB_TOKEN environment variable found but is empty or invalid.")

    # If not found in env, try loading from .env file
    # find_dotenv() searches CWD and parents; returns path or empty string
    dotenv_path = find_dotenv(raise_error_if_not_found=False, usecwd=True)

    if dotenv_path:
        logger.debug(f"Attempting to load environment variables from: {dotenv_path}")
        # load_dotenv returns True if it loaded the file successfully
        loaded = load_dotenv(dotenv_path=dotenv_path, override=False) # override=False: don't overwrite existing env vars
        if loaded:
            logger.debug(f".env file loaded successfully from {dotenv_path}.")
            token_from_dotenv = os.getenv("GITHUB_TOKEN")
            if token_from_dotenv and isinstance(token_from_dotenv, str) and token_from_dotenv.strip():
                logger.info("GITHUB_TOKEN loaded successfully from .env file.")
                # logger.debug(f"Token starts: {token_from_dotenv[:4]}...")
                return token_from_dotenv
            elif token_from_dotenv:
                 logger.warning("GITHUB_TOKEN found in .env file but is empty or invalid.")
            else:
                 logger.warning("GITHUB_TOKEN variable not found within the loaded .env file.")
        else:
            logger.error(f"Failed to load .env file from path: {dotenv_path}")
    else:
        logger.debug(".env file not found in current directory or parent directories.")

    # If token wasn't found in either environment or .env file
    logger.error(
        "GITHUB_TOKEN not found. Please ensure it is set in your .env file "
        "or as an environment variable GITHUB_TOKEN."
    )
    return None