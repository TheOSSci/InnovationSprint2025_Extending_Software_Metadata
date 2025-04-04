# src/rsma/github_client.py

import logging
import base64
from datetime import datetime
from typing import List, Dict, Any, Optional, Union

from github import Github, ContentFile, Repository
from github.GithubException import (
    GithubException,
    RateLimitExceededException,
    UnknownObjectException,
    BadCredentialsException, # Specific exception for auth errors
)

logger = logging.getLogger(__name__)

def _get_rate_limit_message(e: RateLimitExceededException) -> str:
    """Helper to format rate limit error messages consistently including reset time."""
    reset_time_str = "unknown time"
    limit_str = "unknown limit"
    # Extract details from exception headers if available
    if e.headers:
        limit_str = e.headers.get('x-ratelimit-limit', 'unknown limit')
        if "x-ratelimit-reset" in e.headers:
            try:
                reset_timestamp = int(e.headers["x-ratelimit-reset"])
                reset_time_dt = datetime.fromtimestamp(reset_timestamp)
                # Format timestamp clearly with timezone info if possible (might be UTC)
                reset_time_str = reset_time_dt.strftime('%Y-%m-%d %H:%M:%S %Z')
            except (ValueError, TypeError):
                reset_time_str = "invalid timestamp in header"

    return f"Rate limit exceeded. Limit: {limit_str}. Resets at {reset_time_str}."


def get_metadata_files(
    repo_full_name: str, filenames_to_check: List[str], github_client: Github
) -> Dict[str, Dict[str, Any]]:
    """
    Fetches the content of specified files from a single GitHub repository.

    Handles repository access errors (404, rate limits, auth) and individual file
    fetch errors (404, decode errors, non-file types). If repository access fails,
    all requested files will have status 'error' with the repo-level message.

    Args:
        repo_full_name: The full name of the repository (e.g., "owner/repo").
        filenames_to_check: A list of filenames (paths relative to repo root) to fetch.
        github_client: An authenticated PyGithub Github instance.

    Returns:
        A dictionary where keys are the requested filenames. Values are dicts containing:
        - 'status': 'found', 'not_found', 'error', or 'skipped'.
        - 'content': Decoded file content (UTF-8 string) if found, else None.
        - 'error': Error message if status is 'error', 'not_found', or 'skipped'.
    """
    # Initialize results with a default 'skipped' state, assuming repo access might fail
    results: Dict[str, Dict[str, Any]] = {
        filename: {'status': 'skipped', 'content': None, 'error': 'Repository access not attempted or failed'}
        for filename in filenames_to_check
    }
    repo: Optional[Repository.Repository] = None
    repo_access_error_msg: Optional[str] = None

    # --- Step 1: Try to access the Repository object ---
    try:
        logger.debug("Attempting to access repository object for '%s'...", repo_full_name)
        repo = github_client.get_repo(repo_full_name)
        logger.debug("Successfully accessed repository object for '%s'.", repo_full_name)
    except UnknownObjectException:
        # Repository does not exist or user lacks permission to see it
        repo_access_error_msg = f"Repository '{repo_full_name}' not found or access denied (404)."
        logger.warning(repo_access_error_msg)
    except BadCredentialsException:
        # Authentication failed - token is likely invalid or lacks permissions
        repo_access_error_msg = "GitHub authentication failed (401 - Bad Credentials). Check token validity and permissions."
        logger.error(repo_access_error_msg) # Log as error as it stops processing
    except RateLimitExceededException as e:
        # Rate limit hit during the initial repo access
        repo_access_error_msg = f"Failed accessing repository '{repo_full_name}': {_get_rate_limit_message(e)}"
        logger.error(repo_access_error_msg)
    except GithubException as e:
        # Other potential GitHub API errors (e.g., 5xx server errors)
        repo_access_error_msg = f"GitHub API error accessing repository '{repo_full_name}': Status {e.status}, Data: {e.data}"
        logger.error(repo_access_error_msg)
    except Exception as e:
        # Catch other unexpected errors (network issues, etc.) during repo access
        repo_access_error_msg = f"Unexpected error accessing repository '{repo_full_name}': {e}"
        logger.error(repo_access_error_msg, exc_info=True)

    # If repository access failed, update all file results and return early
    if repo_access_error_msg:
        for filename in filenames_to_check:
            results[filename]['status'] = 'error'
            # Prepend context to the error message
            results[filename]['error'] = f"Repo Access Error: {repo_access_error_msg}"
        return results

    # --- Step 2: Repository accessed, proceed to fetch each file ---
    if not repo:
         # This check is defensive; should not be reachable if repo_access_error_msg is None
         logger.error("Internal logic error: Repository object is None despite no access error for '%s'.", repo_full_name)
         for filename in filenames_to_check:
            results[filename]['status'] = 'error'
            results[filename]['error'] = 'Internal Error: Repository object unexpectedly None.'
         return results

    # --- Fetch Files Loop ---
    for file_path in filenames_to_check:
        try:
            logger.debug("Attempting to get contents for '%s' in repo '%s'...", file_path, repo_full_name)
            # Use the acquired repository object to fetch file contents
            content_file_or_list: Union[ContentFile.ContentFile, List[ContentFile.ContentFile]] = repo.get_contents(file_path)

            # Handle case where the path points to a directory
            if isinstance(content_file_or_list, list):
                err = f"Path '{file_path}' is a directory, not a file."
                logger.warning("%s in repo '%s'.", err, repo_full_name)
                results[file_path] = {'status': 'error', 'content': None, 'error': err}
                continue # Process next file in the list

            # Should now be a single ContentFile object
            content_file: ContentFile.ContentFile = content_file_or_list

            # Check if the object type is actually a 'file' (could be 'symlink', 'submodule', etc.)
            if content_file.type != 'file':
                err = f"Path '{file_path}' exists but is not a file (type: {content_file.type})."
                logger.warning("%s in repo '%s'.", err, repo_full_name)
                results[file_path] = {'status': 'error', 'content': None, 'error': err}
                continue

            # --- Step 3: Decode Content ---
            # The 'decoded_content' attribute holds the file content as bytes
            decoded_bytes = content_file.decoded_content
            if decoded_bytes is None:
                # This can happen for empty files. Treat as found with empty content.
                logger.info("File '%s' in repo '%s' has None for decoded_content. Treating as empty.", file_path, repo_full_name)
                results[file_path] = {'status': 'found', 'content': "", 'error': None}
                continue

            try:
                # Decode the bytes using UTF-8 (standard for text files like JSON)
                decoded_content = decoded_bytes.decode('utf-8')
                logger.debug("Successfully fetched and decoded '%s' from '%s'.", file_path, repo_full_name)
                results[file_path] = {'status': 'found', 'content': decoded_content, 'error': None}
            except UnicodeDecodeError as e:
                # File exists but content is not valid UTF-8
                err = f"Failed to decode content of '{file_path}' as UTF-8: {e}"
                logger.error("%s in repo '%s'.", err, repo_full_name)
                results[file_path] = {'status': 'error', 'content': None, 'error': err}
            except Exception as decode_e:
                # Catch other potential errors during decoding
                err = f"Unexpected error decoding content of '{file_path}': {decode_e}"
                logger.error("%s in repo '%s'.", err, repo_full_name, exc_info=True)
                results[file_path] = {'status': 'error', 'content': None, 'error': err}

        # --- Handle File-Specific Exceptions during get_contents() call ---
        except UnknownObjectException:
            # This specific file path was not found within the repository
            logger.info("File '%s' not found in repo '%s' (404).", file_path, repo_full_name)
            results[file_path] = {'status': 'not_found', 'content': None, 'error': 'File not found (404)'}
        except RateLimitExceededException as e:
            # Rate limit hit specifically while fetching this file
            err = f"Failed fetching file '{file_path}': {_get_rate_limit_message(e)}"
            logger.error("%s from repo '%s'.", err, repo_full_name)
            results[file_path] = {'status': 'error', 'content': None, 'error': err}
            # Consider breaking the loop here? If one file hits rate limit, others likely will too.
            # break # Optional: Stop processing files for this repo if rate limited.
        except GithubException as e:
            # Other API errors specific to fetching this file (permissions, server issues)
            err = f"GitHub API error fetching file '{file_path}': Status {e.status}, Data: {e.data}"
            logger.error("%s from repo '%s'.", err, repo_full_name)
            results[file_path] = {'status': 'error', 'content': None, 'error': err}
        except Exception as e:
            # Catch any other unexpected errors during this file's processing
            err = f"Unexpected error fetching or processing file '{file_path}': {e}"
            logger.error("%s from repo '%s'.", err, repo_full_name, exc_info=True)
            results[file_path] = {'status': 'error', 'content': None, 'error': err}

    return results


def get_repository_metadata(repo_full_name: str, github_client: Github) -> Dict[str, Any]:
    """
    Fetches core metadata for a specific GitHub repository.

    Args:
        repo_full_name: The full name of the repository (e.g., "owner/repo").
        github_client: An authenticated PyGithub Github instance.

    Returns:
        A dictionary containing:
        - 'data': Dict with repo metadata if successful, None otherwise. Includes
                  keys like 'full_name', 'html_url', description, counts, dates (ISO strings),
                  'language', 'topics', 'license' (dict or None), status flags.
        - 'error': Error message string if fetching failed, None otherwise.
    """
    repo: Optional[Repository.Repository] = None
    metadata: Optional[Dict[str, Any]] = None
    error_message: Optional[str] = None

    try:
        logger.debug("Attempting to get repository metadata for '%s'...", repo_full_name)
        # This is the primary API call to get the repo object
        repo = github_client.get_repo(repo_full_name)

        # --- Safely extract license information ---
        repo_license_data: Optional[Dict[str, Any]] = None
        # The repo.license attribute itself might be None
        if repo.license:
            repo_license_data = {
                # Use getattr for safety in case attributes are unexpectedly missing from license object
                "spdx_id": getattr(repo.license, 'spdx_id', None),
                "name": getattr(repo.license, 'name', None),
                "url": getattr(repo.license, 'url', None),
            }

        # --- Convert datetimes to ISO 8601 strings, handling potential None values ---
        created_at_iso = repo.created_at.isoformat() if isinstance(repo.created_at, datetime) else None
        pushed_at_iso = repo.pushed_at.isoformat() if isinstance(repo.pushed_at, datetime) else None
        updated_at_iso = repo.updated_at.isoformat() if isinstance(repo.updated_at, datetime) else None

        # --- Extract topics using the dedicated method, handle potential errors ---
        topics: List[str] = []
        try:
            # This makes another API call
            topics = repo.get_topics()
        except GithubException as topic_e:
             # Log warning but don't treat as fatal for the overall metadata fetch
             logger.warning("Could not fetch topics for '%s': Status %s, Data: %s", repo_full_name, topic_e.status, topic_e.data)
             # Optionally include this warning in the main error message?
        except Exception as topic_e_unex:
             # Catch unexpected errors during topic fetch
              logger.warning("Unexpected error fetching topics for '%s': %s", repo_full_name, topic_e_unex)

        # --- Construct metadata dictionary from repo attributes ---
        metadata = {
            "full_name": repo.full_name,
            "html_url": repo.html_url,
            "description": repo.description,
            "stargazers_count": repo.stargazers_count,
            "forks_count": repo.forks_count,
            "watchers_count": repo.watchers_count,
            "open_issues_count": repo.open_issues_count,
            "created_at": created_at_iso,
            "pushed_at": pushed_at_iso,
            "updated_at": updated_at_iso,
            "size": repo.size, # Repository size in Kilobytes
            "language": repo.language, # Primary language detected by GitHub
            "has_issues": repo.has_issues,
            "has_projects": repo.has_projects,
            "has_wiki": repo.has_wiki,
            "is_fork": repo.fork, # Boolean indicating if it's a fork
            "is_archived": repo.archived, # Boolean indicating if archived
            "is_disabled": repo.disabled, # Boolean indicating if disabled (e.g., due to TOS violation)
            "topics": topics, # List of topic strings
            "license": repo_license_data, # Dict containing license details or None
        }
        logger.debug("Successfully extracted metadata for '%s'.", repo_full_name)

    # --- Handle Expected Exceptions during the initial get_repo() call ---
    except UnknownObjectException:
        error_message = f"Repository '{repo_full_name}' not found or access denied (404)."
        logger.warning(error_message)
    except BadCredentialsException:
        error_message = "GitHub authentication failed (401 - Bad Credentials). Check token validity and permissions."
        logger.error(error_message) # Treat as error
    except RateLimitExceededException as e:
        error_message = f"Failed getting metadata for '{repo_full_name}': {_get_rate_limit_message(e)}"
        logger.error(error_message)
    except GithubException as e:
        # Catch other GitHub API errors during get_repo
        error_message = f"GitHub API error getting metadata for '{repo_full_name}': Status {e.status}, Data: {e.data}"
        logger.error(error_message)
    except Exception as e:
        # Catch any other unexpected errors during repo access or attribute reading
        error_message = f"Unexpected error getting metadata for '{repo_full_name}': {e}"
        logger.error(error_message, exc_info=True)

    # Return the structured result
    return {"data": metadata, "error": error_message}