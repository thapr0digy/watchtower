# Desc: utility functions
import json
import logging
import time
from pathlib import Path

logger = logging.getLogger(__name__)

CACHE_DIR = Path("watchtower/cache")
STATUS_SUCCESS = 0
STATUS_FAILURE = 1
TLSX_FILE = CACHE_DIR / "tlsx_domains.txt"
TLSX_CACHE_FILE = CACHE_DIR / "tlsx.json"
TLSX_OPTIONS = [
        "tlsx",
        "-l",
        TLSX_FILE, 
        "-so", 
        "-tv", 
        "-cipher", 
        "-hash", 
        "sha256", 
        "-jarm", 
        "-wc", 
        "-tps",
        "-ce",
        "-ex",
        "-ss",
        "-mm",
        "-re",
        "-cert",
        "-json",
        "-o",
        TLSX_CACHE_FILE
        ]

# Function helpers
def check_cache(tool_name: str, cache_age: int = 86400):
    # Look for .json in the cache directory
    tool_cache = CACHE_DIR / f"{tool_name}.json"
    # If the file exists, check the last modified time
    if tool_cache.exists() and tool_cache.stat().st_size > 0:
        # If the file is older than 24 hours, delete it
        if (time.time() - tool_cache.stat().st_mtime) > cache_age:
            logger.info(f"{tool_name} cache is older than 24 hours. Deleting...")
            tool_cache.unlink()
            return False
    else:
        logger.info(f"{tool_name} cache does not exist. Running {tool_name}...")
    return False

def load_cache(tool_name: str):
    # Load the cache file
    tool_cache = CACHE_DIR / f"{tool_name}.json"
    with open(tool_cache, "r") as f:
        return json.load(f)