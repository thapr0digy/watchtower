import argparse
import json
import logging
import neo4j
import subprocess
import socket
import time

from pathlib import Path
from typing import List
from typing import Dict

logger = logging.getLogger(__name__)

CACHE_DIR = Path("watchtower/cache")

def sync(neo4j_session: neo4j.Session, config: argparse.Namespace):
    
    # Join the list of domains into a comma separated string
    domain_list = ",".join(config.domains)

    # TODO: Check the cache for results from the last run. If older than 24 hours, run again
    logger.info(f"Running on domain(s): {config.domains}")

    cached_result = []
    subprocess_result = None
    subdomain_list = None
    # TODO: Remove in favor of the check_cache function from watchtower/util.py
    cache_updated = check_subfinder_cache()
    if cache_updated:
        logger.info("Using cached subfinder results")
        # Load cached results from file
        with open(CACHE_DIR / "subfinder.json", "r") as f:
            for line in f:
                cached_result.append(json.loads(line))
        subdomain_list = cached_result
    else:
        logger.info("Running subfinder")
        # Run subfinder and output to a file
        subprocess_result = subprocess.run(
                ["subfinder", "-d", f"{domain_list}", "-all", "-json", "-cs", "-o", "watchtower/cache/subfinder.json"], 
                encoding='utf-8', capture_output=True)
        # FIXME: Subfinder doesn't output proper JSON data. We need to fix this into a proper object
        subdomain_list = json.loads(json.dumps(
                [json.loads(res) for res in subprocess_result.stdout.splitlines()]))
    # FIXME: We need to validate the data before we ingest it into the database.
    # This includes whether they resolve or not. We can use the DNS module for this.

    # Validate each subdomain
    for subdomain in subdomain_list:
        try:
            ip = socket.gethostbyname(subdomain['host'])
            # Hostname is valid and okay to ingest
        except socket.gaierror as e:
            logger.warning(f"Invalid hostname: {subdomain['host']}. Skipping...")
            subdomain_list.remove(subdomain)
            continue

    create_domains_sources(neo4j_session, config.update_tag, subdomain_list)
    link_domain_source(neo4j_session, config.update_tag, subdomain_list)

def check_subfinder_cache():
    # Identify the cache directory
    cache_dir = Path("watchtower/cache")
    # Look for subfinder.json in the cache directory
    subfinder_cache = cache_dir / "subfinder.json"
    # If the file exists, check the last modified time
    if subfinder_cache.exists():
        # If the file is older than 24 hours, delete it
        if (time.time() - subfinder_cache.stat().st_mtime) > 86400:
            logger.info("Subfinder cache is older than 24 hours. Deleting...")
            subfinder_cache.unlink()
            return False
        else:
            logger.info("Subfinder cache is less than 24 hours old. Using cached results...")
            return True
    logger.info("Subfinder cache does not exist. Running subfinder...")
    return False

def create_domains_sources(neo4j_session: neo4j.Session, update_tag: int, data: List[Dict]):
    """
    Ingest list of domains as :Domain and set the id and lastupdated properties
    """

    query = """
    UNWIND $Data as row
    MERGE (host:Domain {hostname: row.host})
    ON CREATE SET host.firstseen = timestamp() / 1000
    SET host.lastupdated = $update_tag
    MERGE (tld:DNSZone {hostname: row.input})
    ON CREATE SET tld.firstseen = timestamp() / 1000
    SET tld.lastupdated = $update_tag
    FOREACH (source in row.sources |
        MERGE (src:DataSource {id: source})
        ON CREATE SET src.firstseen = timestamp() / 1000
        SET src.lastupdated = $update_tag
    )
    """

    logger.info("Creating Domain")
    neo4j_session.run(query, Data=data, update_tag=update_tag)


def link_domain_source(neo4j_session: neo4j.Session, update_tag: int, data: List[Dict]):
    """
    Link :Domain records to the :DataSource records
    """

    query = """
    UNWIND $Data as row
    MATCH (host:Domain {id: row.host})
    WITH row, host
    UNWIND row.sources as source
    MATCH (src:DataSource {id: source})
    FOREACH (source in row.sources |
        MERGE (host)-[r:CAME_FROM]-(src)
        ON CREATE SET r.firstseen = timestamp() / 1000
        SET r.lastupdated = $update_tag
    )
    """

    logger.info("Linking Domain to Source records")
    neo4j_session.run(query, Data=data, update_tag=update_tag)
