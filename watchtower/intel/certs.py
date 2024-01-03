import argparse
import json
import logging
import neo4j
import subprocess
import sys
import time

from pathlib import Path
from typing import List
from typing import Dict

import watchtower.util
from watchtower.util import CACHE_DIR, TLSX_OPTIONS, TLSX_FILE

logger = logging.getLogger(__name__)

def start_tlsx_ingest(neo4j_session: neo4j.Session, config: argparse.Namespace):
    """
    Run tlsx and ingest the results into the database
    """
    
    logger.info("Retrieving all domains from the database")
    # Get all domains from the database with web services and
    # return as a list of strings hostname:port
    domains = get_all_domains(neo4j_session, config)
    
    if len(domains) == 0:
        logger.warning(f"No domains found in database.")
        return
    
    logger.info("Writing domains to tlsx file")
    with open(TLSX_FILE, "w") as f:
        for domain in domains:
            f.write(f"{domain}\n")
    
    tlsx_results = None
    cache_exists = watchtower.util.check_cache('tlsx')
    if cache_exists:
        tlsx_results = watchtower.util.load_cache('tlsx')
        print(tlsx_results)
    else:
        # Run tlsx on all domains
        tlsx_results = subprocess.run(TLSX_OPTIONS, encoding='utf-8', capture_output=True)
        print(tlsx_results)
        if tlsx_results.returncode != 0:
            logger.error("tlsx failed. Exiting...")
            sys.exit(1)


def get_all_domains(neo4j_session: neo4j.Session, config: argparse.Namespace):
    """
    Get all domains with web ports from the database
    """
    query = """
    MATCH p=(d:Domain)-[r1]-(ip:IPAddress)-[r2]-(s:Service)
    WHERE s.service IN ['https', 'https-alt']
    RETURN apoc.text.join([d.hostname, toString(s.port)],":") as host_port
    """
    logger.info("Getting all domains from the database")
    results = neo4j_session.run(query)
    return results.value()

def sync(neo4j_session: neo4j.Session, config: argparse.Namespace):
    """
    Sync the data from the various sources into the database
    """
    logger.info("Starting sync with update tag '%d'", config.update_tag)
    start_tlsx_ingest(neo4j_session, config)
