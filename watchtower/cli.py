#!/usr/bin/env python3

# This software is meant to take data from multiple sources such as httpx, subfinder, dnsx, etc
# and ingest into a Neo4j database.

import argparse
import getpass
import logging
import json
import os
import sys
from pathlib import Path
import watchtower.sync

logger = logging.getLogger(__name__)


class CLI:

    def __init__(self, sync):
        self.sync = sync
        self.parser = self._get_args()

    def _get_args(self):
        parser = argparse.ArgumentParser(prog="watchtower")
        parser.add_argument("-d", "--domains", type=str, default="connectbase.com",
                            help="Obtain information for this list of command separated domains")
        parser.add_argument("-dL", "--domain-file", type=str, default=None,
                            help="File with list of domains to go through")
        parser.add_argument("-nL", "--nmap-xml-file", type=str, default=None, 
                            help="Location of nmap XML to ingest into Neo4j")
        parser.add_argument("--neo4j-uri", type=str, default="bolt://localhost:7687",
                            help="A valid Neo4j URI to sync against.")
        parser.add_argument("--neo4j-database", type=str, default="neo4j",
                            help="A valid Neo4j URI to sync against.")
        parser.add_argument("--neo4j-user", type=str, default="neo4j",
                            help="Username to authenticate to Neo4j")
        parser.add_argument("--neo4j-password-prompt", action="store_true", default=None,
                            help="Interactive prompt for password to authenticate to Neo4j")
        parser.add_argument("--neo4j-password-env-var", type=str, default=None,
                            help='The name of an environment variable containing a password with which to authenticate to Neo4j.')
        parser.add_argument("--wix-token-env-var", type=str, default=None,
                            help="The name of an environment variable containing a Wix API token.")
        parser.add_argument("--update-tag", type=int, default=None,
                            help="Tag to use for checking for updates against")
        parser.add_argument("--quiet", "-q", action='store_true',
                            help="Only enable logging.WARNING messages")
        parser.add_argument("-v", "--verbose", action='store_true',
                            help="Enable logging.DEBUG messages")
        return parser

    def main(self, argv=None):
        # Get CLI arguments
        config: argparse.Namespace = self.parser.parse_args()

        # Logging config
        if config.verbose:
            logging.getLogger('watchtower').setLevel(logging.DEBUG)
        elif config.quiet:
            logging.getLogger('watchtower').setLevel(logging.WARNING)
        else:
            logging.getLogger('watchtower').setLevel(logging.INFO)
        logger.debug(
            "Launching watchtower with CLI configuration: %r", vars(config))
        # Setting logger defaults
        logging.basicConfig(
            format="[%(levelname)s] %(funcName) %(asctime)s %(message)s", level=logging.INFO)
        logging.getLogger('neo4j').setLevel(logging.WARNING)

        if config.verbose:
            logger.setLevel(logging.DEBUG)

        if config.neo4j_user:
            config.neo4j_password = None
            if config.neo4j_password_prompt:
                logger.info(
                    "Reading password for Neo4j user '%s' interactively.", config.neo4j_user)
                config.neo4j_password = getpass.getpass()
            elif config.neo4j_password_env_var:
                logger.debug(
                    "Reading password for Neo4j user '%s' from environment variable '%s'.",
                    config.neo4j_user,
                    config.neo4j_password_env_var,
                )
                config.neo4j_password = os.environ.get(
                    config.neo4j_password_env_var)
            if not config.neo4j_password:
                logger.warning(
                    "Neo4j username was provided but a password could not be found.")
        else:
            config.neo4j_password = None

        # Retrieve Wix API token
        if config.wix_token_env_var:
            logger.debug(
                "Reading Wix API token from environment variable '%s'.",
                config.wix_token_env_var,
            )
            config.wix_token = os.environ.get(config.wix_token_env_var)
        else:
            config.wix_token = None
            logger.warning("Wix API token was not provided. No Wix data will be ingested.")

        # Use as nmap XML location file. Can take in a file or directory of XML files

        #if config.nmap_xml_file:
            #self.sync.add_stage('nmap', watchtower.intel.nmap.sync)
        
        if config.domains:
            # Split at the comma and turn into list of domains
            config.domains = config.domains.split(",")
        else:
            logger.error("Missing domain. Defaulting to connectbase.com")

        # Run ingester based on location
        try:
            return watchtower.sync.run_sync(self.sync, config)
        except KeyboardInterrupt:
            sys.exit(1)


def main(argv=None):
    logging.basicConfig(format="%(levelname)s:%(name)s.%(funcName)s:%(created).0f:%(message)s", level=logging.INFO)
    logging.getLogger('neo4j').setLevel(logging.WARNING)
    argv = argv if not None else sys.argv[1:]
    default_sync = watchtower.sync.build_default_sync()
    sys.exit(CLI(default_sync).main())
