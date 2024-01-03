import argparse
import json
import logging
import neo4j.exceptions
import time

import watchtower.intel.dns
import watchtower.intel.subfinder
import watchtower.intel.create_indexes
import watchtower.intel.nmap
import watchtower.intel.certs

from collections import OrderedDict
from typing import Callable
from typing import List
from typing import Tuple

from watchtower.util import STATUS_FAILURE
from watchtower.util import STATUS_SUCCESS
from neo4j import GraphDatabase


logger = logging.getLogger(__name__)


class Sync:

    def __init__(self):
        self._stages = OrderedDict()

    def add_stage(self, name: str, func: Callable):
        """
        Add stage for the workflow to be run for ingestion
        """
        self._stages[name] = func

    def add_stages(self, stages: List[Tuple[str, Callable]]):
        """
        Add stages for the workflow to be run
        """
        for name, func in stages:
            self.add_stage(name, func)

    def run(self, neo4j_driver: neo4j.Driver, config: argparse.Namespace):
        """
        Creates the session, runs all the stages
        """
        logger.info("Starting sync with update tag '%d'", config.update_tag)
        with neo4j_driver.session(database=config.neo4j_database) as neo4j_session:
            for stage_name, stage_func in self._stages.items():
                logger.info("Starting sync stage '%s'", stage_name)
                try:
                    stage_func(neo4j_session, config)
                except (KeyboardInterrupt, SystemExit):
                    logger.warning(
                        "Sync interrupted during stage '%s'.", stage_name)
                    raise
                except Exception:
                    logger.exception(
                        "Unhandled exception during sync stage '%s'", stage_name)
                    raise  # TODO this should be configurable
                logger.info("Finishing sync stage '%s'", stage_name)
        logger.info("Finishing sync with update tag '%d'", config.update_tag)
        return STATUS_SUCCESS


def run_sync(sync: Sync, config: argparse.Namespace) -> bool:
    """
    Returns the success or failure of running the ingestion engine
    """

    neo4j_auth = None
    if config.neo4j_user or config.neo4j_password:
        neo4j_auth = (config.neo4j_user, config.neo4j_password)
    try:
        neo4j_driver = GraphDatabase.driver(
            config.neo4j_uri,
            auth=neo4j_auth,
            max_connection_lifetime=200
        )
    except neo4j.exceptions.ServiceUnavailable as e:
        logger.debug("Error occurred during Neo4j connect.", exc_info=True)
        logger.err or (
            (
                "Unable to connect to Neo4j using the provided URI '%s', an error occurred: '%s'. Make sure the Neo4j "
                "server is running and accessible from your network."
            ),
            config.neo4j_uri,
            e,
        )
        return
    except neo4j.exceptions.AuthError as e:
        logger.debug("Error occurred during Neo4j auth.", exc_info=True)
        if not neo4j_auth:
            logger.error(
                (
                    "Unable to auth to Neo4j, an error occurred: '%s'. watchtower attempted to connect to Neo4j "
                    "without any auth. Check your Neo4j server settings to see if auth is required and, if it is, "
                    "provide watchtower with a valid username and password."
                ),
                e,
            )
        else:
            logger.error(
                (
                    "Unable to auth to Neo4j, an error occurred: '%s'. watchtower attempted to connect to Neo4j with "
                    "a username and password. Check your Neo4j server settings to see if the username and password "
                    "provided to watchtower are valid credentials."
                ),
                e,
            )
        return STATUS_FAILURE
    default_update_tag = int(time.time())
    if not config.update_tag:
        config.update_tag = default_update_tag
    return sync.run(neo4j_driver, config)


def build_default_sync():
    """
    Create a Sync object containing the stages/workflow to run for ingestion
    """
    sync = Sync()
    sync.add_stages([
        ('create-indexes', watchtower.intel.create_indexes.run),
        ('subfinder', watchtower.intel.subfinder.sync),
        ('dns', watchtower.intel.dns.sync),
        #('nmap', watchtower.intel.nmap.sync),
        ('certs', watchtower.intel.certs.sync)
    ])
    return sync
