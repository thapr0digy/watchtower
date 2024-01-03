import argparse
import logging
import neo4j

from importlib.resources import open_binary
from typing import List

logger = logging.getLogger(__name__)


def get_index_statements() -> List[str]:
    statements = []
    with open_binary('watchtower.data', 'indexes.cypher') as f:
        for line in f.readlines():
            statements.append(
                line.decode('UTF-8').rstrip('\r\n'),
            )
    return statements


def run(neo4j_session: neo4j.Session, config: argparse.Namespace) -> None:
    logger.info("Creating indexes for watchtower node types.")
    for statement in get_index_statements():
        logger.debug("Executing statement: %s", statement)
        neo4j_session.run(statement)
