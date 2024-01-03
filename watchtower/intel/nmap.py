import argparse
import json
import logging
import neo4j
import sys
from libnmap.parser import NmapParser
from libnmap.objects import NmapHost, NmapReport, NmapService
from libnmap.objects.cpe import CPE as NmapCPE

from pathlib import Path
from typing import List, Dict

logger = logging.getLogger(__name__)


def sync(neo4j_session: neo4j.Session, config: argparse.Namespace):
    location = Path(config.nmap_xml_file)
    config.file = None

    if location.exists():
        if location.is_file():
            parse_nmap_file(neo4j_session, config, location)
        if location.is_dir():
            config.file = False
            parse_nmap_dir(neo4j_session, config, location)
    else:
        logger.error("Location doesn't exist. Exiting")
        sys.exit(1)

def parse_nmap_dir(neo4j_session: neo4j.Session, config: argparse.Namespace):
    logger.info(f"Parsing nmap files in directory: {config.location}")
    # TODO: To prevent re-using pathlib, set config.location to use Path object
    location = Path(config.nmap_xml_file)
    for nmap_file in location.glob('*.xml'):
        parse_nmap_file(neo4j_session, config, nmap_file)

def parse_nmap_file(neo4j_session: neo4j.Session, config: argparse.Namespace, filename: Path = None):
    """
    Parse Nmap XML files for ingestions into the database as the following nodes:

    :Port
    :Domain
    :DNSRecord
    """
    logger.info("Parsing nmap XML file")
    if not filename:
        filename = Path(config.nmap_xml_file)
    nmap_report = NmapParser.parse_fromfile(filename)
    results = transform(nmap_report)
    for scanned_host in nmap_report.hosts:
        ipv4addr = scanned_host.ipv4
        ipv6addr = scanned_host.ipv6
        # FIXME: When there are multiple, it's because there's a PTR record that was found. Need to 
        # fix the libnmap code for this to take in the type= field
        hostnames = scanned_host.hostnames
        services = scanned_host.services
        logger.info(f"Creating nodes for {ipv4addr} with hostnames {hostnames}")
        #load_domain_dns_record(neo4j_session, config.update_tag, ipv4addr, ipv6addr, hostnames)
        
        # Go through each NmapService node and add relevant data
        for service in services:
            logger.info(f"Creating nodes for {ipv4addr}:{service.port} with service {service.service} and banner {service.banner}")
            create_service_records(neo4j_session, config.update_tag, service)
            if ipv4addr:
                logger.debug(f"Found IPv4 address {ipv4addr} for {service.port}")
                link_service_to_ip(neo4j_session, config.update_tag, service, ipv4addr)
            if ipv6addr:
                logger.debug(f"Found IPv6 address {ipv6addr} for {service.port}")
                link_service_to_ip(neo4j_session, config.update_tag, service, ipv6addr)
                

def transform(nmap_report: List[NmapHost]) -> List[Dict]:
    """
    Transforms the list of NmapHost objects into a Dict to work with
    """
    transformed_nmap_list: List[Dict] = []
    for host_object in nmap_report.hosts:
        # TODO: This seems to work for the writable attributes. 
        #       Double check there are no missing attributes
        host_json = json.dumps(host_object.__dict__, default=lambda o: o.__dict__)
        transformed_nmap_list.append(host_json)
    return transformed_nmap_list

def load_domain_dns_record(neo4j_session: neo4j.Session, update_tag: int, ipv4addr: str, ipv6addr: str, hostnames: List[str]):
    query = """
    UNWIND $Hostnames as hostname
    MERGE (host:Domain {hostname: hostname})
    ON CREATE SET host.firstseen = timestamp() / 1000
    SET host.lastupdated = $update_tag
    MERGE (dr4:DNSRecord {response: $Ipv4addr, type: 'a'})
    ON CREATE SET dr4.firstseen = timestamp() / 1000
    SET dr4.lastupdated = $update_tag
    """
    
    # TODO: Can probably do this smarter. Look to merge this logic into the Cypher query
    if ipv6addr:
        query += """
        MERGE (dr6:DNSRecord {id: $Ipv6addr, type: 'aaaa'})
        ON CREATE SET dr6.firstseen = timestamp() / 1000
        SET dr6.lastupdated = $update_tag
        """

    neo4j_session.run(query, update_tag=update_tag, Ipv4addr=ipv4addr, Ipv6addr=ipv6addr, Hostnames=hostnames)
    #        neo4j_session.run(query, Ipv4addr=ipv4addr, Hostnames=hostnames)

def create_service_records(neo4j_session: neo4j.Session, update_tag: int, service: NmapService):

    """
    Create :Service nodes and add relevant information for when they were last seen
    """

    # Parse the NmapService object for all the fields, then send to Neo4j
    # TODO: Check in case one of the fields isn't what we expected
    port = service.port
    protocol = service.protocol
    banner = service.banner
    servicename = service.service
    state = service.state

    if banner:
        query = """
        MERGE (s:Service {port: $Port, protocol: $Protocol, service: $ServiceName, banner: $ServiceBanner})
        ON CREATE SET s.firstseen = timestamp() / 1000
        SET s.lastupdated = $update_tag
        """
        neo4j_session.run(query, update_tag=update_tag, Port=port, Protocol=protocol, ServiceName=servicename, ServiceBanner=banner)
    else:
        query = """
        MERGE (s:Service {port: $Port, protocol: $Protocol, service: $ServiceName})
        ON CREATE SET s.firstseen = timestamp() / 1000
        SET s.lastupdated = $update_tag
        """
        neo4j_session.run(query, update_tag=update_tag, Port=port, Protocol=protocol, ServiceName=servicename)


def link_service_to_ip(neo4j_session: neo4j.Session, update_tag:int, service: NmapService, ipaddr: str):
    """
    Link :Service nodes to the :Domain nodes
    """
    port = service.port
    protocol = service.protocol
    servicename = service.service
    state = service.state

    query = """
    MATCH (s:Service {port: $Port, protocol: $Protocol, service: $ServiceName})
    MATCH (ip:IPAddress {address: $IPaddr})
    MERGE (ip)-[r:EXPOSES {state: $State}]->(s)
    ON CREATE SET r.firstseen = timestamp() / 1000
    SET r.lastupdated = $update_tag
    """
    neo4j_session.run(query, update_tag=update_tag, Port=port, Protocol=protocol, ServiceName=servicename, State=state, IPaddr=ipaddr)