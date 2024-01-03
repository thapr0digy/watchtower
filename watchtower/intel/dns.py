import argparse
import json
import logging
import neo4j
import requests
import subprocess
from subprocess import PIPE, STDOUT
from typing import List
from typing import Dict

logger = logging.getLogger(__name__)

def start_dnsx_ingest(neo4j_session: neo4j.Session, config: argparse.Namespace):
    """
    Perform active scanning, parse the DNSRecords and create records
    """
    # TODO: Provide the ability to load from a file

    logger.info("Running dnsx resolution")

    # TODO: Move options to watchtower.util
    cmdline_options = [
        "dnsx",
        "-a",
        "-aaaa",
        "-cname",
        "-mx",
        "-axfr",
        "-ns",
        "-txt",
        "-caa",
        "-ptr",
        "-soa",
        "-json",
        "-silent",
        "-o",
        "cache/dnsx.json"

    ]
    # TODO: Figure out what to do with the "all" keys
    record_types = [
        "a", "aaaa", "caa", "cname", "mx", "ns", "ptr", "soa", "txt"
    ]

    # Grab domains from database, convert List[List] into string
    dns_records_list = pull_domain_nodes(neo4j_session)
    dns_record_str = "\n".join([str(record[0]) for record in dns_records_list])

    # Create subprocess with stdin pipe for sending newline separated domain list into dnsx
    p = subprocess.Popen(cmdline_options, stdin=PIPE,
                         stdout=PIPE, encoding='utf-8')
    result = p.communicate(input=dns_record_str)[0]
    dns_list = json.loads(json.dumps(
        [json.loads(res) for res in result.splitlines()]))

    # For each key in the dns record, perform create query in database
    # TODO: Do something with the "all" key which contains the entire raw record
    
    # TODO: Handle for records where the status_code != NOERROR
    # This is for identifying NXDOMAIN, SERVFAIL, REFUSED and more
    for dns_record in dns_list:
        # Track the subdomain higher up for sending to a linking function
        subdomain = dns_record["host"]
        for record_key, record_values in dns_record.items():
            if "resolver" in record_key:
                create_dns_resolver(
                    neo4j_session, config.update_tag, record_values)
            if record_key in record_types:
                create_dns_record(
                    neo4j_session, config.update_tag, record_key, record_values)
            link_dns_to_domain(neo4j_session, config.update_tag,
                               subdomain, record_key, record_values)


def start_wix_ingest(neo4j_session: neo4j.Session, config: argparse.Namespace):
    """
    Authenticate to the Wix API and pull all records for each domain we own
    """
    # TODO: Put this in a configuration file
    # TODO: Create an authentication client for logging in
    # TODO: Figure out why the API key doesn't work with Wix
    if isinstance(config.domains, str):
        domains = [config.domains]
    else:
        domains = config.domains

    if not config.wix_token:
        logger.error("Wix token not provided, skipping Wix ingest")
        return
    
    login_cookie = {
        'wixSession2': config.wix_token
        }
    
    session = requests.Session()
    session.cookies.update(login_cookie)
    for domain in domains:
        # FIXME: Turn this into a dynamic formatted string
        resp = __wix_get_dns_data(session, domain)
        json_data = resp.json()
        # Parse through the data
        create_dns_zone_node(neo4j_session, config.update_tag, domain)
        traverse_wix_data(neo4j_session, config.update_tag, domain, json_data)

def __wix_get_dns_data(session: requests.Session, domain: str):
    domains_url = f"https://manage.wix.com/api/v1/zones/domain_name?domain={domain}"
    logger.info(f"Pulling DNS data for {domain} from {domains_url}")
    resp = session.get(domains_url)
    return resp
    
def traverse_wix_data(neo4j_session: neo4j.Session, update_tag: int, dns_zone:str, json_data: Dict):
    # As we traverse each provider, assign all necessary information from each record
    records = json_data['records']
    for record in records:
        # Traverse the list of records and call the appropriate function
        # FIXME: MX records contain the priority values. 
        dns_type = record['recordType']
        hostname = record['hostName']
        ttl = record['ttl']
        values = record['values']
        priority = None

        if dns_type == "MX":
            priority = [item.split()[0] for item in values]
            values = [item.split()[-1] for item in values]
            # TODO: We may want to create an :IPAddress node for the MX record with an IP
        
        # TODO: Fix the A, AAAA, CNAME, TXT records to only take in proper domains
        # FIXME: Handle CNAME differently.
        elif dns_type == "A" or dns_type == "AAAA":
            # Don't create a :Domain for the hostname. Instead, create a :DNSRecord
            # and link it to the :DNSZone
            logger.info(f"Creating domain records for hostname: {hostname}")
            create_domain_node(neo4j_session, update_tag, hostname)
            create_ipaddress_node(neo4j_session, update_tag, dns_type, values)
            link_domain_ipaddress(neo4j_session, update_tag, hostname, values)
            link_domain_source(neo4j_session, update_tag, hostname, "wix")
            link_zone_to_domain(neo4j_session, update_tag, hostname, dns_zone)
        elif dns_type == "CNAME":
            logger.info(f"Creating CNAME records for hostname: {hostname}")
        elif dns_type == "TXT":
            logger.info(f"Creating TXT records for hostname: {hostname}")
            create_dns_txt_record(neo4j_session, update_tag, hostname, dns_type, values, ttl)
        elif dns_type == "SOA":
            # TODO: Need to parse all the values from the SOA record
            # Skip for now
            logger.warning(f"Skipping SOA record for hostname: {hostname}")
            continue
        elif dns_type == "NS":
            # We can pass through to everything else
            logger.info(f"Creating NS records for hostname: {hostname}")
            pass
        elif dns_type == "CAA":
            # We can pass through to everything else. Skip for now
            logger.warning(f"Skipping CAA records for hostname: {hostname}")
            continue
        elif dns_type == "PTR":
            # Not sure what to do here yet. Skip for now
            logger.warning(f"Skipping PTR records for hostname: {hostname}")
            continue
        elif dns_type == "SRV":
            # We can pass through
            logger.warning(f"Creating SRV records for hostname: {hostname}")
        else:
            logger.error(f"Unknown DNS type: {dns_type}")
            exit()

        create_dns_record(neo4j_session, update_tag, hostname, dns_type, values, ttl)
        link_dns_to_domain(neo4j_session, update_tag, dns_zone, hostname, dns_type, values)
        
            
def pull_domain_nodes(neo4j_session: neo4j.Session) -> List[List]:
    """
    Pull :Domain nodes from database and output a list
    """
    query = """
    MATCH (d:Domain)
    RETURN d.hostname
    """

    values = neo4j_session.run(query)
    return values.values()

def create_domain_node(neo4j_session: neo4j.Session, update_tag: int, domain: str):
    """
    Create :Domain nodes 
    """
    query = """
    MERGE (d:Domain {hostname: $Domain})
    ON CREATE SET d.firstseen = timestamp() / 1000
    SET d.lastupdated = $update_tag
    """

    logger.debug(f"Creating Domain node with hostname: {domain}")
    neo4j_session.run(query, update_tag=update_tag, Domain=domain)

def create_dns_record(neo4j_session: neo4j.Session, update_tag: int, hostname: str, key: str, values: List, ttl: int = None):
    """
    Create :DNSRecord nodes 

    """
    query = """
    UNWIND $Data as recordinfo
    MERGE (record:DNSRecord {value: recordinfo, type: $RecordType})
    ON CREATE SET record.firstseen = timestamp() / 1000
    SET record.lastupdated = $update_tag, record.hostname = $Hostname
    """
    if ttl:
        query += ", record.ttl = $ttl"
    
    logger.debug(f"Creating DNSRecord: {hostname}, {key}, {ttl}, {values}")
    neo4j_session.run(query, update_tag=update_tag, Hostname=hostname, RecordType=key, Data=values, ttl=ttl)

def create_dns_txt_record(neo4j_session: neo4j.Session, update_tag: int, domain: str, key: str, values: List, ttl: int = None):
    """
    Create :DNSRecord nodes 

    """
    query = """
    UNWIND $Data as recordinfo
    MERGE (record:DNSRecord {value: recordinfo, type: $RecordType})
    ON CREATE SET record.firstseen = timestamp() / 1000
    SET record.lastupdated = $update_tag, record.hostname = $Domain
    """
    if ttl:
        query += ", record.ttl = $ttl"
    
    logger.debug(f"Creating DNSRecord type: {key}, ttl: {ttl}, values: {values}")
    neo4j_session.run(query, update_tag=update_tag, Domain=domain, RecordType=key, Data=values, ttl=ttl)

def create_dns_resolver(neo4j_session: neo4j.Session, update_tag: int, values: List):
    """
    Create :DNSResolver nodes 

    """
    query = """
    UNWIND $Data as resolver
    MERGE (res:DNSResolver {id: resolver})
    ON CREATE SET res.firstseen = timestamp() / 1000
    SET res.lastupdated = $update_tag
    """

    neo4j_session.run(query, update_tag=update_tag, Data=values)

def create_ipaddress_node(neo4j_session: neo4j.Session, update_tag: int, dns_type: str, values: List):
    """
    Create :IPv4Address and :IPv6Address nodes 
    """
    query = """
    UNWIND $Values as ipaddress
    WITH ipaddress
    WHERE $DNSType = 'A'
    MERGE (ip:IPAddress {address: ipaddress})
    ON CREATE SET ip.firstseen = timestamp() / 1000, ip.version = "4", ip :DNSRecord
    SET ip.lastupdated = $update_tag
    WITH ipaddress
    WHERE $DNSType = 'AAAA'
    MERGE (ip:IPAddress {address: ipaddress})
    ON CREATE SET ip.firstseen = timestamp() / 1000, ip.version = "6", ip: DNSRecord
    SET ip.lastupdated = $update_tag
    """

    logger.debug(f"Creating IPAddress node(s): {values}")
    neo4j_session.run(query, update_tag=update_tag, DNSType=dns_type, Values=values)

def create_dns_zone_node(neo4j_session: neo4j.Session, update_tag: int, domain: str):
    """
    Create :DNSZone nodes 
    """
    query = """
    MERGE (zone:DNSZone {hostname: $Domain})
    ON CREATE SET zone.firstseen = timestamp() / 1000
    SET zone.lastupdated = $update_tag
    """

    logger.debug(f"Creating DNSZone node with domain: {domain}")
    neo4j_session.run(query, update_tag=update_tag, Domain=domain)

def link_dns_to_domain(neo4j_session: neo4j.Session, update_tag: int, dns_zone: str, domain: str, key: str, values: List):
    """
    Create relationship between the :DNSRecord and :Domain nodes
    """
    query = """
    UNWIND $Data as recordinfo
    MATCH (zone:DNSZone {hostname: $Zone})
    MATCH (record:DNSRecord {value: recordinfo, type: $Type})
    MERGE (zone)-[r:CONTAINS]-(record)
    ON CREATE SET r.firstseen = timestamp() / 1000
    SET r.lastupdated = $update_tag
    """
    logger.debug(f"Linking DNSZone {dns_zone} to DNSRecord {key} with values {values}")
    neo4j_session.run(query, update_tag=update_tag, Zone=dns_zone, Domain=domain, Type=key, Data=values)

def link_domain_ipaddress(neo4j_session: neo4j.Session, update_tag: int, domain: str, values: List):
    """
    Create relationship between the :Domain and :IPAddress nodes
    """
    query = """
    UNWIND $IPAddresses as ipaddress
    MATCH (d:Domain {hostname: $Domain})
    MATCH (ip:IPAddress {address: ipaddress})
    MERGE (d)-[r:RESOLVED_TO]-(ip)
    ON CREATE SET r.firstseen = timestamp() / 1000
    SET r.lastupdated = $update_tag
    """

    logger.debug(f"Linking Domain {domain} to IPAddresses {values}")
    neo4j_session.run(query, update_tag=update_tag, Domain=domain, IPAddresses=values)

def link_domain_source(neo4j_session: neo4j.Session, update_tag: int, domain: str, source: str):
    """
    Link :Domain records to the :DataSource records
    """

    query = """
    MATCH (host:Domain {hostname: $Domain})
    MATCH (src:DataSource {id: $Source})
    MERGE (host)-[r:CAME_FROM]-(src)
    ON CREATE SET r.firstseen = timestamp() / 1000
    SET r.lastupdated = $update_tag
    """

    logger.debug(f"Linking Domain {domain} to DataSource wix")
    neo4j_session.run(query, update_tag=update_tag, Domain=domain, Source=source)

def link_zone_to_domain(neo4j_session: neo4j.Session, update_tag: int, domain: str, zone: str):
    """
    Link :DNSZone records to the :Domain records
    """

    query = """
    MATCH (zone:DNSZone {hostname: $Zone})
    MATCH (host:Domain {hostname: $Domain})
    MERGE (zone)-[r:REGISTERED_DOMAIN]-(host)
    ON CREATE SET r.firstseen = timestamp() / 1000
    SET r.lastupdated = $update_tag
    """

    logger.debug(f"Linking DNSZone {zone} to Domain {domain}")
    neo4j_session.run(query, update_tag=update_tag, Domain=domain, Zone=zone)

def sync(neo4j_session: neo4j.Session, config: argparse.Namespace):
    #start_dnsx_ingest(neo4j_session, config)
    start_wix_ingest(neo4j_session, config)