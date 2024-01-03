Watchtower Attack Surface Management Tool

What is Watchtower
--------------------
A set of tools, APIs and ETL code to understand the attack surface of an organization. This includes network data, cloud configuration information and more. It makes it all queryable from a graph database for attack path mapping and for identifying insights that may not exist in other tools.

How it works
-------------
JSON data is pushed into a bucket from external tools
The data is then transformed and loaded into Neo4j AuraDB

TODO
-----
- Implement nmap importer
- Create Runner class for running multiple tools
