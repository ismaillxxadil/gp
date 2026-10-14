import os

from dotenv import load_dotenv
from neo4j import GraphDatabase


class Neo4jConnection:
    def __init__(self):
        load_dotenv("infrastructure/.env")

        self.uri = os.getenv("NEO4J_URI", "bolt://localhost:7687")
        self.username = os.getenv("NEO4J_USER", "neo4j")
        self.password = os.getenv("NEO4J_PASSWORD")

        if not self.password:
            raise ValueError("NEO4J_PASSWORD is not configured")

        self.driver = GraphDatabase.driver(
            self.uri,
            auth=(self.username, self.password),
        )

    def verify(self):
        self.driver.verify_connectivity()

    def close(self):
        self.driver.close()
