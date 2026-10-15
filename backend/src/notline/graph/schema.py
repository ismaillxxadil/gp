from neo4j import Driver

CONSTRAINTS = [
    """
    CREATE CONSTRAINT asset_id_unique IF NOT EXISTS
    FOR (a:Asset)
    REQUIRE a.asset_id IS UNIQUE
    """,
    """
    CREATE CONSTRAINT ip_address_unique IF NOT EXISTS
    FOR (ip:IPAddress)
    REQUIRE ip.address IS UNIQUE
    """,
    """
    CREATE CONSTRAINT service_id_unique IF NOT EXISTS
    FOR (s:Service)
    REQUIRE s.service_id IS UNIQUE
    """,
    """
    CREATE CONSTRAINT observation_id_unique IF NOT EXISTS
    FOR (o:Observation)
    REQUIRE o.observation_id IS UNIQUE
    """,
    """
    CREATE CONSTRAINT cpe_name_unique IF NOT EXISTS
    FOR (c:CPE)
    REQUIRE c.cpe_name IS UNIQUE
    """,
    """
    CREATE CONSTRAINT cve_id_unique IF NOT EXISTS
    FOR (c:CVE)
    REQUIRE c.cve_id IS UNIQUE
    """,
    """
    CREATE CONSTRAINT component_id_unique IF NOT EXISTS
    FOR (component:SoftwareComponent)
    REQUIRE component.component_id IS UNIQUE
    """,
    """
    CREATE CONSTRAINT advisory_id_unique IF NOT EXISTS
    FOR (advisory:Advisory)
    REQUIRE advisory.advisory_id IS UNIQUE
    """,
]


def initialize_schema(driver: Driver) -> None:
    for statement in CONSTRAINTS:
        driver.execute_query(statement, database_="neo4j")
