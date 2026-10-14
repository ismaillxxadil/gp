from notline.graph.connection import Neo4jConnection
from notline.graph.schema import initialize_schema


def main():
    db = Neo4jConnection()

    try:
        db.verify()
        initialize_schema(db.driver)
        print("SUCCESS: NOTLINE graph schema initialized.")
    finally:
        db.close()


if __name__ == "__main__":
    main()
