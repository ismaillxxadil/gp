from notline.graph.connection import Neo4jConnection
from notline.graph.writer import (
    retire_unlisted_inventory_assets,
    update_asset_communication_graph,
    write_inventory_asset,
)
from notline.network_profile import get_configured_network_profile


def main():
    profile = get_configured_network_profile()
    db = Neo4jConnection()

    try:
        for asset in profile.inventory_assets:
            write_inventory_asset(db.driver, asset)

        retire_unlisted_inventory_assets(
            db.driver,
            (asset.asset_id for asset in profile.inventory_assets),
        )
        update_asset_communication_graph(db.driver)
        print(
            f"[{profile.name}] Seeded "
            f"{len(profile.inventory_assets)} stable inventory assets."
        )
        print("Asset communication graph updated!")
    finally:
        db.close()


if __name__ == "__main__":
    main()
