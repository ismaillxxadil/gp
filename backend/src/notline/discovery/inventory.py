from dataclasses import dataclass


@dataclass(frozen=True)
class InventoryAsset:
    """Stable device information known from the lab topology."""

    asset_id: str
    name: str
    asset_type: str
    network_zone: str
    addresses: tuple[str, ...]


# Dynamic DHCP clients are intentionally excluded. Their identity comes from
# passive DHCP observations and is represented by the observed MAC address.
STATIC_ASSETS: tuple[InventoryAsset, ...] = (
    InventoryAsset(
        asset_id="r1",
        name="r1",
        asset_type="router",
        network_zone="routing",
        addresses=(
            "10.10.10.1",
            "10.10.20.1",
            "10.10.25.1",
            "10.10.30.1",
            "10.10.35.1",
        ),
    ),
    InventoryAsset(
        asset_id="dhcp1",
        name="dhcp1",
        asset_type="dhcp_dns_server",
        network_zone="infrastructure",
        addresses=("10.10.10.2", "10.10.20.2", "10.10.40.2"),
    ),
    InventoryAsset(
        asset_id="web1",
        name="web1",
        asset_type="web_server",
        network_zone="web",
        addresses=("10.10.20.20",),
    ),
    InventoryAsset(
        asset_id="app1",
        name="app1",
        asset_type="application_server",
        network_zone="application",
        addresses=("10.10.25.30",),
    ),
    InventoryAsset(
        asset_id="db1",
        name="db1",
        asset_type="database_server",
        network_zone="database",
        addresses=("10.10.30.10",),
    ),
    InventoryAsset(
        asset_id="files1",
        name="files1",
        asset_type="file_server",
        network_zone="management",
        addresses=("10.10.35.40",),
    ),
    InventoryAsset(
        asset_id="srv1",
        name="srv1",
        asset_type="ssh_server",
        network_zone="management",
        addresses=("10.10.35.10",),
    ),
)
