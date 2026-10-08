# Enterprise network lab context

## Purpose

This lab models a small enterprise network with segmented user, server,
database, and IoT VLANs. It uses Containerlab, Docker, Open vSwitch (OVS),
FRRouting, Zeek, Nginx, Node.js, PostgreSQL, OpenSSH, and Samba.

## Topology

```text
                         +-- VLAN 10 -- PC1, PC2
                         |
R1 (FRR router) ---------+-- VLAN 20 -- SRV1, WEB1, APP1, FILES1
                         |
                         +-- VLAN 30 -- DB1
                         |
                         +-- VLAN 40 -- IOT1, IOT2

SW1 mirror --> PROBE2 (user-side traffic)
SW2 mirror --> PROBE1 (server/database/IoT-side traffic)
```

R1 routes between VLAN 10, VLAN 20, and VLAN 30. VLAN 40 is intentionally
isolated: IoT clients receive DHCP addresses but no default gateway.

## Nodes and addresses

| Node | Image/service | Interface/address | Purpose |
| --- | --- | --- | --- |
| `r1` | `quay.io/frrouting/frr:10.7.1` | `eth1`: 10.10.10.1, `eth2`: 10.10.20.1, `eth3`: 10.10.30.1 | Inter-VLAN router |
| `pc1` | `alpine:3.21.3` | DHCP on VLAN 10 | User workstation |
| `pc2` | `alpine:3.21.3` | DHCP on VLAN 10 | User workstation |
| `srv1` | `alpine:3.21.3` + OpenSSH | 10.10.20.10 | SSH server |
| `web1` | `enterprise-web:2.0` + Nginx | 10.10.20.20 | Frontend and reverse proxy |
| `app1` | `enterprise-app:1.0` + Node.js | 10.10.20.30:3000 | Application API |
| `files1` | `alpine:3.21.3` + Samba | 10.10.20.40 | Windows-compatible SMB file server |
| `db1` | `postgres:18.0-alpine3.21` | 10.10.30.10:5432 | PostgreSQL database |
| `dhcp1` | `alpine:3.21.3` + dnsmasq | 10.10.10.2, 10.10.20.2, 10.10.40.2 | DHCP and DNS |
| `iot1` | `alpine:3.21.3` | DHCP on VLAN 40 | Quiet IoT endpoint |
| `iot2` | `alpine:3.21.3` | DHCP on VLAN 40 | Quiet IoT endpoint |
| `probe1` | `zeek/zeek:7.0.5` | Passive `eth1` on SW2 mirror | Server-side monitoring |
| `probe2` | `zeek/zeek:7.0.5` | Passive `eth1` on SW1 mirror | User-side monitoring |

## VLANs and OVS ports

| VLAN | Network | OVS ports | Members |
| --- | --- | --- | --- |
| 10 | 10.10.10.0/24 | `sw1`: `ovsp1`-`ovsp4` | R1, PC1, PC2, DHCP1 |
| 20 | 10.10.20.0/24 | `sw2`: `ovs2p1`, `ovs2p2`, `ovs2p3`, `ovs2p6`, `ovs2p7`, `ovs2p11` | R1, SRV1, WEB1, APP1, DHCP1, FILES1 |
| 30 | 10.10.30.0/24 | `sw2`: `ovs2p4`, `ovs2p5` | R1, DB1 |
| 40 | 10.10.40.0/24 | `sw2`: `ovs2p8`-`ovs2p10` | IOT1, IOT2, DHCP1 |

`ovs2p_probe` and `ovsp_probe` are mirror output ports and must not be given
an access VLAN tag.

## DHCP and DNS

`dhcp1` runs dnsmasq with these pools:

- VLAN 10: `10.10.10.100-10.10.10.150`, gateway `10.10.10.1`, DNS `10.10.10.2`
- VLAN 20: `10.10.20.100-10.10.20.150`, gateway `10.10.20.1`
- VLAN 40: `10.10.40.100-10.10.40.150`, no gateway

Internal DNS records:

```text
frontend.enterprise.local -> 10.10.20.20
app.enterprise.local      -> 10.10.20.30
db.enterprise.local       -> 10.10.30.10
```

PC1 and PC2 explicitly use `10.10.10.2` because Docker initially supplies
`127.0.0.11` in `/etc/resolv.conf`.

## Application and enterprise services

- `frontend.enterprise.local` serves the Nginx frontend and proxies `/api/`.
- `app.enterprise.local:3000` exposes the Node.js API.
- The API uses PostgreSQL at `10.10.30.10`.
- `srv1` accepts SSH as `labuser` with password `labpassword`.
- `files1` provides an anonymous read/write SMB share at `\\files1\shared`.
  Its lab IP is `10.10.20.40`; use `//10.10.20.40/shared` from SMB clients.

## Start and rebuild

Build local images when needed:

```bash
docker build -t enterprise-web:2.0 ./web1
docker build -t enterprise-app:1.0 ./app1
```

Start the complete lab, apply VLANs, and recreate both mirrors:

```bash
./start-lab.sh
```

The first deployment can take longer while Docker pulls pinned images and
Alpine installs service packages.

## Verification commands

List containers:

```bash
docker ps --format 'table {{.Names}}\t{{.Image}}\t{{.Status}}' | grep clab-step2-switch
```

Check client addresses and routes:

```bash
docker exec clab-step2-switch-pc1 ip -4 addr show eth1
docker exec clab-step2-switch-pc2 ip -4 addr show eth1
docker exec clab-step2-switch-iot1 ip -4 addr show eth1
docker exec clab-step2-switch-iot2 ip -4 addr show eth1
docker exec clab-step2-switch-pc1 ip route
```

Check DNS:

```bash
docker exec clab-step2-switch-pc1 nslookup frontend.enterprise.local
docker exec clab-step2-switch-pc1 nslookup app.enterprise.local
docker exec clab-step2-switch-pc1 nslookup db.enterprise.local
```

Test the application chain:

```bash
docker exec clab-step2-switch-pc1 wget -T 5 -qO- http://frontend.enterprise.local/
docker exec clab-step2-switch-pc1 wget -T 5 -qO- \
  'http://frontend.enterprise.local/api/users/search?name=appuser'
```

Test SSH:

```bash
docker exec -it clab-step2-switch-pc1 ssh labuser@10.10.20.10
```

Test the Samba server:

```bash
docker exec clab-step2-switch-pc1 apk add --no-cache samba-client
docker exec clab-step2-switch-pc1 smbclient -N //10.10.20.40/shared -c 'ls'
```

Inspect Samba logs and processes:

```bash
docker exec clab-step2-switch-files1 ps
docker logs clab-step2-switch-files1
```

Capture user-side traffic on probe2:

```bash
docker exec clab-step2-switch-probe2 tcpdump -ni eth1 -c 10
docker exec clab-step2-switch-pc1 ping -c 3 10.10.10.1
```

Capture server-side traffic on probe1:

```bash
docker exec clab-step2-switch-probe1 tcpdump -ni eth1 -c 10
docker exec clab-step2-switch-pc1 wget -T 5 -qO- http://frontend.enterprise.local/
```

Inspect both OVS mirrors:

```bash
sudo ovs-vsctl list mirror
sudo ovs-vsctl --columns=name,ports,mirrors list bridge sw1
sudo ovs-vsctl --columns=name,ports,mirrors list bridge sw2
```

Inspect Zeek logs:

```bash
ls -lh probe-logs/
ls -lh probe2-logs/
```

## Troubleshooting

If a client has no address, inspect its DHCP log:

```bash
docker exec clab-step2-switch-pc1 cat /var/log/udhcpc.log
docker exec clab-step2-switch-iot1 cat /var/log/udhcpc.log
```

If DNS fails, verify the resolver and query the lab DNS directly:

```bash
docker exec clab-step2-switch-pc1 cat /etc/resolv.conf
docker exec clab-step2-switch-pc1 nslookup app.enterprise.local 10.10.10.2
```

If a mirror is empty, start tcpdump before generating traffic and verify the
mirror objects. Capture on `probe1:eth1` or `probe2:eth1`, not only on the
host-side OVS port.
