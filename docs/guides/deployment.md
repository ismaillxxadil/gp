# Lab deployment and troubleshooting guide

This guide covers the host-side lifecycle. It is separate from the
[graph pipeline guide](./pipeline.md), which begins after the lab and Neo4j are
already running.

## Prerequisites

The first-time setup checks for Git, Docker, Containerlab, Open vSwitch, and
Python 3. Docker Compose must also be available through Docker. OVS and
Containerlab operations require host privileges.

Run the repository setup once:

~~~bash
./scripts/setup.sh
~~~

The setup script creates backend/.venv, installs the backend with development
dependencies, creates runtime directories, generates a local Neo4j password in
infrastructure/.env when needed, and creates sw1/sw2 if they do not exist.
Treat the generated environment file as private.

## Startup sequence

Start the full environment with:

~~~bash
./scripts/start.sh
~~~

The script performs these steps:

1. verifies infrastructure/.env exists;
2. starts Neo4j with [compose.yaml](../../infrastructure/compose.yaml);
3. builds the local enterprise-web:2.0 and enterprise-app:1.0 images;
4. creates runtime directories and OVS bridges;
5. calls [start-lab.sh](../../start-lab.sh);
6. prints the Neo4j Browser URL when deployment completes.

start-lab.sh then:

1. destroys the existing Containerlab deployment for step2.clab.yml;
2. deploys the topology again;
3. applies access VLAN tags and renews DHCP clients;
4. clears and recreates the SW1 and SW2 SPAN mirrors.

Because step 1 is destructive to the ephemeral Containerlab deployment, do not
use startup as a way to preserve manual changes inside containers. Persist the
change in the repository or a bind-mounted data directory first.

## Verify the deployment

### Container state

~~~bash
docker ps --format 'table {{.Names}}\t{{.Image}}\t{{.Status}}' | grep clab-step2-switch
docker ps --filter name=notline-neo4j
~~~

The lab should have thirteen clab-step2-switch-* containers. Neo4j should be
healthy before backend commands are run.

### Runtime versions

~~~bash
docker exec clab-step2-switch-web1 nginx -v 2>&1
docker exec clab-step2-switch-app1 node --version
docker exec clab-step2-switch-db1 postgres --version 2>&1 || true
~~~

The web and Node.js versions must match the verified security targets before
running enrichment. The enrichment step assumes the configured runtime
evidence is true; it does not automatically discover a Docker image mismatch.
Rebuild/recreate the lab and update the verified target declarations together
when a runtime version changes.

### Addresses, routes, and DNS

~~~bash
docker exec clab-step2-switch-pc1 ip -4 addr show eth1
docker exec clab-step2-switch-pc2 ip -4 addr show eth1
docker exec clab-step2-switch-iot1 ip -4 addr show eth1
docker exec clab-step2-switch-iot2 ip -4 addr show eth1
docker exec clab-step2-switch-pc1 ip route
docker exec clab-step2-switch-pc1 nslookup frontend.enterprise.local
docker exec clab-step2-switch-pc1 nslookup app.enterprise.local
docker exec clab-step2-switch-pc1 nslookup db.enterprise.local
~~~

PC1 and PC2 should use 10.10.10.2 as their DNS server. IoT clients should
receive addresses but no default route by design.

### Application and service checks

~~~bash
docker exec clab-step2-switch-pc1 wget -T 5 -qO- http://frontend.enterprise.local/
docker exec clab-step2-switch-pc1 wget -T 5 -qO- \
  'http://frontend.enterprise.local/api/users/search?name=appuser'
docker exec clab-step2-switch-pc1 smbclient -N //10.10.35.40/shared -c 'ls'
~~~

The SSH check can be run interactively when needed:

~~~bash
docker exec -it clab-step2-switch-pc1 ssh labuser@10.10.35.10
~~~

The lab credentials are defined only by the topology/runtime configuration and
should be treated as disposable research-lab credentials.

### OVS mirrors and Zeek logs

~~~bash
sudo ovs-vsctl show
sudo ovs-vsctl list mirror
sudo ovs-vsctl --columns=name,ports,mirrors list bridge sw1
sudo ovs-vsctl --columns=name,ports,mirrors list bridge sw2
docker exec clab-step2-switch-probe1 tcpdump -ni eth1 -c 10
docker exec clab-step2-switch-probe2 tcpdump -ni eth1 -c 10
ls -lh probe-logs/
ls -lh probe2-logs/
~~~

Start a probe capture before generating a test request. Capturing on
probe1:eth1 or probe2:eth1 validates the mirror destination; inspecting only
the host-side OVS port does not prove that Zeek receives packets.

## Troubleshooting

### Docker or Compose is unavailable

~~~bash
docker info
docker compose version
~~~

Start Docker and rerun setup. Do not proceed to Containerlab until Docker is
accessible to the current user.

### OVS port or bridge is missing

~~~bash
sudo ovs-vsctl show
sudo ovs-vsctl --may-exist add-br sw1
sudo ovs-vsctl --may-exist add-br sw2
~~~

Then rerun the startup script so Containerlab links and VLAN tags are recreated
together.

### A client has no address

~~~bash
docker exec clab-step2-switch-pc1 cat /var/log/udhcpc.log
docker exec clab-step2-switch-iot1 cat /var/log/udhcpc.log
docker exec clab-step2-switch-pc1 ip link show eth1
~~~

Confirm that VLAN tags were applied and that config/vlan-config.sh renewed the
client lease. A client lease must be observed by Zeek before it becomes a
current passive asset in the graph.

### DNS or application traffic fails

~~~bash
docker exec clab-step2-switch-pc1 cat /etc/resolv.conf
docker exec clab-step2-switch-pc1 nslookup app.enterprise.local 10.10.10.2
docker logs clab-step2-switch-dhcp1
docker logs clab-step2-switch-web1
docker logs clab-step2-switch-app1
~~~

Check the route and VLAN membership before debugging the application code.

### Zeek logs are empty

~~~bash
docker exec clab-step2-switch-probe1 cat /sys/class/net/eth1/operstate
docker exec clab-step2-switch-probe2 cat /sys/class/net/eth1/operstate
docker exec clab-step2-switch-probe1 ps
docker exec clab-step2-switch-probe2 ps
~~~

If the interfaces are up, inspect both mirror objects and generate one simple
request while tcpdump is running. Empty logs do not necessarily mean the
parser is broken; first prove that packets reach the probe.

### Neo4j is still starting

~~~bash
docker ps --filter name=notline-neo4j
curl -fsS http://localhost:7474 >/dev/null && echo 'Neo4j HTTP is ready'
~~~

Wait for the health check before running graph initialization or import. The
Neo4j credentials are loaded by the backend from infrastructure/.env.

## Continue into the graph pipeline

After deployment verification succeeds, follow the
[graph pipeline](./pipeline.md): generate benign traffic, import Zeek logs,
run security enrichment, audit readiness, and only then consider simulation.
