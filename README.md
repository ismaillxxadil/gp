# Enterprise Lab: Containerlab, OVS, and a Three-Tier Application

This repository contains a small enterprise-style network lab for a graduation
project inspired by NOTLINE's non-intrusive security-twin concept.

The lab uses Containerlab, Docker, Open vSwitch (OVS), and FRRouting to create:

```text
PC1/PC2 (users)
       |
     SW1 -- VLAN 10 -- R1
                         |
                         +-- VLAN 20 -- WEB1
                         +-- VLAN 25 -- APP1
                         +-- VLAN 35 -- SRV1, FILES1
                         |
                         +-- VLAN 30 -- DB1
                         |
                         +-- VLAN 40 -- IOT1, IOT2
```

The application path is:

```text
PC1 -> WEB1 (Nginx, HTTP) -> APP1 (Express, HTTP API) -> DB1 (PostgreSQL)
```

`probe1` is an active passive-monitoring endpoint. OVS port mirroring is
configured on the running host, and mirrored Ethernet traffic is delivered to
`probe1:eth1`. The mirror configuration is host-local and is not represented
in the Containerlab YAML, so it must be recreated and verified on another
machine.

## Repository contents

| Path | Purpose |
| --- | --- |
| `step2.clab.yml` | Containerlab topology |
| `config/vlan-config.sh` | Applies OVS access-port VLAN tags |
| `r1/` | FRRouting configuration |
| `web1/` | Nginx image and static HTML |
| `app1/` | Node.js/Express API image |
| `commands.txt` | Previously used lab commands |
| `propmt.txt` | Project context and working requirements |

## Prerequisites

The instructions below target Ubuntu Linux. The teammate's machine must have:

- Docker Engine and permission to run Docker commands
- Containerlab
- Open vSwitch (`openvswitch-switch`)
- Git
- Internet access on the first run to pull base images
- Sufficient CPU, RAM, and disk space for the containers and Docker images

Wireshark is optional and only needed for interactive packet capture on the
host. `probe1` installs `tcpdump` inside its Alpine container during topology
deployment.

## Install the prerequisites on Ubuntu

Skip this section for software that is already installed. These commands
install Docker Engine from Docker's Ubuntu repository, Open vSwitch, Git, and
the basic tools used by the lab.

### Install Docker Engine

```bash
sudo apt-get update
sudo apt-get install -y ca-certificates curl
sudo install -m 0755 -d /etc/apt/keyrings
sudo curl -fsSL https://download.docker.com/linux/ubuntu/gpg \
  -o /etc/apt/keyrings/docker.asc
sudo chmod a+r /etc/apt/keyrings/docker.asc
echo \
  "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.asc] \
  https://download.docker.com/linux/ubuntu \
  $(. /etc/os-release && echo "$VERSION_CODENAME") stable" \
  | sudo tee /etc/apt/sources.list.d/docker.list >/dev/null
sudo apt-get update
sudo apt-get install -y docker-ce docker-ce-cli containerd.io \
  docker-buildx-plugin docker-compose-plugin
sudo systemctl enable --now docker
```

Allow the current user to run Docker without `sudo`. Log out and back in
after running this command:

```bash
sudo usermod -aG docker "$USER"
```

Verify Docker after starting a new login session:

```bash
docker run --rm hello-world
```

### Install Open vSwitch and Git

```bash
sudo apt-get update
sudo apt-get install -y openvswitch-switch git iproute2 tcpdump
sudo systemctl enable --now openvswitch-switch
```

### Install Containerlab

Containerlab's official installer detects the Ubuntu architecture and installs
the current release:

```bash
curl -L https://get.containerlab.dev | sudo bash
```

Verify all required tools:

```bash
docker --version
containerlab version
ovs-vsctl --version
git --version
```

If the Docker group change has not taken effect yet, start a new login shell
before deploying. Commands that access host OVS or Containerlab may require
`sudo`.

### Verify prerequisites

```bash
docker --version
containerlab version
ovs-vsctl --version
git --version
```

Verify Docker access:

```bash
docker run --rm hello-world
```

If Docker requires `sudo` on the machine, either run the Docker commands below
with `sudo` or add the teammate's user to the Docker group and start a new
login session.

## Clone and enter the project

```bash
git clone https://github.com/ismaillxxadil/gp.git
cd gp
```

If the repository is private, authenticate with GitHub when prompted.

If you are running the project from the local directory instead of cloning it,
use:

```bash
cd /home/ismail/enterprise-lab/step2-switch
```

## Complete first-run procedure

Run the following from the repository root on a fresh machine:

```bash
mkdir -p db1/data
docker build -t enterprise-web:2.0 ./web1
docker build -t enterprise-app:1.0 ./app1
sudo ovs-vsctl --may-exist add-br sw1
sudo ovs-vsctl --may-exist add-br sw2
sudo containerlab deploy --dry-run -t step2.clab.yml
sudo containerlab deploy -t step2.clab.yml
bash config/vlan-config.sh
```

The dry run must complete without topology errors before running the real
deployment. The VLAN script must run after deployment because the OVS ports are
created by Containerlab.

## Build the local application images

The topology references two local images. Build them before deploying:

```bash
docker build -t enterprise-web:2.0 ./web1
docker build -t enterprise-app:1.0 ./app1
```

Check that both images exist:

```bash
docker image inspect enterprise-web:2.0 enterprise-app:1.0 >/dev/null
```

The other images are pulled by Containerlab/Docker:

- `quay.io/frrouting/frr:10.7.1`
- `zeek/zeek:7.0.5`
- `alpine:3.21.3`
- `postgres:18.0-alpine3.21`

## Prepare the OVS bridges

Containerlab's `ovs-bridge` nodes represent host OVS bridges; they are not
Docker containers. Create the bridges once if they do not already exist:

```bash
sudo ovs-vsctl --may-exist add-br sw1
sudo ovs-vsctl --may-exist add-br sw2
```

Confirm them:

```bash
sudo ovs-vsctl list-br
```

Expected:

```text
sw1
sw2
```

## Validate and deploy the topology

Always validate before changing the running lab:

```bash
sudo containerlab deploy --dry-run -t step2.clab.yml
```

Deploy:

```bash
sudo containerlab deploy -t step2.clab.yml
```

Apply the VLAN access-port configuration after deployment, because the
Containerlab links must exist before the OVS ports can be tagged:

```bash
bash config/vlan-config.sh
```

If the script is not executable, the command above still works. Alternatively:

```bash
chmod +x config/vlan-config.sh
./config/vlan-config.sh
```

Check the running nodes:

```bash
docker ps --format 'table {{.Names}}\t{{.Image}}\t{{.Status}}' \
  | grep clab-step2-switch
```

Expected nodes include:

```text
clab-step2-switch-r1
clab-step2-switch-probe1
clab-step2-switch-pc1
clab-step2-switch-pc2
clab-step2-switch-srv1
clab-step2-switch-web1
clab-step2-switch-app1
clab-step2-switch-db1
```

`sw1` and `sw2` are host Open vSwitch bridges, not Docker containers. Verify
them separately with `sudo ovs-vsctl list-br`.

The DHCP server is connected to user VLAN 10, server VLAN 20, and isolated IoT
VLAN 40. It provides `10.10.10.100-10.10.10.150` to PC1/PC2,
`10.10.20.100-10.10.20.150` to the server VLAN, and
`10.10.40.100-10.10.40.150` to IoT1/IoT2. The IoT pool does not advertise a
default gateway, keeping the devices isolated and reducing unnecessary routed
traffic. All DHCP clients use quiet retry settings.
The DHCP server also provides DNS on `10.10.10.2`; PC1 and PC2 receive that
address through DHCP.
Because Docker supplies a managed `/etc/resolv.conf`, PC1 and PC2 explicitly
write the lab DNS address after DHCP starts.

Web1 is available from PC1 and PC2 as `frontend.enterprise.local`, which
resolves to `10.10.20.20` through the lab DNS server.
APP1 and DB1 are also available as `app.enterprise.local`
(`10.10.25.30`) and `db.enterprise.local` (`10.10.30.10`).

SRV1 runs OpenSSH with the lab account `labuser` and password
`labpassword`. PC1 installs the OpenSSH client during deployment. After PC1
receives its DHCP address, connect to SRV1 with:

```bash
docker exec -it clab-step2-switch-pc1 ssh labuser@10.10.35.10
```

## Verify OVS VLAN tags

```bash
sudo ovs-vsctl get port ovsp1 tag
sudo ovs-vsctl get port ovsp2 tag
sudo ovs-vsctl get port ovsp3 tag

sudo ovs-vsctl get port ovs2p1 tag
sudo ovs-vsctl get port ovs2p2 tag
sudo ovs-vsctl get port ovs2p3 tag
sudo ovs-vsctl get port ovs2p6 tag
sudo ovs-vsctl get port ovs2p11 tag
sudo ovs-vsctl get port ovs2p12 tag
sudo ovs-vsctl get port ovs2p13 tag

sudo ovs-vsctl get port ovs2p4 tag
sudo ovs-vsctl get port ovs2p5 tag
```

Expected values:

```text
SW1 ports: ovsp1=10, ovsp2=10, ovsp3=10
SW2 ports: ovs2p1=20, ovs2p3=20, ovs2p6=25, ovs2p2=35, ovs2p11=35,
ovs2p12=25, ovs2p13=35
SW2 database ports: ovs2p4=30, ovs2p5=30
```

The probe port is intentionally not assigned an access VLAN by the current
script. It receives traffic through the OVS mirror rather than participating
in the application path.

## Verify the passive probe and OVS mirroring

The probe must remain passive: it should observe mirrored traffic without
acting as a router or endpoint in the application path.

Check that the probe is running and has its capture interface:

```bash
docker ps --format 'table {{.Names}}\t{{.Status}}' \
  | grep clab-step2-switch-probe1
docker exec clab-step2-switch-probe1 ip link show eth1
docker exec clab-step2-switch-probe1 command -v tcpdump
```

Inspect the host OVS mirror objects. These commands require permission to read
the OVS database, normally through `sudo`:

```bash
sudo ovs-vsctl list mirror
sudo ovs-vsctl --columns=name,ports,mirrors list bridge sw1
sudo ovs-vsctl --columns=name,ports,mirrors list bridge sw2
```

Generate traffic and capture it on the probe:

```bash
docker exec clab-step2-switch-probe1 \
  sh -c 'timeout 10 tcpdump -ni eth1 -c 5'
```

While the capture is running, use another terminal to generate traffic:

```bash
docker exec clab-step2-switch-pc1 ping -c 2 10.10.20.20
```

The capture should show mirrored Ethernet frames, such as ARP, ICMP, or TCP
traffic. For example, ARP requests and replies confirm that frames are
reaching the probe interface, but a single capture does not prove that every
VLAN or every OVS port is included in the mirror. Verify the configured
`select_src_port`, `select_dst_port`, and `output_port` values in
`ovs-vsctl list mirror`.

Capture on `probe1:eth1`, not only on the host-side OVS port name
`ovs2p_probe`. The mirror output is delivered across the link into the probe
container, where `eth1` is the reliable capture interface:

```bash
docker exec clab-step2-switch-probe1 tcpdump -ni eth1 -c 10
```

The startup script clears stale mirror objects before creating a mirror for
the newly created probe port. Rerun `./start-lab.sh` after restarting the lab.

## Verify connectivity

Check the configured addresses:

```bash
docker exec clab-step2-switch-pc1 ip -4 addr show dev eth1
docker exec clab-step2-switch-pc2 ip -4 addr show dev eth1
docker exec clab-step2-switch-iot1 ip -4 addr show dev eth1
docker exec clab-step2-switch-srv1 ip -4 addr show dev eth1
docker exec clab-step2-switch-web1 ip -4 addr show dev eth1
docker exec clab-step2-switch-app1 ip -4 addr show dev eth1
docker exec clab-step2-switch-db1 ip -4 addr show dev eth1
```

Test the main network path from PC1:

```bash
docker exec clab-step2-switch-pc1 ping -c 3 10.10.10.1
docker exec clab-step2-switch-pc1 ping -c 3 10.10.10.20
docker exec clab-step2-switch-pc1 ping -c 3 10.10.35.10
docker exec clab-step2-switch-pc1 ping -c 3 10.10.20.20
docker exec clab-step2-switch-pc1 ping -c 3 10.10.25.30
docker exec clab-step2-switch-pc1 ping -c 3 10.10.30.10
```

## Verify the application chain

### WEB1 static HTML

```bash
docker exec clab-step2-switch-pc1 \
  wget -qO- http://10.10.20.20/
```

The response should contain `Enterprise Web Server - WEB1`.

### APP1 directly

```bash
docker exec clab-step2-switch-pc1 \
  wget -qO- http://10.10.25.30:3000/api/health
```

Expected response:

```json
{"status":"healthy","server":"APP1"}
```

### WEB1 reverse proxy to APP1

```bash
docker exec clab-step2-switch-pc1 \
  wget -qO- http://10.10.20.20/api/health
```

This request reaches Nginx on WEB1 and is forwarded to APP1 because of the
`/api/` location in `web1/nginx.conf`.

### APP1 to DB1

Check PostgreSQL:

```bash
docker exec clab-step2-switch-db1 \
  pg_isready -U appuser -d enterprise_db
```

The application database-backed endpoint can be tested directly:

```bash
docker exec clab-step2-switch-pc1 \
  wget -qO- 'http://10.10.25.30:3000/api/users/search?name=appuser'
```

### Full WEB1 -> APP1 -> DB1 request

```bash
docker exec clab-step2-switch-pc1 \
  wget -qO- 'http://10.10.20.20/api/users/search?name=appuser'
```

The response should contain a user named `appuser`.

The search endpoint intentionally uses unsafe SQL string interpolation and is
for this isolated lab only. Do not expose this lab to an untrusted network or
reuse the endpoint in production.

## Useful troubleshooting commands

Containerlab status:

```bash
sudo containerlab inspect -t step2.clab.yml
```

Container logs:

```bash
docker logs --tail 100 clab-step2-switch-web1
docker logs --tail 100 clab-step2-switch-app1
docker logs --tail 100 clab-step2-switch-db1
```

Router interfaces and routes:

```bash
docker exec clab-step2-switch-r1 ip -4 addr
docker exec clab-step2-switch-r1 vtysh -c 'show ip route'
```

OVS state:

```bash
sudo ovs-vsctl show
sudo ovs-vsctl list-ports sw1
sudo ovs-vsctl list-ports sw2
```

If a previous deployment is stuck or the topology has to be removed, use the
destructive command deliberately:

```bash
sudo containerlab destroy -t step2.clab.yml
```

After destroying the lab, redeploy it and reapply the VLAN script.

## Database persistence and reset

The topology bind-mounts `./db1/data` into the PostgreSQL container. This
directory is machine-local lab state and is ignored by Git. A fresh clone
starts with an empty database directory and PostgreSQL initializes it using
the credentials in `step2.clab.yml`.

On a fresh clone, create the bind-mount directory before deployment:

```bash
mkdir -p db1/data
```

To preserve database state, back up `db1/data` separately. To intentionally
reset the database, first destroy the topology, then remove only the local
database directory and redeploy:

```bash
sudo containerlab destroy -t step2.clab.yml
rm -rf db1/data
mkdir -p db1/data
sudo containerlab deploy -t step2.clab.yml
bash config/vlan-config.sh
```

## Create a GitHub repository and upload the project

### 1. Create an empty repository on GitHub

On GitHub:

1. Open **New repository**.
2. Choose a repository name, for example `enterprise-lab-step2`.
3. Choose **Private** if the lab should not be public.
4. Do **not** initialize it with a README, `.gitignore`, or license because
   this project already contains those files.
5. Create the repository.

### 2. Initialize and commit locally

Run these commands from the project directory:

```bash
cd /home/ismail/enterprise-lab/step2-switch
git init
git branch -M main
git status
git add README.md .gitignore step2.clab.yml config r1 web1 app1 \
  commands.txt propmt.txt
git commit -m "Add enterprise Containerlab topology"
```

Review the files before pushing:

```bash
git status
git ls-files
```

The database data directory, Node dependencies, and Containerlab generated
state should not appear in the commit.

### 3. Connect this local repository to `ismaillxxadil/gp` and push

Run these commands from the project directory:

```bash
git remote add origin https://github.com/ismaillxxadil/gp.git
git remote -v
git push -u origin main
```

If `origin` already exists, update it instead:

```bash
git remote set-url origin https://github.com/ismaillxxadil/gp.git
git push -u origin main
```

GitHub authentication may require a browser login, GitHub CLI authentication,
or a personal access token instead of an account password. The GitHub
repository should be empty, or its existing history must be reconciled before
the first push.

### 4. Future updates

```bash
git add README.md step2.clab.yml config r1 web1 app1 commands.txt propmt.txt
git commit -m "Describe the change"
git push
```

## Limitations

- `enterprise-web:2.0` and `enterprise-app:1.0` are local images; they are
  built from this repository and are not pulled from a registry.
- OVS bridges and VLAN tags are host-level configuration.
- The current topology uses access-port VLAN tags and does not require a
  trunk.
- OVS SPAN/mirroring is working on the current lab host and has been verified
  by capturing mirrored ARP traffic on `probe1:eth1`. The mirror is host-local
  configuration and is not automatically recreated by this repository.
- This is a NOTLINE-inspired educational lab, not an exact reproduction of
  the research system.
