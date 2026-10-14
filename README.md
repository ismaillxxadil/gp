
# NOTLINE — Self-Healing Cybersecurity Digital Twin

**A research-oriented cybersecurity digital twin platform for network monitoring, security analysis, and future autonomous threat response using intelligent agents and Large Language Models (LLMs).**

> **Project status:** In development — the enterprise network lab, passive monitoring infrastructure, Neo4j environment, and initial Python backend components are implemented. Autonomous self-healing and LLM-based reasoning are planned features, not yet operational.

## 1. Project Overview

NOTLINE is a graduation project inspired by research on non-intrusive cybersecurity digital twins.

Our goal is to develop a system that can observe an enterprise network, construct and maintain a digital representation of its infrastructure, analyze potential security risks, and eventually recommend or execute controlled defensive responses.

The project combines:

- **Network emulation** using Containerlab and Docker
- **Network segmentation** using Open vSwitch and VLANs
- **Routing** using FRRouting
- **Passive network monitoring** using Zeek
- **Graph-based digital twin storage** using Neo4j
- **Security data processing** using Python
- **Future intelligent analysis** using agents and LLMs
- **Future self-healing mechanisms** for validated defensive actions

The system is intended for an isolated research environment.

## 2. Project Architecture

### Enterprise network

```text
                     Enterprise Network
                             |
                       FRRouting (R1)
                             |
              +--------------+--------------+
              |                             |
         OVS Switch 1                  OVS Switch 2
              |                             |
         VLAN 10 Users               VLAN 20 Web
          PC1, PC2                   VLAN 25 App
                                    VLAN 30 Database
                                    VLAN 35 Management
                                    VLAN 40 IoT

          Zeek Probe 2               Zeek Probe 1
              |                             |
          OVS Mirror                    OVS Mirror
```

The network includes 13 Containerlab nodes:

| Node | Role |
|---|---|
| `r1` | Enterprise router using FRRouting |
| `pc1`, `pc2` | Employee workstations |
| `dhcp1` | DHCP and DNS services |
| `web1` | Nginx web frontend |
| `app1` | Node.js / Express application |
| `db1` | PostgreSQL database |
| `srv1` | Internal server |
| `files1` | File-sharing server |
| `iot1`, `iot2` | Simulated IoT devices |
| `probe1`, `probe2` | Zeek passive monitoring probes |

### Application architecture

```text
PC1 / PC2
    |
    v
WEB1 (Nginx)
    |
    v
APP1 (Node.js / Express)
    |
    v
DB1 (PostgreSQL)
```

This application chain generates realistic network traffic for security monitoring and future attack-simulation experiments.

### Cybersecurity digital twin architecture

```text
     Enterprise Network
             |
             v
      OVS Port Mirroring
             |
             v
       Zeek Monitoring
             |
             v
       JSON Event Logs
             |
             v
    Python Discovery Backend
             |
             v
        Neo4j Graph
             |
             v
   Future Security Analysis
             |
             v
   Future Agents and LLMs
             |
             v
  Future Controlled Response
```

**Important:** The architecture above includes both implemented components and planned integrations. Zeek logs are currently generated and the Neo4j environment is available, but automatic ingestion of Zeek events into the graph has not yet been completed.

## 3. Technology Stack

| Category | Technologies |
|---|---|
| Operating system | Ubuntu Linux / WSL2 |
| Containers | Docker Engine |
| Network emulation | Containerlab |
| Virtual switching | Open vSwitch |
| Routing | FRRouting |
| Network monitoring | Zeek |
| Graph database | Neo4j |
| Relational database | PostgreSQL |
| Backend | Python |
| Web server | Nginx |
| Application API | Node.js, Express |
| Testing | pytest |
| Version control | Git, GitHub |
| Planned intelligence | Security agents, LLM integration |

## 4. Repository Structure

```text
gp-main/
|
|-- README.md
|-- .gitignore
|-- step2.clab.yml
|-- start-lab.sh
|
|-- scripts/
|   |-- setup.sh
|   |-- start.sh
|   `-- init_graph.py
|
|-- config/
|   `-- vlan-config.sh
|
|-- infrastructure/
|   |-- compose.yaml
|   `-- .env              # Generated locally, not committed
|
|-- backend/
|   |-- pyproject.toml
|   |-- src/notline/
|   |   |-- discovery/
|   |   `-- graph/
|   `-- tests/
|
|-- r1/
|-- web1/
|-- app1/
|
|-- db1/data/             # Local runtime data
|-- probe-logs/           # Local Zeek logs
`-- probe2-logs/          # Local Zeek logs
```

Runtime data, local credentials, virtual environments, and generated Containerlab directories are excluded from Git.

## 5. System Requirements

The project is designed for an Ubuntu Linux environment, including Ubuntu running under WSL2 on Windows.

### Required software

- Git
- Docker Engine
- Docker Compose
- Containerlab
- Open vSwitch
- Python 3 with virtual environment support
- Internet access for initial image downloads and package installation
- Sudo privileges for network configuration

For Windows users, WSL2 with Ubuntu is recommended.

### Installation resources

Follow the official installation documentation for your operating system:

- [Docker Engine for Ubuntu](https://docs.docker.com/engine/install/ubuntu/)
- [Containerlab Installation](https://containerlab.dev/install/)
- [Open vSwitch Documentation](https://docs.openvswitch.org/)
- [WSL Installation](https://learn.microsoft.com/windows/wsl/install)

On Ubuntu, the Open vSwitch package is commonly installed using:

```bash
sudo apt update
sudo apt install -y openvswitch-switch
```

Ensure Docker and Open vSwitch are running before proceeding.

## 6. Quick Start

### Step 1 — Clone the repository

```bash
git clone <YOUR-PRIVATE-REPOSITORY-URL>
cd <YOUR-REPOSITORY-DIRECTORY>
```

Replace the placeholders with the actual private GitHub repository URL and directory name.

Your GitHub account must have access to the repository.

### Step 2 — Run first-time setup

```bash
./scripts/setup.sh
```

This script:

1. Checks required tools.
2. Verifies Docker and Docker Compose.
3. Creates the Python virtual environment.
4. Installs the backend package and development dependencies.
5. Creates required runtime directories.
6. Generates a local Neo4j password if one does not already exist.
7. Initializes the OVS bridges.

The generated `infrastructure/.env` file must remain private.

### Step 3 — Start NOTLINE

```bash
./scripts/start.sh
```

The startup script automatically:

1. Starts Neo4j.
2. Builds the web and application Docker images.
3. Prepares the OVS bridges and runtime directories.
4. Destroys and rebuilds the Containerlab network.
5. Applies VLAN configuration.
6. Configures OVS SPAN traffic mirrors for both Zeek probes.

**Startup can take several minutes**, especially when Containerlab installs packages inside containers.

Do not interrupt the process simply because the output pauses temporarily.

The startup is complete when you see:

```text
=== Lab successfully deployed with active NOTLINE monitoring! ===
=== NOTLINE Started ===
Neo4j: http://localhost:7474
```

**Note:** The current startup workflow intentionally destroys and recreates the Containerlab deployment each time. Ephemeral changes inside the lab containers may be lost. Persisted bind-mounted data and Neo4j volumes are managed separately.

## 7. Verify the Deployment

### Check the containers

```bash
docker ps --format 'table {{.Names}}\t{{.Status}}'
```

You should see 13 Containerlab nodes and the Neo4j container.

### Inspect the lab

```bash
sudo containerlab inspect -t step2.clab.yml
```

### Check OVS

```bash
sudo ovs-vsctl show
```

Confirm that `sw1` and `sw2` exist and that the expected ports are attached without missing-interface errors.

### Check Zeek logs

```bash
ls -lh probe-logs/
ls -lh probe2-logs/
```

Inspect recent connection records:

```bash
tail -n 5 probe-logs/conn.log
```

Zeek connection logs are configured to use JSON records.

The presence of valid recent records confirms that a probe has captured network traffic. It does not by itself guarantee complete visibility across every VLAN or application.

### Open Neo4j

Open:

http://localhost:7474

Use the Neo4j credentials configured locally in `infrastructure/.env`.

The graph database is currently prepared for the digital twin, but live network-to-graph synchronization remains under development.

## 8. Python Backend

The backend is organized as an installable Python package.

Current components include:

- Pydantic-based discovery models
- Zeek log parsing
- Neo4j connection management
- Initial graph schema and constraints
- Unit tests for Zeek parsing

### Run backend tests

From the repository root:

```bash
backend/.venv/bin/python -m pytest backend/tests -v
```

### Initialize graph schema

```bash
backend/.venv/bin/python scripts/init_graph.py
```

Run graph initialization only after Neo4j is available and the required environment configuration is present.

## 9. Development Roadmap

### Phase 1 — Enterprise Network Environment

**Implemented**

- Containerlab topology
- Segmented enterprise network
- FRRouting
- Web, application, and database services
- DHCP/DNS and simulated IoT devices
- Two Zeek probes
- OVS SPAN traffic mirroring

### Phase 2 — Discovery and Digital Twin Construction

**In progress**

- Parse Zeek connection records
- Develop incremental log ingestion
- Identify observed hosts and communications
- Model assets and relationships in Neo4j
- Maintain and update the digital twin graph

### Phase 3 — Security Analysis

**Planned**

- Enrich discovered assets with available service information
- Investigate vulnerability and exposure analysis
- Represent relevant attack paths and security relationships
- Evaluate the quality of the digital twin against the emulated network

### Phase 4 — Intelligent Agents and LLM Integration

**Planned**

- Develop security-analysis agent workflows
- Integrate LLM-assisted reasoning
- Generate explainable security recommendations
- Evaluate accuracy, reliability, and limitations

### Phase 5 — Controlled Self-Healing

**Planned**

- Define safe defensive actions
- Introduce policy checks and approval controls
- Execute selected responses in the isolated lab
- Verify network recovery and service availability
- Compare security outcomes before and after remediation

The scope and implementation of later phases will be refined as the research progresses.

## 10. Troubleshooting

### Docker is unavailable

Check:

```bash
docker info
```

Ensure the Docker daemon is running and your user has appropriate access.

### Open vSwitch ports show "No such device"

This can happen after restarting WSL or the laptop because container interfaces may no longer match the saved OVS configuration.

Rebuild the lab using:

```bash
./scripts/start.sh
```

Do not launch multiple Containerlab deployments simultaneously.

### Containerlab appears stuck

Some topology startup commands install packages inside containers and may take several minutes.

Wait for completion and check container status in another terminal:

```bash
docker ps -a
```

### Zeek reports that the `ip` command is missing

The current Zeek container image may not include the `ip` utility.

This can cause a topology initialization warning even when the interface is operational.

Check the interface state:

```bash
docker exec clab-step2-switch-probe1 cat /sys/class/net/eth1/operstate
```

Then verify that recent connection logs are being generated.

This initialization issue is a known improvement item.

### Neo4j is still starting

Check:

```bash
docker ps --filter name=notline-neo4j
```

Allow time for its health check to complete.

## 11. Security and Research Boundaries

This environment is designed for controlled cybersecurity research and experimentation.

- Keep intentionally vulnerable services isolated from production networks.
- Do not expose lab credentials or services publicly.
- Do not commit `.env` files or runtime database data.
- Use test data rather than real personal or organizational information.
- Require appropriate validation and authorization before automated defensive actions.
- Treat LLM recommendations as untrusted until independently checked.

## 12. Team Collaboration

The project is maintained in a private GitHub repository.

Recommended development workflow:

```bash
git pull origin main
git checkout -b feature/your-feature
```

Make your changes, run the relevant tests, and submit a pull request for review.

Do not commit secrets, virtual environments, generated network state, or monitoring logs.

## 13. Research Background

This project is inspired by the NOTLINE research approach to non-intrusive cybersecurity digital twins.

The current implementation is a research prototype extending the general concept toward intelligent security analysis and controlled self-healing.

Full bibliographic references and research evaluation results will be added as the project develops.

---

**Academic Graduation Project — Cybersecurity Digital Twin, Intelligent Agents, and LLM-Assisted Self-Healing**

*Status: Active development.*# NOTLINE — Self-Healing Cybersecurity Digital Twin

**A research-oriented cybersecurity digital twin platform for network monitoring, security analysis, and future autonomous threat response using intelligent agents and Large Language Models (LLMs).**

> **Project status:** In development — the enterprise network lab, passive monitoring infrastructure, Neo4j environment, and initial Python backend components are implemented. Autonomous self-healing and LLM-based reasoning are planned features, not yet operational.

## 1. Project Overview

NOTLINE is a graduation project inspired by research on non-intrusive cybersecurity digital twins.

Our goal is to develop a system that can observe an enterprise network, construct and maintain a digital representation of its infrastructure, analyze potential security risks, and eventually recommend or execute controlled defensive responses.

The project combines:

- **Network emulation** using Containerlab and Docker
- **Network segmentation** using Open vSwitch and VLANs
- **Routing** using FRRouting
- **Passive network monitoring** using Zeek
- **Graph-based digital twin storage** using Neo4j
- **Security data processing** using Python
- **Future intelligent analysis** using agents and LLMs
- **Future self-healing mechanisms** for validated defensive actions

The system is intended for an isolated research environment.

## 2. Project Architecture

### Enterprise network

```text
                     Enterprise Network
                             |
                       FRRouting (R1)
                             |
              +--------------+--------------+
              |                             |
         OVS Switch 1                  OVS Switch 2
              |                             |
         VLAN 10 Users               VLAN 20 Web
          PC1, PC2                   VLAN 25 App
                                    VLAN 30 Database
                                    VLAN 35 Management
                                    VLAN 40 IoT

          Zeek Probe 2               Zeek Probe 1
              |                             |
          OVS Mirror                    OVS Mirror
```

The network includes 13 Containerlab nodes:

| Node | Role |
|---|---|
| `r1` | Enterprise router using FRRouting |
| `pc1`, `pc2` | Employee workstations |
| `dhcp1` | DHCP and DNS services |
| `web1` | Nginx web frontend |
| `app1` | Node.js / Express application |
| `db1` | PostgreSQL database |
| `srv1` | Internal server |
| `files1` | File-sharing server |
| `iot1`, `iot2` | Simulated IoT devices |
| `probe1`, `probe2` | Zeek passive monitoring probes |

### Application architecture

```text
PC1 / PC2
    |
    v
WEB1 (Nginx)
    |
    v
APP1 (Node.js / Express)
    |
    v
DB1 (PostgreSQL)
```

This application chain generates realistic network traffic for security monitoring and future attack-simulation experiments.

### Cybersecurity digital twin architecture

```text
     Enterprise Network
             |
             v
      OVS Port Mirroring
             |
             v
       Zeek Monitoring
             |
             v
       JSON Event Logs
             |
             v
    Python Discovery Backend
             |
             v
        Neo4j Graph
             |
             v
   Future Security Analysis
             |
             v
   Future Agents and LLMs
             |
             v
  Future Controlled Response
```

**Important:** The architecture above includes both implemented components and planned integrations. Zeek logs are currently generated and the Neo4j environment is available, but automatic ingestion of Zeek events into the graph has not yet been completed.

## 3. Technology Stack

| Category | Technologies |
|---|---|
| Operating system | Ubuntu Linux / WSL2 |
| Containers | Docker Engine |
| Network emulation | Containerlab |
| Virtual switching | Open vSwitch |
| Routing | FRRouting |
| Network monitoring | Zeek |
| Graph database | Neo4j |
| Relational database | PostgreSQL |
| Backend | Python |
| Web server | Nginx |
| Application API | Node.js, Express |
| Testing | pytest |
| Version control | Git, GitHub |
| Planned intelligence | Security agents, LLM integration |

## 4. Repository Structure

```text
gp-main/
|
|-- README.md
|-- .gitignore
|-- step2.clab.yml
|-- start-lab.sh
|
|-- scripts/
|   |-- setup.sh
|   |-- start.sh
|   `-- init_graph.py
|
|-- config/
|   `-- vlan-config.sh
|
|-- infrastructure/
|   |-- compose.yaml
|   `-- .env              # Generated locally, not committed
|
|-- backend/
|   |-- pyproject.toml
|   |-- src/notline/
|   |   |-- discovery/
|   |   `-- graph/
|   `-- tests/
|
|-- r1/
|-- web1/
|-- app1/
|
|-- db1/data/             # Local runtime data
|-- probe-logs/           # Local Zeek logs
`-- probe2-logs/          # Local Zeek logs
```

Runtime data, local credentials, virtual environments, and generated Containerlab directories are excluded from Git.

## 5. System Requirements

The project is designed for an Ubuntu Linux environment, including Ubuntu running under WSL2 on Windows.

### Required software

- Git
- Docker Engine
- Docker Compose
- Containerlab
- Open vSwitch
- Python 3 with virtual environment support
- Internet access for initial image downloads and package installation
- Sudo privileges for network configuration

For Windows users, WSL2 with Ubuntu is recommended.

### Installation resources

Follow the official installation documentation for your operating system:

- [Docker Engine for Ubuntu](https://docs.docker.com/engine/install/ubuntu/)
- [Containerlab Installation](https://containerlab.dev/install/)
- [Open vSwitch Documentation](https://docs.openvswitch.org/)
- [WSL Installation](https://learn.microsoft.com/windows/wsl/install)

On Ubuntu, the Open vSwitch package is commonly installed using:

```bash
sudo apt update
sudo apt install -y openvswitch-switch
```

Ensure Docker and Open vSwitch are running before proceeding.

## 6. Quick Start

### Step 1 — Clone the repository

```bash
git clone <YOUR-PRIVATE-REPOSITORY-URL>
cd <YOUR-REPOSITORY-DIRECTORY>
```

Replace the placeholders with the actual private GitHub repository URL and directory name.

Your GitHub account must have access to the repository.

### Step 2 — Run first-time setup

```bash
./scripts/setup.sh
```

This script:

1. Checks required tools.
2. Verifies Docker and Docker Compose.
3. Creates the Python virtual environment.
4. Installs the backend package and development dependencies.
5. Creates required runtime directories.
6. Generates a local Neo4j password if one does not already exist.
7. Initializes the OVS bridges.

The generated `infrastructure/.env` file must remain private.

### Step 3 — Start NOTLINE

```bash
./scripts/start.sh
```

The startup script automatically:

1. Starts Neo4j.
2. Builds the web and application Docker images.
3. Prepares the OVS bridges and runtime directories.
4. Destroys and rebuilds the Containerlab network.
5. Applies VLAN configuration.
6. Configures OVS SPAN traffic mirrors for both Zeek probes.

**Startup can take several minutes**, especially when Containerlab installs packages inside containers.

Do not interrupt the process simply because the output pauses temporarily.

The startup is complete when you see:

```text
=== Lab successfully deployed with active NOTLINE monitoring! ===
=== NOTLINE Started ===
Neo4j: http://localhost:7474
```

**Note:** The current startup workflow intentionally destroys and recreates the Containerlab deployment each time. Ephemeral changes inside the lab containers may be lost. Persisted bind-mounted data and Neo4j volumes are managed separately.

## 7. Verify the Deployment

### Check the containers

```bash
docker ps --format 'table {{.Names}}\t{{.Status}}'
```

You should see 13 Containerlab nodes and the Neo4j container.

### Inspect the lab

```bash
sudo containerlab inspect -t step2.clab.yml
```

### Check OVS

```bash
sudo ovs-vsctl show
```

Confirm that `sw1` and `sw2` exist and that the expected ports are attached without missing-interface errors.

### Check Zeek logs

```bash
ls -lh probe-logs/
ls -lh probe2-logs/
```

Inspect recent connection records:

```bash
tail -n 5 probe-logs/conn.log
```

Zeek connection logs are configured to use JSON records.

The presence of valid recent records confirms that a probe has captured network traffic. It does not by itself guarantee complete visibility across every VLAN or application.

### Open Neo4j

Open:

http://localhost:7474

Use the Neo4j credentials configured locally in `infrastructure/.env`.

The graph database is currently prepared for the digital twin, but live network-to-graph synchronization remains under development.

## 8. Python Backend

The backend is organized as an installable Python package.

Current components include:

- Pydantic-based discovery models
- Zeek log parsing
- Neo4j connection management
- Initial graph schema and constraints
- Unit tests for Zeek parsing

### Run backend tests

From the repository root:

```bash
backend/.venv/bin/python -m pytest backend/tests -v
```

### Initialize graph schema

```bash
backend/.venv/bin/python scripts/init_graph.py
```

Run graph initialization only after Neo4j is available and the required environment configuration is present.

## 9. Development Roadmap

### Phase 1 — Enterprise Network Environment

**Implemented**

- Containerlab topology
- Segmented enterprise network
- FRRouting
- Web, application, and database services
- DHCP/DNS and simulated IoT devices
- Two Zeek probes
- OVS SPAN traffic mirroring

### Phase 2 — Discovery and Digital Twin Construction

**In progress**

- Parse Zeek connection records
- Develop incremental log ingestion
- Identify observed hosts and communications
- Model assets and relationships in Neo4j
- Maintain and update the digital twin graph

### Phase 3 — Security Analysis

**Planned**

- Enrich discovered assets with available service information
- Investigate vulnerability and exposure analysis
- Represent relevant attack paths and security relationships
- Evaluate the quality of the digital twin against the emulated network

### Phase 4 — Intelligent Agents and LLM Integration

**Planned**

- Develop security-analysis agent workflows
- Integrate LLM-assisted reasoning
- Generate explainable security recommendations
- Evaluate accuracy, reliability, and limitations

### Phase 5 — Controlled Self-Healing

**Planned**

- Define safe defensive actions
- Introduce policy checks and approval controls
- Execute selected responses in the isolated lab
- Verify network recovery and service availability
- Compare security outcomes before and after remediation

The scope and implementation of later phases will be refined as the research progresses.

## 10. Troubleshooting

### Docker is unavailable

Check:

```bash
docker info
```

Ensure the Docker daemon is running and your user has appropriate access.

### Open vSwitch ports show "No such device"

This can happen after restarting WSL or the laptop because container interfaces may no longer match the saved OVS configuration.

Rebuild the lab using:

```bash
./scripts/start.sh
```

Do not launch multiple Containerlab deployments simultaneously.

### Containerlab appears stuck

Some topology startup commands install packages inside containers and may take several minutes.

Wait for completion and check container status in another terminal:

```bash
docker ps -a
```

### Zeek reports that the `ip` command is missing

The current Zeek container image may not include the `ip` utility.

This can cause a topology initialization warning even when the interface is operational.

Check the interface state:

```bash
docker exec clab-step2-switch-probe1 cat /sys/class/net/eth1/operstate
```

Then verify that recent connection logs are being generated.

This initialization issue is a known improvement item.

### Neo4j is still starting

Check:

```bash
docker ps --filter name=notline-neo4j
```

Allow time for its health check to complete.

## 11. Security and Research Boundaries

This environment is designed for controlled cybersecurity research and experimentation.

- Keep intentionally vulnerable services isolated from production networks.
- Do not expose lab credentials or services publicly.
- Do not commit `.env` files or runtime database data.
- Use test data rather than real personal or organizational information.
- Require appropriate validation and authorization before automated defensive actions.
- Treat LLM recommendations as untrusted until independently checked.

## 12. Team Collaboration

The project is maintained in a private GitHub repository.

Recommended development workflow:

```bash
git pull origin main
git checkout -b feature/your-feature
```

Make your changes, run the relevant tests, and submit a pull request for review.

Do not commit secrets, virtual environments, generated network state, or monitoring logs.

## 13. Research Background

This project is inspired by the NOTLINE research approach to non-intrusive cybersecurity digital twins.

The current implementation is a research prototype extending the general concept toward intelligent security analysis and controlled self-healing.

Full bibliographic references and research evaluation results will be added as the project develops.

---

**Academic Graduation Project — Cybersecurity Digital Twin, Intelligent Agents, and LLM-Assisted Self-Healing**

*Status: Active development.*# NOTLINE — Self-Healing Cybersecurity Digital Twin

**A research-oriented cybersecurity digital twin platform for network monitoring, security analysis, and future autonomous threat response using intelligent agents and Large Language Models (LLMs).**

> **Project status:** In development — the enterprise network lab, passive monitoring infrastructure, Neo4j environment, and initial Python backend components are implemented. Autonomous self-healing and LLM-based reasoning are planned features, not yet operational.

## 1. Project Overview

NOTLINE is a graduation project inspired by research on non-intrusive cybersecurity digital twins.

Our goal is to develop a system that can observe an enterprise network, construct and maintain a digital representation of its infrastructure, analyze potential security risks, and eventually recommend or execute controlled defensive responses.

The project combines:

- **Network emulation** using Containerlab and Docker
- **Network segmentation** using Open vSwitch and VLANs
- **Routing** using FRRouting
- **Passive network monitoring** using Zeek
- **Graph-based digital twin storage** using Neo4j
- **Security data processing** using Python
- **Future intelligent analysis** using agents and LLMs
- **Future self-healing mechanisms** for validated defensive actions

The system is intended for an isolated research environment.

## 2. Project Architecture

### Enterprise network

```text
                     Enterprise Network
                             |
                       FRRouting (R1)
                             |
              +--------------+--------------+
              |                             |
         OVS Switch 1                  OVS Switch 2
              |                             |
         VLAN 10 Users               VLAN 20 Web
          PC1, PC2                   VLAN 25 App
                                    VLAN 30 Database
                                    VLAN 35 Management
                                    VLAN 40 IoT

          Zeek Probe 2               Zeek Probe 1
              |                             |
          OVS Mirror                    OVS Mirror
```

The network includes 13 Containerlab nodes:

| Node | Role |
|---|---|
| `r1` | Enterprise router using FRRouting |
| `pc1`, `pc2` | Employee workstations |
| `dhcp1` | DHCP and DNS services |
| `web1` | Nginx web frontend |
| `app1` | Node.js / Express application |
| `db1` | PostgreSQL database |
| `srv1` | Internal server |
| `files1` | File-sharing server |
| `iot1`, `iot2` | Simulated IoT devices |
| `probe1`, `probe2` | Zeek passive monitoring probes |

### Application architecture

```text
PC1 / PC2
    |
    v
WEB1 (Nginx)
    |
    v
APP1 (Node.js / Express)
    |
    v
DB1 (PostgreSQL)
```

This application chain generates realistic network traffic for security monitoring and future attack-simulation experiments.

### Cybersecurity digital twin architecture

```text
     Enterprise Network
             |
             v
      OVS Port Mirroring
             |
             v
       Zeek Monitoring
             |
             v
       JSON Event Logs
             |
             v
    Python Discovery Backend
             |
             v
        Neo4j Graph
             |
             v
   Future Security Analysis
             |
             v
   Future Agents and LLMs
             |
             v
  Future Controlled Response
```

**Important:** The architecture above includes both implemented components and planned integrations. Zeek logs are currently generated and the Neo4j environment is available, but automatic ingestion of Zeek events into the graph has not yet been completed.

## 3. Technology Stack

| Category | Technologies |
|---|---|
| Operating system | Ubuntu Linux / WSL2 |
| Containers | Docker Engine |
| Network emulation | Containerlab |
| Virtual switching | Open vSwitch |
| Routing | FRRouting |
| Network monitoring | Zeek |
| Graph database | Neo4j |
| Relational database | PostgreSQL |
| Backend | Python |
| Web server | Nginx |
| Application API | Node.js, Express |
| Testing | pytest |
| Version control | Git, GitHub |
| Planned intelligence | Security agents, LLM integration |

## 4. Repository Structure

```text
gp-main/
|
|-- README.md
|-- .gitignore
|-- step2.clab.yml
|-- start-lab.sh
|
|-- scripts/
|   |-- setup.sh
|   |-- start.sh
|   `-- init_graph.py
|
|-- config/
|   `-- vlan-config.sh
|
|-- infrastructure/
|   |-- compose.yaml
|   `-- .env              # Generated locally, not committed
|
|-- backend/
|   |-- pyproject.toml
|   |-- src/notline/
|   |   |-- discovery/
|   |   `-- graph/
|   `-- tests/
|
|-- r1/
|-- web1/
|-- app1/
|
|-- db1/data/             # Local runtime data
|-- probe-logs/           # Local Zeek logs
`-- probe2-logs/          # Local Zeek logs
```

Runtime data, local credentials, virtual environments, and generated Containerlab directories are excluded from Git.

## 5. System Requirements

The project is designed for an Ubuntu Linux environment, including Ubuntu running under WSL2 on Windows.

### Required software

- Git
- Docker Engine
- Docker Compose
- Containerlab
- Open vSwitch
- Python 3 with virtual environment support
- Internet access for initial image downloads and package installation
- Sudo privileges for network configuration

For Windows users, WSL2 with Ubuntu is recommended.

### Installation resources

Follow the official installation documentation for your operating system:

- [Docker Engine for Ubuntu](https://docs.docker.com/engine/install/ubuntu/)
- [Containerlab Installation](https://containerlab.dev/install/)
- [Open vSwitch Documentation](https://docs.openvswitch.org/)
- [WSL Installation](https://learn.microsoft.com/windows/wsl/install)

On Ubuntu, the Open vSwitch package is commonly installed using:

```bash
sudo apt update
sudo apt install -y openvswitch-switch
```

Ensure Docker and Open vSwitch are running before proceeding.

## 6. Quick Start

### Step 1 — Clone the repository

```bash
git clone <YOUR-PRIVATE-REPOSITORY-URL>
cd <YOUR-REPOSITORY-DIRECTORY>
```

Replace the placeholders with the actual private GitHub repository URL and directory name.

Your GitHub account must have access to the repository.

### Step 2 — Run first-time setup

```bash
./scripts/setup.sh
```

This script:

1. Checks required tools.
2. Verifies Docker and Docker Compose.
3. Creates the Python virtual environment.
4. Installs the backend package and development dependencies.
5. Creates required runtime directories.
6. Generates a local Neo4j password if one does not already exist.
7. Initializes the OVS bridges.

The generated `infrastructure/.env` file must remain private.

### Step 3 — Start NOTLINE

```bash
./scripts/start.sh
```

The startup script automatically:

1. Starts Neo4j.
2. Builds the web and application Docker images.
3. Prepares the OVS bridges and runtime directories.
4. Destroys and rebuilds the Containerlab network.
5. Applies VLAN configuration.
6. Configures OVS SPAN traffic mirrors for both Zeek probes.

**Startup can take several minutes**, especially when Containerlab installs packages inside containers.

Do not interrupt the process simply because the output pauses temporarily.

The startup is complete when you see:

```text
=== Lab successfully deployed with active NOTLINE monitoring! ===
=== NOTLINE Started ===
Neo4j: http://localhost:7474
```

**Note:** The current startup workflow intentionally destroys and recreates the Containerlab deployment each time. Ephemeral changes inside the lab containers may be lost. Persisted bind-mounted data and Neo4j volumes are managed separately.

## 7. Verify the Deployment

### Check the containers

```bash
docker ps --format 'table {{.Names}}\t{{.Status}}'
```

You should see 13 Containerlab nodes and the Neo4j container.

### Inspect the lab

```bash
sudo containerlab inspect -t step2.clab.yml
```

### Check OVS

```bash
sudo ovs-vsctl show
```

Confirm that `sw1` and `sw2` exist and that the expected ports are attached without missing-interface errors.

### Check Zeek logs

```bash
ls -lh probe-logs/
ls -lh probe2-logs/
```

Inspect recent connection records:

```bash
tail -n 5 probe-logs/conn.log
```

Zeek connection logs are configured to use JSON records.

The presence of valid recent records confirms that a probe has captured network traffic. It does not by itself guarantee complete visibility across every VLAN or application.

### Open Neo4j

Open:

http://localhost:7474

Use the Neo4j credentials configured locally in `infrastructure/.env`.

The graph database is currently prepared for the digital twin, but live network-to-graph synchronization remains under development.

## 8. Python Backend

The backend is organized as an installable Python package.

Current components include:

- Pydantic-based discovery models
- Zeek log parsing
- Neo4j connection management
- Initial graph schema and constraints
- Unit tests for Zeek parsing

### Run backend tests

From the repository root:

```bash
backend/.venv/bin/python -m pytest backend/tests -v
```

### Initialize graph schema

```bash
backend/.venv/bin/python scripts/init_graph.py
```

Run graph initialization only after Neo4j is available and the required environment configuration is present.

## 9. Development Roadmap

### Phase 1 — Enterprise Network Environment

**Implemented**

- Containerlab topology
- Segmented enterprise network
- FRRouting
- Web, application, and database services
- DHCP/DNS and simulated IoT devices
- Two Zeek probes
- OVS SPAN traffic mirroring

### Phase 2 — Discovery and Digital Twin Construction

**In progress**

- Parse Zeek connection records
- Develop incremental log ingestion
- Identify observed hosts and communications
- Model assets and relationships in Neo4j
- Maintain and update the digital twin graph

### Phase 3 — Security Analysis

**Planned**

- Enrich discovered assets with available service information
- Investigate vulnerability and exposure analysis
- Represent relevant attack paths and security relationships
- Evaluate the quality of the digital twin against the emulated network

### Phase 4 — Intelligent Agents and LLM Integration

**Planned**

- Develop security-analysis agent workflows
- Integrate LLM-assisted reasoning
- Generate explainable security recommendations
- Evaluate accuracy, reliability, and limitations

### Phase 5 — Controlled Self-Healing

**Planned**

- Define safe defensive actions
- Introduce policy checks and approval controls
- Execute selected responses in the isolated lab
- Verify network recovery and service availability
- Compare security outcomes before and after remediation

The scope and implementation of later phases will be refined as the research progresses.

## 10. Troubleshooting

### Docker is unavailable

Check:

```bash
docker info
```

Ensure the Docker daemon is running and your user has appropriate access.

### Open vSwitch ports show "No such device"

This can happen after restarting WSL or the laptop because container interfaces may no longer match the saved OVS configuration.

Rebuild the lab using:

```bash
./scripts/start.sh
```

Do not launch multiple Containerlab deployments simultaneously.

### Containerlab appears stuck

Some topology startup commands install packages inside containers and may take several minutes.

Wait for completion and check container status in another terminal:

```bash
docker ps -a
```

### Zeek reports that the `ip` command is missing

The current Zeek container image may not include the `ip` utility.

This can cause a topology initialization warning even when the interface is operational.

Check the interface state:

```bash
docker exec clab-step2-switch-probe1 cat /sys/class/net/eth1/operstate
```

Then verify that recent connection logs are being generated.

This initialization issue is a known improvement item.

### Neo4j is still starting

Check:

```bash
docker ps --filter name=notline-neo4j
```

Allow time for its health check to complete.

## 11. Security and Research Boundaries

This environment is designed for controlled cybersecurity research and experimentation.

- Keep intentionally vulnerable services isolated from production networks.
- Do not expose lab credentials or services publicly.
- Do not commit `.env` files or runtime database data.
- Use test data rather than real personal or organizational information.
- Require appropriate validation and authorization before automated defensive actions.
- Treat LLM recommendations as untrusted until independently checked.

## 12. Team Collaboration

The project is maintained in a private GitHub repository.

Recommended development workflow:

```bash
git pull origin main
git checkout -b feature/your-feature
```

Make your changes, run the relevant tests, and submit a pull request for review.

Do not commit secrets, virtual environments, generated network state, or monitoring logs.

## 13. Research Background

This project is inspired by the NOTLINE research approach to non-intrusive cybersecurity digital twins.

The current implementation is a research prototype extending the general concept toward intelligent security analysis and controlled self-healing.

Full bibliographic references and research evaluation results will be added as the project develops.

---

**Academic Graduation Project — Cybersecurity Digital Twin, Intelligent Agents, and LLM-Assisted Self-Healing**

*Status: Active development.*# NOTLINE — Self-Healing Cybersecurity Digital Twin

**A research-oriented cybersecurity digital twin platform for network monitoring, security analysis, and future autonomous threat response using intelligent agents and Large Language Models (LLMs).**

> **Project status:** In development — the enterprise network lab, passive monitoring infrastructure, Neo4j environment, and initial Python backend components are implemented. Autonomous self-healing and LLM-based reasoning are planned features, not yet operational.

## 1. Project Overview

NOTLINE is a graduation project inspired by research on non-intrusive cybersecurity digital twins.

Our goal is to develop a system that can observe an enterprise network, construct and maintain a digital representation of its infrastructure, analyze potential security risks, and eventually recommend or execute controlled defensive responses.

The project combines:

- **Network emulation** using Containerlab and Docker
- **Network segmentation** using Open vSwitch and VLANs
- **Routing** using FRRouting
- **Passive network monitoring** using Zeek
- **Graph-based digital twin storage** using Neo4j
- **Security data processing** using Python
- **Future intelligent analysis** using agents and LLMs
- **Future self-healing mechanisms** for validated defensive actions

The system is intended for an isolated research environment.

## 2. Project Architecture

### Enterprise network

```text
                     Enterprise Network
                             |
                       FRRouting (R1)
                             |
              +--------------+--------------+
              |                             |
         OVS Switch 1                  OVS Switch 2
              |                             |
         VLAN 10 Users               VLAN 20 Web
          PC1, PC2                   VLAN 25 App
                                    VLAN 30 Database
                                    VLAN 35 Management
                                    VLAN 40 IoT

          Zeek Probe 2               Zeek Probe 1
              |                             |
          OVS Mirror                    OVS Mirror
```

The network includes 13 Containerlab nodes:

| Node | Role |
|---|---|
| `r1` | Enterprise router using FRRouting |
| `pc1`, `pc2` | Employee workstations |
| `dhcp1` | DHCP and DNS services |
| `web1` | Nginx web frontend |
| `app1` | Node.js / Express application |
| `db1` | PostgreSQL database |
| `srv1` | Internal server |
| `files1` | File-sharing server |
| `iot1`, `iot2` | Simulated IoT devices |
| `probe1`, `probe2` | Zeek passive monitoring probes |

### Application architecture

```text
PC1 / PC2
    |
    v
WEB1 (Nginx)
    |
    v
APP1 (Node.js / Express)
    |
    v
DB1 (PostgreSQL)
```

This application chain generates realistic network traffic for security monitoring and future attack-simulation experiments.

### Cybersecurity digital twin architecture

```text
     Enterprise Network
             |
             v
      OVS Port Mirroring
             |
             v
       Zeek Monitoring
             |
             v
       JSON Event Logs
             |
             v
    Python Discovery Backend
             |
             v
        Neo4j Graph
             |
             v
   Future Security Analysis
             |
             v
   Future Agents and LLMs
             |
             v
  Future Controlled Response
```

**Important:** The architecture above includes both implemented components and planned integrations. Zeek logs are currently generated and the Neo4j environment is available, but automatic ingestion of Zeek events into the graph has not yet been completed.

## 3. Technology Stack

| Category | Technologies |
|---|---|
| Operating system | Ubuntu Linux / WSL2 |
| Containers | Docker Engine |
| Network emulation | Containerlab |
| Virtual switching | Open vSwitch |
| Routing | FRRouting |
| Network monitoring | Zeek |
| Graph database | Neo4j |
| Relational database | PostgreSQL |
| Backend | Python |
| Web server | Nginx |
| Application API | Node.js, Express |
| Testing | pytest |
| Version control | Git, GitHub |
| Planned intelligence | Security agents, LLM integration |

## 4. Repository Structure

```text
gp-main/
|
|-- README.md
|-- .gitignore
|-- step2.clab.yml
|-- start-lab.sh
|
|-- scripts/
|   |-- setup.sh
|   |-- start.sh
|   `-- init_graph.py
|
|-- config/
|   `-- vlan-config.sh
|
|-- infrastructure/
|   |-- compose.yaml
|   `-- .env              # Generated locally, not committed
|
|-- backend/
|   |-- pyproject.toml
|   |-- src/notline/
|   |   |-- discovery/
|   |   `-- graph/
|   `-- tests/
|
|-- r1/
|-- web1/
|-- app1/
|
|-- db1/data/             # Local runtime data
|-- probe-logs/           # Local Zeek logs
`-- probe2-logs/          # Local Zeek logs
```

Runtime data, local credentials, virtual environments, and generated Containerlab directories are excluded from Git.

## 5. System Requirements

The project is designed for an Ubuntu Linux environment, including Ubuntu running under WSL2 on Windows.

### Required software

- Git
- Docker Engine
- Docker Compose
- Containerlab
- Open vSwitch
- Python 3 with virtual environment support
- Internet access for initial image downloads and package installation
- Sudo privileges for network configuration

For Windows users, WSL2 with Ubuntu is recommended.

### Installation resources

Follow the official installation documentation for your operating system:

- [Docker Engine for Ubuntu](https://docs.docker.com/engine/install/ubuntu/)
- [Containerlab Installation](https://containerlab.dev/install/)
- [Open vSwitch Documentation](https://docs.openvswitch.org/)
- [WSL Installation](https://learn.microsoft.com/windows/wsl/install)

On Ubuntu, the Open vSwitch package is commonly installed using:

```bash
sudo apt update
sudo apt install -y openvswitch-switch
```

Ensure Docker and Open vSwitch are running before proceeding.

## 6. Quick Start

### Step 1 — Clone the repository

```bash
git clone <YOUR-PRIVATE-REPOSITORY-URL>
cd <YOUR-REPOSITORY-DIRECTORY>
```

Replace the placeholders with the actual private GitHub repository URL and directory name.

Your GitHub account must have access to the repository.

### Step 2 — Run first-time setup

```bash
./scripts/setup.sh
```

This script:

1. Checks required tools.
2. Verifies Docker and Docker Compose.
3. Creates the Python virtual environment.
4. Installs the backend package and development dependencies.
5. Creates required runtime directories.
6. Generates a local Neo4j password if one does not already exist.
7. Initializes the OVS bridges.

The generated `infrastructure/.env` file must remain private.

### Step 3 — Start NOTLINE

```bash
./scripts/start.sh
```

The startup script automatically:

1. Starts Neo4j.
2. Builds the web and application Docker images.
3. Prepares the OVS bridges and runtime directories.
4. Destroys and rebuilds the Containerlab network.
5. Applies VLAN configuration.
6. Configures OVS SPAN traffic mirrors for both Zeek probes.

**Startup can take several minutes**, especially when Containerlab installs packages inside containers.

Do not interrupt the process simply because the output pauses temporarily.

The startup is complete when you see:

```text
=== Lab successfully deployed with active NOTLINE monitoring! ===
=== NOTLINE Started ===
Neo4j: http://localhost:7474
```

**Note:** The current startup workflow intentionally destroys and recreates the Containerlab deployment each time. Ephemeral changes inside the lab containers may be lost. Persisted bind-mounted data and Neo4j volumes are managed separately.

## 7. Verify the Deployment

### Check the containers

```bash
docker ps --format 'table {{.Names}}\t{{.Status}}'
```

You should see 13 Containerlab nodes and the Neo4j container.

### Inspect the lab

```bash
sudo containerlab inspect -t step2.clab.yml
```

### Check OVS

```bash
sudo ovs-vsctl show
```

Confirm that `sw1` and `sw2` exist and that the expected ports are attached without missing-interface errors.

### Check Zeek logs

```bash
ls -lh probe-logs/
ls -lh probe2-logs/
```

Inspect recent connection records:

```bash
tail -n 5 probe-logs/conn.log
```

Zeek connection logs are configured to use JSON records.

The presence of valid recent records confirms that a probe has captured network traffic. It does not by itself guarantee complete visibility across every VLAN or application.

### Open Neo4j

Open:

http://localhost:7474

Use the Neo4j credentials configured locally in `infrastructure/.env`.

The graph database is currently prepared for the digital twin, but live network-to-graph synchronization remains under development.

## 8. Python Backend

The backend is organized as an installable Python package.

Current components include:

- Pydantic-based discovery models
- Zeek log parsing
- Neo4j connection management
- Initial graph schema and constraints
- Unit tests for Zeek parsing

### Run backend tests

From the repository root:

```bash
backend/.venv/bin/python -m pytest backend/tests -v
```

### Initialize graph schema

```bash
backend/.venv/bin/python scripts/init_graph.py
```

Run graph initialization only after Neo4j is available and the required environment configuration is present.

## 9. Development Roadmap

### Phase 1 — Enterprise Network Environment

**Implemented**

- Containerlab topology
- Segmented enterprise network
- FRRouting
- Web, application, and database services
- DHCP/DNS and simulated IoT devices
- Two Zeek probes
- OVS SPAN traffic mirroring

### Phase 2 — Discovery and Digital Twin Construction

**In progress**

- Parse Zeek connection records
- Develop incremental log ingestion
- Identify observed hosts and communications
- Model assets and relationships in Neo4j
- Maintain and update the digital twin graph

### Phase 3 — Security Analysis

**Planned**

- Enrich discovered assets with available service information
- Investigate vulnerability and exposure analysis
- Represent relevant attack paths and security relationships
- Evaluate the quality of the digital twin against the emulated network

### Phase 4 — Intelligent Agents and LLM Integration

**Planned**

- Develop security-analysis agent workflows
- Integrate LLM-assisted reasoning
- Generate explainable security recommendations
- Evaluate accuracy, reliability, and limitations

### Phase 5 — Controlled Self-Healing

**Planned**

- Define safe defensive actions
- Introduce policy checks and approval controls
- Execute selected responses in the isolated lab
- Verify network recovery and service availability
- Compare security outcomes before and after remediation

The scope and implementation of later phases will be refined as the research progresses.

## 10. Troubleshooting

### Docker is unavailable

Check:

```bash
docker info
```

Ensure the Docker daemon is running and your user has appropriate access.

### Open vSwitch ports show "No such device"

This can happen after restarting WSL or the laptop because container interfaces may no longer match the saved OVS configuration.

Rebuild the lab using:

```bash
./scripts/start.sh
```

Do not launch multiple Containerlab deployments simultaneously.

### Containerlab appears stuck

Some topology startup commands install packages inside containers and may take several minutes.

Wait for completion and check container status in another terminal:

```bash
docker ps -a
```

### Zeek reports that the `ip` command is missing

The current Zeek container image may not include the `ip` utility.

This can cause a topology initialization warning even when the interface is operational.

Check the interface state:

```bash
docker exec clab-step2-switch-probe1 cat /sys/class/net/eth1/operstate
```

Then verify that recent connection logs are being generated.

This initialization issue is a known improvement item.

### Neo4j is still starting

Check:

```bash
docker ps --filter name=notline-neo4j
```

Allow time for its health check to complete.

## 11. Security and Research Boundaries

This environment is designed for controlled cybersecurity research and experimentation.

- Keep intentionally vulnerable services isolated from production networks.
- Do not expose lab credentials or services publicly.
- Do not commit `.env` files or runtime database data.
- Use test data rather than real personal or organizational information.
- Require appropriate validation and authorization before automated defensive actions.
- Treat LLM recommendations as untrusted until independently checked.

## 12. Team Collaboration

The project is maintained in a private GitHub repository.

Recommended development workflow:

```bash
git pull origin main
git checkout -b feature/your-feature
```

Make your changes, run the relevant tests, and submit a pull request for review.

Do not commit secrets, virtual environments, generated network state, or monitoring logs.

## 13. Research Background

This project is inspired by the NOTLINE research approach to non-intrusive cybersecurity digital twins.

The current implementation is a research prototype extending the general concept toward intelligent security analysis and controlled self-healing.

Full bibliographic references and research evaluation results will be added as the project develops.

---

**Academic Graduation Project — Cybersecurity Digital Twin, Intelligent Agents, and LLM-Assisted Self-Healing**

*Status: Active development
