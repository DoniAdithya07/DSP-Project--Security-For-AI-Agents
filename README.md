# AegisMind Security Framework 🛡️

AegisMind is a robust security middleware designed to protect autonomous AI agents from common vulnerabilities, including prompt injection, unauthorized tool execution, and sensitive data leakage.

## 🚀 Features

- **Prompt Firewall**: Real-time scanning of incoming prompts to detect and block malicious injections or high-risk content.
- **Secure Tool Gateway**: Role-based access control (RBAC) for agent tools. Ensures agents only execute authorized actions based on their assigned roles.
- **Audit Logging**: Comprehensive logging of all agent actions, tool executions, and security events for forensic analysis.
- **Interactive Dashboard**: A modern React-based interface to monitor security events, audit logs, and system health in real-time.

## 🏗️ Tech Stack

- **Backend**: Python, FastAPI, SQLAlchemy (PostgreSQL), Redis.
- **Frontend**: React, Vite, Tailwind CSS, Framer Motion, Lucide Icons.
- **Infrastructure**: Docker, Docker Compose.

## 🛠️ Getting Started

### Prerequisites

- Docker and Docker Compose installed on your machine.

### Installation

1. Clone the repository:
   ```bash
   git clone https://github.com/Akash26436/Security-for-AI-Agents.git
   cd Security-for-AI-Agents
   ```

2. Start the services using Docker Compose:
   ```bash
   docker-compose up --build
   ```

3. Access the services:
   - **Frontend**: [http://localhost:5173](http://localhost:5173)
   - **Backend API**: [http://localhost:8000](http://localhost:8000)
   - **API Documentation**: [http://localhost:8000/docs](http://localhost:8000/docs)

## 📁 Project Structure

```text
.
├── backend/            # FastAPI source code, models, and security logic
├── frontend/           # React dashboard with real-time monitoring
├── docker-compose.yml  # Multi-container orchestration
└── README.md           # Project documentation
```

## 🔒 Security Focus

AegisMind implements a "defense-in-depth" strategy for AI agents:
1. **Input Validation**: Filter prompts at the boundary.
2. **Execution Control**: Mediate every tool request via the Secure Gateway.
3. **Observability**: Log every internal and external interaction for full transparency.

---
Built with ❤️ for Secure AI.
