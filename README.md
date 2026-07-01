# SRE Toolkit & Automation Scripts

This repository contains a collection of custom Bash and Python automation scripts designed to monitor, optimize, and orchestrate my personal hybrid-cloud infrastructure. 

These tools are built around the core principles of **Site Reliability Engineering (SRE)**: automating manual labor, ensuring high availability, maintaining strict OPSEC, and deploying self-healing diagnostics.

---

## 📂 Repository Contents

### 1. `ask_agent.sh` — The Zero-Trust AIOps Troubleshooting Agent
A zero-trust Bash function designed for LLM-assisted terminal debugging. Instead of manually parsing kernel logs and searching StackOverflow, this script:
*   Automatically builds a Context Environment Layer (`whoami`, `os-release`, `pwd`).
*   Ships the context over a private SD-WAN (Tailscale) mesh to an isolated heavy-compute node running an open-weight LLM (e.g., Llama 3.1).
*   **Security Protocol:** The agent is restricted from executing catastrophic commands (e.g., `rm -rf /`, `mkfs`) by utilizing a rigorous regex sanitization filter and a `bash -n` syntax pre-check before automatically applying compute fixes.

### 2. `tailscale_sentinelfixed.sh` — Interactive Mesh Network CLI Manager
A CLI-based GUI built in Bash to manage the Tailscale routing mesh without remembering exact flag syntax.
*   Acts as a dynamic `PS3` menu.
*   Enables instant switching of Exit Nodes (forcing traffic to the OCI public gateway).
*   Automates network diagnostics (`netcheck`, `ping`) and handles state resets safely to prevent asymmetric routing loops across the cluster.

### 4. `Gamemode.sh` — Legacy Workload Optimizer & Process Injector
**Context:** This script serves as the architectural predecessor to the heavy-compute orchestrators found in this toolkit. Originally designed to aggressively optimize a 12GB Linux host for gaming and Wine-based memory injection, its core logic laid the foundation for the thermal monitoring, state-restoration (`trap`), and memory allocation patterns used in the newer AI/VM agents.

**Key Technical Implementations:**
*   **Dynamic State Restoration:** Utilizes Bash `trap` (SIGINT/SIGTERM/EXIT) to capture the host's original state (swappiness, security contexts) and guarantees a safe restore to baseline desktop mode when the heavy workload terminates.
*   **Security Context Manipulation:** Temporarily modifies the Linux kernel's YAMA security module (`/proc/sys/kernel/yama/ptrace_scope`) to allow cross-process memory injection (necessary for Wine trainers), auto-restoring to default security upon exit.
*   **Environment Variable Overrides:** Directly injects Mesa graphics and OpenGL environment flags (`MESA_GL_VERSION_OVERRIDE`, `vblank_mode=0`) at runtime to bypass generic driver bottlenecks and force Iris graphics acceleration.
*   **Memory Paging & IO:** Forces immediate caching flushes (`drop_caches=3`) and adjusts `vm.swappiness` prior to launching the containerized target (Flatpak/Native Lutris) to guarantee maximum physical RAM availability.
---

## Operational Security (OPSEC)

All scripts within this repository have been decoupled from their internal environment variables. 
*   **Private APIs & Keys** have been redacted or moved to untracked `.env` files.
*   **Private SD-WAN IP Addresses** (e.g., `100.X.X.X`) are dynamically injected at runtime via user profile exports (e.g., `~/.bashrc`), ensuring the public GitHub repository maintains zero vector vulnerability while exposing core logic for portfolio demonstration.

---

**Author:** Bokgosi Letebele | *Systems Administrator & Infrastructure Engineer*  
**Primary Stack:** RHEL 9 (Rocky), Ubuntu 24.04, Docker, Ansible, KVM/libvirt, WireGuard
