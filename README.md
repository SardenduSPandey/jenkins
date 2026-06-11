# Jenkins Security Automation Projects

This repository contains a collection of Jenkins pipeline projects focused on automating security and network analysis tasks in a CI/CD environment. Each project integrates industry-standard tools to help identify vulnerabilities, misconfigurations, and security risks early in the development lifecycle.

---

## Projects Overview

### 1. Automated Network Scanning Tool (Nmap)
**Directory:** `automated_network_scan/`

This Jenkins pipeline automates network reconnaissance and vulnerability scanning using **Nmap**. It scans target hosts or IP ranges to discover open ports, running services, and potential network-level vulnerabilities. The pipeline can be triggered on-demand or scheduled, making it useful for continuous network monitoring and infrastructure audits.

**Key Features:**
- Automated Nmap scans integrated into Jenkins pipelines
- Configurable target hosts, port ranges, and scan profiles
- Generates structured scan reports for review
- Helps identify exposed services and misconfigurations in network infrastructure

---

### 2. Static Application Security Testing (SAST) with SonarQube
**Directory:** `automated_sast_scan/`

This pipeline integrates **SonarQube** for Static Application Security Testing (SAST). It automatically analyzes source code for security vulnerabilities, code quality issues, and bugs on every code commit or pull request, enabling developers to catch security flaws before they reach production.

**Key Features:**
- Automated code analysis triggered via Jenkins pipeline
- Detects common vulnerabilities such as SQL injection, XSS, insecure configurations, and more
- Quality gate enforcement to fail builds that do not meet security thresholds
- Provides detailed reports with issue severity, location, and remediation guidance

---

### 3. Software Composition Analysis (SCA) with Dependabot
**Directory:** `automated_sca_dependabot/`

This project automates **Software Composition Analysis (SCA)** using **Dependabot** integrated with Jenkins. It scans project dependencies for known vulnerabilities (CVEs) in open-source libraries and third-party packages, and automates dependency update pull requests to keep projects secure and up to date.

**Key Features:**
- Automated scanning of project dependencies for known CVEs
- Integrates Dependabot alerts and updates into the Jenkins CI/CD workflow
- Supports multiple package ecosystems (npm, Maven, pip, etc.)
- Reduces risk from vulnerable third-party libraries with automated remediation suggestions

---

### 4. Automated DAST Scan
**Directory:** `automated_dast_scan/`

This pipeline performs **Dynamic Application Security Testing (DAST)** to identify vulnerabilities in running web applications. Unlike SAST, DAST tests the application from the outside by simulating real-world attacks, helping uncover runtime vulnerabilities that static analysis may miss.

**Key Features:**
- Automated dynamic scanning of live/staging web applications
- Identifies runtime vulnerabilities such as authentication flaws, injection attacks, and misconfigurations
- Integrated into the Jenkins pipeline for continuous security testing

---

## Tech Stack

| Tool | Purpose |
|------|---------|
| Jenkins | CI/CD Orchestration |
| Nmap | Network Scanning |
| SonarQube | Static Application Security Testing (SAST) |
| Dependabot | Software Composition Analysis (SCA) |
| ZAP | Dynamic Application Security Testing (DAST) |
| GitHub | Version Control |

---

## Getting Started

1. Clone this repository:
   ```bash
   git clone https://github.com/SardenduSPandey/jenkins.git
   ```
2. Navigate to the relevant project directory.
3. Review the `Jenkinsfile` inside each folder for pipeline configuration.
4. Configure the required environment variables and credentials in Jenkins before running the pipelines.

---

## Author

**Sardendu S Pandey**
GitHub: [@SardenduSPandey](https://github.com/SardenduSPandey)
