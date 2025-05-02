# UAR (User Access-Rights Review)


<p align="center">
  <img alt="UAR" src="./uar-logo-512x512.png" width="128px">
</p>

---

## 🌐 Links

- OUTSCALE API documentation: https://docs.outscale.com/en/
- UAR GitHub repository: https://github.com/outscale/uar

---

## 📄 Table of Contents

- [UAR (User Access-Rights Review)](#uar-user-access-rights-review)
  - [🌐 Links](#-links)
  - [📄 Table of Contents](#-table-of-contents)
  - [🧭 Overview](#-overview)
  - [✅ Requirements](#-requirements)
  - [⚙️ Install](#️-install)
    - [from source](#from-source)
      - [1. Install Rust](#1-install-rust)
      - [2. Clone the repository](#2-clone-the-repository)
      - [3. Update dependencies](#3-update-dependencies)
      - [4. Build the project](#4-build-the-project)
      - [5. Install locally](#5-install-locally)
    - [from pre-compiled binaries](#from-pre-compiled-binaries)
  - [🚀 Usage](#-usage)
    - [Basic command](#basic-command)
    - [Optional filters](#optional-filters)
  - [📦 Report Output](#-report-output)
  - [🔐 Authorization Review](#-authorization-review)
    - [Access Control Rules to Remember](#access-control-rules-to-remember)
  - [🤝 Contributing](#-contributing)

---

## 🧭 Overview

**UAR** (User Access-Rights Review) is a command-line tool that provides an access rights assessment for users and resources in an OUTSCALE account.

It performs read operations using the OUTSCALE API (oAPI) to:
- Build an inventory of all resources
- Evaluate access policies for each user, including group-based permissions
- Output a detailed report in CSV, JSON, and Cypher formats

---

## ✅ Requirements

- [Rust (stable)](https://www.rust-lang.org/tools/install)
- Git (to clone the repository)
- Internet access (to reach the OUTSCALE public API)

---

## ⚙️ Install

### from source

#### 1. Install Rust

If Rust is not already installed:

```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
```

#### 2. Clone the repository

```bash
git clone https://github.com/outscale/uar
cd uar
```

#### 3. Update dependencies

```bash
cargo update
```

#### 4. Build the project

```bash
cargo build --release
```

#### 5. Install locally

```bash
cargo install --path .
```

### from pre-compiled binaries

Alternatively, you may find pre-compiled binaries to download on the [releases page](https://github.com/outscale/UAR/releases/).  

---

## 🚀 Usage

UAR requires **three mandatory parameters** for authentication and region:

- `--osc-access-key` or environment variable `OSC_ACCESS_KEY`
- `--osc-secret-key` or environment variable `OSC_SECRET_KEY`
- `--osc-region` or environment variable `OSC_REGION`

### Basic command

```bash
uar
```

### Optional filters

Filter by user ID and/or resource ID:

```bash
uar --osc-user-id Alice --osc-resource-id vol-493d8cd0
```

Customize the output path and file name (default: `uar_report`):

```bash
uar --report-path /reports/my_custom_report
```

Limit the number of resources shown in CLI (default: 10):

```bash
uar --max-resources-display-on-cli 5
```

---

## 📦 Report Output

By default, reports are saved in the current directory with the following files:

- `uar_report.csv`
- `uar_report.json`
- `uar_report.cypher`

These can be renamed or redirected with the `--report-path` option.

---

## 🔐 Authorization Review

To ensure accurate and complete results, use credentials from:
- An OUTSCALE account **or**
- An EIM user with wide read access (e.g., `Allow api::Read*`)

> ⚠️ If insufficient permissions are used, the report may be incomplete or empty.

### Access Control Rules to Remember

1. **Implicit Deny**: Any action not explicitly allowed is denied.
2. **Explicit Deny**: If both `Allow` and `Deny` exist, the **Deny** always overrides the Allow.

---

## 🤝 Contributing

We welcome contributions! See [CONTRIBUTING.md](./CONTRIBUTING.md) for guidelines.