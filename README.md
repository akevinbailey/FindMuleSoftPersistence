# MuleSoft Persistence Scanner

A lightweight Python utility that scans MuleSoft Flow XML files and detects components that may write to the local file system.

This tool is designed for:

- Security audits
- CloudHub 2.0 and RTF migration readiness
- Compliance validation
- DevSecOps pipeline enforcement
- Legacy application modernization

---

## 🚀 Features

The scanner recursively searches MuleSoft XML flow files and reports:

### Rule 1 – File Connector Configuration
Detects: `file:config`

### Rule 2 – Persistent Object Store
Detects: `<os:object-store ...>` Where: `persistent="false"` is NOT present

### Rule 3 – Persistent VM Queues
Detects: `<vm:queue queueType="PERSISTENT">`

### Rule 4 – Direct Java File Usage
Detects: `java.io.File` and `java.nio.file`


### Rule 5 – DataWeave & Java Interop File Access

Detects file system access patterns inside:
- `<dw:transform-message>`
- `<ee:transform>`
- `<java:invoke>`
- `<java:invoke-static>`

## 🛡 Limitations
- Heuristic-based detection (regex-based, not full XML parsing)
- Does not analyze compiled Java classes
- Does not scan non-XML resources