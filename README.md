# C2Detector

<p align="center">
  <img src="https://img.shields.io/badge/DFIR-triage-2f80ed?style=for-the-badge" alt="DFIR triage">
  <img src="https://img.shields.io/badge/framework-Havoc%20only-c0392b?style=for-the-badge" alt="Havoc only">
  <img src="https://img.shields.io/badge/artifacts-auto%20extract-16a085?style=for-the-badge" alt="Auto extract artifacts">
  <img src="https://img.shields.io/badge/input-PCAP%20%2F%20PCAPNG-6c5ce7?style=for-the-badge" alt="PCAP and PCAPNG">
</p>

C2Detector is a compact DFIR triage tool for `.pcap` and `.pcapng` files. It
extracts HTTP/TLS metadata, detects C2 patterns, and writes a Markdown report
plus CSV artifacts.

> [!IMPORTANT]
> Current framework support: **Havoc detection only**. More C2 frameworks are
> coming soon.

> [!TIP]
> For Havoc traffic, C2Detector can recover AES key/IV material from Demon init
> packets, decrypt matching payloads, and automatically extract encrypted
> artifacts such as embedded executables, archives, documents, and PDFs.


---

## Limitations

- **Framework Coverage**: Only Havoc C2 framework is currently supported. Detection
  for other C2 frameworks (Cobalt Strike, Sliver, etc.) is not yet implemented.
- **Protocol Support**: Limited to HTTP/TLS traffic. Other protocols (DNS, HTTPS with
  encrypted payloads) have limited or no detection capabilities.
- **Decryption**: Automatic decryption only works for Havoc C2 traffic. Other encrypted
  protocols cannot be decrypted without manual key provision.
- **Artifact Extraction**: Automated extraction is limited to payloads within Havoc C2
  traffic. Detection of embedded objects in other frameworks requires manual analysis.
- **PCAP Size**: Performance may degrade with very large PCAP files (>1GB).
- **Real-time Analysis**: This tool is designed for offline PCAP analysis and does not
  support live packet capture analysis.

---

## Build

Install the Python dependency used for portable Havoc AES-CTR decryption:

```bash
python3 -m pip install -r requirements.txt
```

There is no compile step; run the CLI directly with Python.

## Example

```bash
python3 c2detector.py --pcap infected.pcap --out investigation/
```

`--out` is treated as a parent directory. C2Detector creates a `report/`
subdirectory inside it.

For Havoc captures, C2Detector auto-detects 4-byte magic markers by default. You
can pin one explicitly:

```bash
python3 c2detector.py --pcap infected.pcap --out investigation/ --havoc-magic deadbeef
```

Use `--havoc-no-decrypt` to detect Havoc without writing decrypted payloads.

## Generated Files

```text
investigation/
└── report/
    ├── report.md
    ├── timeline.csv
    ├── suspicious_flows.csv
    ├── extracted_http_objects/
    │   └── index.csv
    └── havoc_decrypted/
        ├── index.csv
        └── carved_artifacts/
```

`report.md` is the main analyst report. The CSV files provide timeline,
suspicious-flow, extracted-object, and Havoc decryption indexes.
`havoc_decrypted/` stores decrypted Havoc payloads, and
`havoc_decrypted/carved_artifacts/` stores automatically extracted encrypted
artifacts when matching traffic is found.
