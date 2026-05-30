# C2Detector

<p align="center">
  <img src="https://img.shields.io/badge/DFIR-triage-2f80ed?style=for-the-badge" alt="DFIR triage">
  <img src="https://img.shields.io/badge/framework-Havoc%20%2B%20Nimplant-c0392b?style=for-the-badge" alt="Havoc and Nimplant">
  <img src="https://img.shields.io/badge/artifacts-auto%20extract-16a085?style=for-the-badge" alt="Auto extract artifacts">
  <img src="https://img.shields.io/badge/input-PCAP%20%2F%20PCAPNG-6c5ce7?style=for-the-badge" alt="PCAP and PCAPNG">
</p>

C2Detector is a compact DFIR triage tool for `.pcap` and `.pcapng` files. It
extracts HTTP/TLS metadata, detects C2 patterns, and writes a Markdown report
plus CSV artifacts.

> [!IMPORTANT]
> Current framework support: **Havoc** and **Nimplant** HTTP traffic.

> [!TIP]
> For Havoc traffic, C2Detector can recover AES key/IV material from Demon init
> packets. For Nimplant traffic, it can recover the AES key from the `k` login
> value via XOR-fold key search. Matching payloads are decrypted and written as
> DFIR artifacts.

---

## Limitations

- **Framework Coverage**: Havoc and Nimplant HTTP traffic are currently supported.
  Detection for other C2 frameworks (Cobalt Strike, Sliver, etc.) is not yet
  implemented.
- **Protocol Support**: Limited to HTTP/TLS traffic. Other protocols (DNS, HTTPS with
  encrypted payloads) have limited or no detection capabilities.
- **Decryption**: Automatic decryption currently covers Havoc and Nimplant HTTP
  traffic. Other encrypted protocols cannot be decrypted without manual key provision.
- **Artifact Extraction**: Automated extraction is focused on payloads within
  supported framework traffic. Nimplant screenshot/upload transfers are detected in
  task/result plaintext, with deeper special-case carving planned separately.
- **PCAP Size**: Performance may degrade with very large PCAP files (>1GB).
- **Real-time Analysis**: This tool is designed for offline PCAP analysis and does not
  support live packet capture analysis.

---

## Build

Create a local virtual environment and install the Python dependency used for
portable AES-CTR decryption and Nimplant key recovery:

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt
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

For Nimplant captures, C2Detector detects the `id`/`k` login handshake and tries
to recover the AES key automatically:

```bash
python3 c2detector.py --pcap nimplant.pcapng --out investigation/
```

Use `--nimplant-no-decrypt` to detect Nimplant without key recovery. If you
already know the AES key, pass it as hex, base64, or 16-byte text:

```bash
python3 c2detector.py --pcap nimplant.pcapng --out investigation/ --nimplant-aes-key 5a6a4c744871754762437866736e6f53
```

## Generated Files

```text
investigation/
└── report/
    ├── report.md
    ├── timeline.csv
    ├── suspicious_flows.csv
    ├── index.csv
    └── carved_artifacts/
```

`report.md` is the main analyst report. The CSV files provide timeline,
suspicious-flow, and carved-artifact indexes. `carved_artifacts/` stores decoded
screenshots, transfer bodies, and other recovered files when matching framework
traffic is found. Raw HTTP objects and decrypted per-request bodies are not
written to disk by default.
