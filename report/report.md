# C2Detector DFIR Report

## Executive Summary

C2Detector identified 3 suspicious C2-like pattern(s) in `capture.pcapng`.

## Capture Summary

- Total packets observed: 506
- Parsed IPv4 TCP/UDP packets: 500
- Unsupported or skipped packets: 6
- Flow records: 20
- HTTP requests: 32
- TLS ClientHello records: 0
- Extracted HTTP objects: 43

## Findings

### NIMPLANT-001: Nimplant HTTP C2

- Suspicious host: `10.0.2.2`
- Confidence: **High** (92/100)
- First seen: 2024-07-30T17:54:37.913756+00:00
- Last seen: 2024-07-30T17:57:51.988717+00:00

Evidence:
- Nimplant-like login response returned JSON fields `id` and `k`
- Implant ID: gxksd3v7
- Obfuscated key (base64): opO2j7SMi7iSsoqVh5uZpA==
- X-Identifier matched on 31 later HTTP request(s)
- Destination: 10.0.2.15:4444 host=192.168.1.34:4444 uri=/api/v2/login
- Recovered AES key: 5a6a4c744871754762437866736e6f53
- Representative XOR seed: 0x0000f800
- Key validation: Nimplant bootstrap JSON fields: P, h, i, o, p, r, u
- Decryption attempted: 21 successful, 0 failed, 0 skipped using openssl
- Carved Nimplant artifact files: 2
- Recovered task/result GUIDs: 10
- User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:127.0) Gecko/20100101 Firefox/127.0

### HTTP-001: Generic HTTP beaconing

- Suspicious host: `10.0.2.2`
- Confidence: **High** (85/100)
- First seen: 2024-07-30T17:54:58.018463+00:00
- Last seen: 2024-07-30T17:57:51.988717+00:00

Evidence:
- 10 repeated POST requests to the same endpoint
- Fixed sleep interval: ~10s (jitter ratio 0.01)
- Destination: 10.0.2.15:4444 host=192.168.1.34:4444 uri=/api/v2/query
- Repeated POST requests can indicate tasking or check-in traffic
- HTTP pattern match: periodic same-endpoint beaconing

### HTTP-002: Generic HTTP beaconing

- Suspicious host: `10.0.2.2`
- Confidence: **High** (80/100)
- First seen: 2024-07-30T17:54:47.970672+00:00
- Last seen: 2024-07-30T17:57:51.917716+00:00

Evidence:
- 19 repeated GET requests to the same endpoint
- Fixed sleep interval: ~10s (jitter ratio 0.00)
- Destination: 10.0.2.15:4444 host=192.168.1.34:4444 uri=/api/v2/ping
- HTTP payload sizes are comparatively stable across check-ins
- HTTP pattern match: periodic same-endpoint beaconing

## Nimplant Decryption

- Attempts: 22
- Successful decrypts: 21
- Transfer artifacts: 1
- Carved file artifacts: 2
- Failed: 0
- Skipped: 0
- Backend: openssl
- Request decrypt rule: base64-decode JSON `data`, use the first 16 decoded bytes as IV, AES-CTR decrypt the remainder
- Response decrypt rule: base64-decode JSON `t`, use the first 16 decoded bytes as IV, AES-CTR decrypt the remainder
- Output directory: report root
- Carved artifacts: `carved_artifacts/`
- Artifact index: `index.csv`
- Raw decrypted request and response bodies are parsed for context but are not written to disk

Sample attempts:

- request 10.0.2.2:61395 -> 10.0.2.15:4444 uri=/api/v2/login field=data size=137 status=success validation=Nimplant bootstrap JSON fields: P, h, i, o, p, r, u
- response 10.0.2.15:4444 -> 10.0.2.2:61395 uri=/api/v2/ping field=t size=54 status=success guid=vEh6Q4Qi task=whoami validation=Nimplant task `whoami`
- request 10.0.2.2:61395 -> 10.0.2.15:4444 uri=/api/v2/query field=data size=65 status=success guid=vEh6Q4Qi validation=Nimplant task result
- response 10.0.2.15:4444 -> 10.0.2.2:61395 uri=/api/v2/ping field=t size=51 status=success guid=jOerVZrv task=pwd validation=Nimplant task `pwd`
- request 10.0.2.2:61395 -> 10.0.2.15:4444 uri=/api/v2/query field=data size=89 status=success guid=jOerVZrv validation=Nimplant task result
- response 10.0.2.15:4444 -> 10.0.2.2:61395 uri=/api/v2/ping field=t size=62 status=success guid=enakuw6O task=shell ipconfig validation=Nimplant task `shell ipconfig`
- request 10.0.2.2:61395 -> 10.0.2.15:4444 uri=/api/v2/query field=data size=473 status=success guid=enakuw6O validation=Nimplant task result
- response 10.0.2.15:4444 -> 10.0.2.2:61395 uri=/api/v2/ping field=t size=50 status=success guid=rrQpuCTQ task=ps validation=Nimplant task `ps`
- request 10.0.2.2:61395 -> 10.0.2.15:4444 uri=/api/v2/query field=data size=4937 status=success guid=rrQpuCTQ validation=Nimplant task result
- response 10.0.2.15:4444 -> 10.0.2.2:61395 uri=/api/v2/ping field=t size=58 status=success guid=mKetyp74 task=screenshot validation=Nimplant task `screenshot`
- request 10.0.2.2:61395 -> 10.0.2.15:4444 uri=/api/v2/query field=data size=180265 status=success guid=mKetyp74 validation=Nimplant task result; carved PNG image artifact=artifact_request_gxksd3v7_mKetyp74_1722362198.576252_69f1cf7d31e5.png artifact_type=PNG image artifact_offset=0
- response 10.0.2.15:4444 -> 10.0.2.2:61395 uri=/api/v2/ping field=t size=53 status=success guid=7lxy17BD task=getAv validation=Nimplant task `getAv`

Carved artifacts:

- artifact_request_gxksd3v7_mKetyp74_1722362198.576252_69f1cf7d31e5.png type=PNG image size=113277 sha256=69f1cf7d31e5133017fb4dfc9d81a96ec90683c577c6abbcb454325e5e00b4f3 guid=mKetyp74 source=request /api/v2/query
- artifact_transfer_gxksd3v7_CVbPWFec_1722362251.858400_edfa88168aa0.exe type=Windows PE executable size=144384 sha256=edfa88168aa03c065bf24de88c65e222118764023be3ed859df3fb0ff7adaf25 guid=CVbPWFec source=transfer /api/v2/ping/37fd453cbfb4794f48283819f010a9fe

## Generated Artifacts

- `timeline.csv`: normalized HTTP, TLS, and finding timeline
- `suspicious_flows.csv`: one row per suspicious flow or endpoint pattern
- `index.csv`: carved artifact index when framework plugins recover files
- `carved_artifacts/`: decoded screenshots, transfers, and other recovered files

## Notes and Limitations

- This backbone parses `.pcap` and `.pcapng` files with Ethernet or raw IPv4 link types.
- HTTP parsing uses lightweight directional TCP stream reassembly, not a full TCP engine.
- TLS JA3 is derived from visible ClientHello records only; encrypted payloads are not decrypted.
- Framework-specific C2 logic lives in detector plugins under `plugins/`.
