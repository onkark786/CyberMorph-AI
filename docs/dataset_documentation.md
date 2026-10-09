# CyberMorph AI — Benchmark Datasets Documentation

This document provides academic descriptions, origin specifications, feature semantics, and handling procedures for the two datasets powering **CyberMorph AI**.

---

## 1. Dataset 1: UCI Phishing Websites Dataset

- **Repository:** UC Irvine Machine Learning Repository (Dataset ID: 327)
- **Primary Domain:** Web Security, Phishing Detection, Lexical & Structural Website Classification
- **Sample Count:** 11,055 instances
- **Attribute Count:** 30 features + 1 target class
- **Target Variable:** `result` (`-1`: Phishing, `+1`: Legitimate)

### Feature Catalog & Threat Logic
The dataset defines ternary values (`-1` = Phishing / High Risk, `0` = Suspicious / Neutral, `+1` = Legitimate / Safe):

| Feature Name | Category | Risk Description | Safe Value | Phishing Value |
|---|---|---|---|---|
| `having_ip_address` | Structural | Hostname contains literal IPv4 address instead of registered domain | 1 | -1 |
| `url_length` | Lexical | URLs > 75 characters frequently conceal credential harvesting paths | 1 (<54) | -1 (>75) |
| `shortining_service` | Structural | Use of redirection services (e.g. tinyurl, bit.ly) to mask target host | 1 | -1 |
| `having_at_symbol` | Lexical | Browsers disregard tokens preceding `@` in URL authority | 1 | -1 |
| `double_slash_redirecting`| Structural | `//` redirection occurring after position 7 | 1 | -1 |
| `prefix_suffix` | Lexical | Hyphens in domain names spoofing authentic brands (e.g. `paypal-update`) | 1 | -1 |
| `having_sub_domain` | Structural | Deeply nested subdomains disguising fraudulent root domains | 1 (single) | -1 (>2) |
| `sslfinal_state` | Protocol | Encryption protocol & certificate trust | 1 (HTTPS) | -1 (HTTP) |
| `domain_registration_length` | Domain | Domains registered for < 1 year have higher fraudulent velocity | 1 | -1 |
| `favicon` | Content | Favicon loaded from external untrusted host | 1 | -1 |
| `port` | Network | Connection requested on non-standard ports (outside 80/443) | 1 | -1 |
| `https_token` | Lexical | Deceptive `https` substring embedded inside domain name | 1 | -1 |
| `request_url` | Content | Ratio of external embedded media sources | 1 | -1 |
| `url_of_anchor` | Content | Anchors linking to `#` or javascript handlers | 1 | -1 |
| `links_in_tags` | Content | Script and style tags linked externally | 1 | -1 |
| `sfh` | Form | Server Form Handler action URL pointing to `about:blank` or external domain | 1 | -1 |
| `submitting_to_email` | Content | Form submissions routed to `mailto:` addresses | 1 | -1 |
| `abnormal_url` | Structural | Hostname does not match registered domain owner | 1 | -1 |
| `redirect` | Protocol | Multiple HTTP 301/302 redirects | 1 | -1 |
| `on_mouseover` | Behavior | JavaScript status bar manipulation hiding real link destinations | 1 | -1 |
| `rightclick` | Behavior | JavaScript disabling context menu | 1 | -1 |
| `popupwindow` | Behavior | Deceptive popups prompting for credentials | 1 | -1 |
| `iframe` | Content | Transparent iframes used for clickjacking | 1 | -1 |
| `age_of_domain` | Domain | Newly created domains (< 6 months) | 1 | -1 |
| `dnsrecord` | DNS | Verification against authoritative DNS | 1 | -1 |
| `web_traffic` | Popularity | Alexa/SimilarWeb global traffic rank | 1 | -1 |
| `page_rank` | Popularity | Search engine index prominence | 1 | -1 |
| `google_index` | Search | Presence in authoritative search index | 1 | -1 |
| `links_pointing_to_page` | Graph | Inbound hyperlink count | 1 | -1 |
| `statistical_report` | Reputation | Known presence in PhishTank or StopBadware feeds | 1 | -1 |

---

## 2. Dataset 2: CIC-IDS2017 Network Intrusion Dataset

- **Source:** Canadian Institute for Cybersecurity (University of New Brunswick)
- **Capture Environment:** Simulated production network generating realistic background traffic and attack executions.
- **Extraction Tool:** CICFlowMeter (bidirectional network flow generator)
- **Target Variable:** `Label` (Binary: `BENIGN` vs `ATTACK`; Multi-class includes `PortScan`, `DDoS`, `DoS`, `Botnet`, `Brute Force`).

### Key Flow Features
1. **Flow Duration & Timing:** `Flow Duration`, `Flow IAT Mean`, `Flow IAT Std`, `Flow IAT Max`, `Flow IAT Min`
2. **Packet Volumes & Rates:** `Total Fwd Packets`, `Total Backward Packets`, `Flow Bytes/s`, `Flow Packets/s`
3. **Payload Distribution:** `Fwd Packet Length Mean`, `Bwd Packet Length Mean`, `Packet Length Std`, `Average Packet Size`
4. **TCP Protocol Flags:** `FIN Flag Count`, `SYN Flag Count`, `RST Flag Count`, `PSH Flag Count`, `ACK Flag Count`, `URG Flag Count`
5. **Window & Segment Sizing:** `Init_Win_bytes_forward`, `Init_Win_bytes_backward`, `min_seg_size_forward`

### Preprocessing & Anomaly Mitigation
- **Whitespace Sanitization:** Leading/trailing whitespace in column names (e.g. `' Destination Port'`) is stripped systematically.
- **Infinite Values:** `np.inf` resulting from zero flow durations is replaced with NaN and imputed using column medians.
- **Data Leakage Safeguards:** Preprocessing statistics are calculated exclusively from training folds and subsequently applied to test folds.
