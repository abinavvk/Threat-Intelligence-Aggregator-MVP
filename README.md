# Threat Intelligence Aggregator (Non-AI)

A deterministic, rule-based cybersecurity Blue Team command-line toolkit built with Python 3. The system ingests threat intelligence feeds across multiple formats, extracts Indicators of Compromise (IOCs), validates indicators against network and syntax specifications, normalizes metadata, correlates cross-feed recurrences, calculates deterministic risk scores, and exports production-grade blocklists and analytical reports.

---

## Supported IOC Types

The aggregator processes eight primary Indicator of Compromise categories:
1. **IPv4 Addresses** (e.g., standard public IPs; validates and flags private/reserved RFC 1918 / RFC 5737 ranges)
2. **IPv6 Addresses** (e.g., standard unicast, compressed notation; flags documentation/local ranges)
3. **Domain Names** (FQDN syntax validation, TLD check, rejection of invalid labels)
4. **URLs** (HTTP/HTTPS scheme, host validation, defanged URL handling)
5. **Email Addresses** (RFC 5322 compliance, domain check)
6. **MD5 Hashes** (32-character hexadecimal)
7. **SHA1 Hashes** (40-character hexadecimal)
8. **SHA256 Hashes** (64-character hexadecimal)

---

## System Architecture

```text
Threat-Intelligence-Aggregator/
|-- main.py                    # Top-level CLI entry point (argparse)
|-- requirements.txt           # Minimal runtime dependencies (requests, pytest)
|-- README.md                  # Comprehensive system documentation
|-- .gitignore                 # Version control hygiene configuration
|
|-- config/
|   |-- __init__.py
|   |-- settings.py            # Global configuration, paths, severity thresholds
|
|-- modules/                   # Core application logic
|   |-- __init__.py
|   |-- feed_collector.py      # Multi-format feed ingestion (CSV, TXT, JSON, HTTP/HTTPS)
|   |-- ioc_parser.py          # Multi-type regex & structural IOC extraction
|   |-- validator.py           # Network & cryptographic indicator validation
|   |-- normalizer.py          # Data normalization & deduplication
|   |-- database_manager.py    # SQLite storage with parameterized queries
|   |-- correlation.py         # Cross-feed correlation & deterministic scoring
|   |-- blocklist_generator.py # Formatted export (TXT, CSV, JSON) by IOC type
|   |-- report_generator.py    # Comprehensive Blue Team threat analytics
|   |-- pipeline.py            # End-to-end orchestration pipeline engine
|
|-- database/                  # SQLite persistent storage (.gitkeep)
|-- feeds/
|   |-- samples/               # Synthetic, safe benchmark threat feeds (.gitkeep)
|-- output/
|   |-- blocklists/            # Exported firewall/DNS/EDR blocklists (.gitkeep)
|   |-- reports/               # Executive and analytical intelligence reports (.gitkeep)
|-- logs/                      # Runtime execution logs (.gitkeep)
|-- tests/                     # Automated test suite (pytest)
|-- docs/                      # Architectural and operational documentation
```

---

## Deterministic Severity Scoring Model

This project strictly adheres to non-AI, deterministic heuristics:

| Distinct Source Count | Severity Rating | Description |
|:---:|:---:|:---|
| **$\ge$ 5** | **HIGH** | Corroborated across 5 or more independent intelligence feeds. High confidence maliciousness. |
| **2 – 4** | **MEDIUM** | Observed across 2 to 4 independent intelligence feeds. Corroborated threat indicator. |
| **1** | **LOW** | Isolated indicator observed in a single feed. Candidate for monitoring or validation. |

---

## Installation & Setup

1. **Clone or navigate to the repository:**
   ```bash
   cd Threat-Intelligence-Aggregator
   ```

2. **Verify Python 3.10+ installation:**
   ```bash
   python --version
   ```

3. **Install dependencies:**
   ```bash
   pip install -r requirements.txt
   ```

4. **Verify installation & status:**
   ```bash
   python main.py status
   ```

---

## Feed Collection (Phase 2)

The **Feed Collector** (`modules/feed_collector.py`) ingests threat intelligence indicators from local files and remote endpoints. It provides deterministic provenance tracking, strict size boundaries, and error tolerance.

### Key Capabilities
- **Supported Formats:** CSV, TXT, JSON.
- **Local File Ingestion:** Validates file existence, format extensions, file size limits (50MB default), and UTF-8 encoding with fallback.
- **Remote Network Ingestion:** Strict HTTP/HTTPS scheme enforcement, TLS verification enabled, configurable timeouts, custom User-Agent, and chunked streaming download to enforce payload boundaries.
- **Resilience:** Sequential multi-source collection (`collect_many`) guarantees that network drops or malformed individual feeds do not halt the collection of other feeds.
- **Provenance Data Structure (`FeedResult`):** Standardized metadata dataclass capturing `source_name`, `source_type`, `source_location`, `format`, `raw_content`, `fetched_at` (ISO 8601 UTC), `success`, and `error`.

### CLI Usage Examples

1. **Collect one or more local feed files:**
   ```bash
   python main.py collect --file feeds/samples/sample_feed.csv feeds/samples/sample_feed.txt feeds/samples/sample_feed.json
   ```

2. **Collect from remote threat URLs:**
   ```bash
   python main.py collect --url https://example.com/feeds/blocklist.txt https://example.org/threats.json
   ```

3. **Collect mixed sources simultaneously:**
   ```bash
   python main.py collect -f feeds/samples/sample_feed.csv -u https://example.com/feed.txt
   ```

4. **Verify environment status:**
   ```bash
   python main.py status
   ```

---

## IOC Candidate Parser (Phase 3)

The **IOC Parser** (`modules/ioc_parser.py`) extracts candidate Indicators of Compromise across all 8 supported categories from structured and unstructured threat intelligence feeds (`FeedResult` objects).

### Key Capabilities
- **Supported Feed Formats:** CSV (header-aware column detection), JSON (arrays of objects, nested structures, raw lists), and TXT (line-by-line, inline comment stripping).
- **Supported IOC Types:** IPv4, IPv6, Domain, URL, Email, MD5, SHA1, SHA256.
- **Span-Masking False-Positive Mitigation:** Higher-order indicators (URLs, Emails) are extracted first and their character spans masked so that embedded hostnames, IPs, or domains are not extracted as unrelated duplicate indicators.
- **Provenance Preservation (`ParsedIOC`):** Each extracted indicator retains its originating `source_name`, `source_type`, `source_location`, `feed_format`, `extracted_at` timestamp, `raw_value`, and auxiliary feed `metadata`.
- **Blue Team Operational Notice:** Ingestion and parsing identify **candidate IOCs only**. Parsing does not evaluate maliciousness or verify RFC/network validity (handled deterministically in Phase 4).

### CLI Usage Examples

1. **Parse candidate IOCs from local feeds:**
   ```bash
   python main.py parse --file feeds/samples/sample_feed.csv feeds/samples/sample_feed.txt feeds/samples/sample_feed.json
   ```

2. **Parse single feed:**
   ```bash
   python main.py parse -f feeds/samples/sample_feed.csv
   ```

---

## IOC Structural Validator & Scope Classifier (Phase 4)

The **IOC Validator** (`modules/validator.py`) enforces strict RFC standards and cryptographic specifications on extracted IOC candidates without performing any external network queries, DNS lookups, or payload execution.

### Validation Rules Across IOC Types
1. **IPv4:** Evaluated via standard `ipaddress.IPv4Address`. Rejects non-decimal octets and out-of-range values (>255). Segregates documentation (RFC 5737 TEST-NET-1/2/3), private (RFC 1918), loopback (`127.0.0.0/8`), multicast (RFC 5771), and link-local addresses.
2. **IPv6:** Evaluated via `ipaddress.IPv6Address`. Validates hexadecimal groups and compressed `::` notation. Segregates documentation (RFC 3849 `2001:db8::/32`), loopback (`::1`), link-local, and unique local addresses.
3. **Domain:** RFC 1035 / RFC 1123 FQDN syntax check. Maximum 253 total characters, 1-63 characters per label, valid alphanumeric boundaries (no leading/trailing hyphens or double dots), rejection of bare IP addresses, and alpha TLD check.
4. **URL:** RFC 3986 compliance. Scheme strictly restricted to `http` and `https`. Verifies host network location (valid domain or IP).
5. **Email:** Conservative RFC 5322 check. Validates single `@`, local part (1-64 chars, valid characters), and domain part structure.
6. **MD5 / SHA1 / SHA256:** Enforces exact character lengths (32, 40, and 64 characters respectively) and strict hexadecimal character sets (`[a-fA-F0-9]`).

### Blue Team Network Classifications
- `normal`: Publicly routable IPs, standard domains, URLs, emails, and hashes.
- `documentation`: Benchmark/test address ranges (RFC 5737 / RFC 3849) used safely in testing environments.
- `private`: RFC 1918 internal addresses (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`).
- `loopback`: Host loopback space (`127.0.0.0/8`, `::1`).
- `reserved`: IETF-reserved network space.
- `special`: Multicast or link-local address space.
- `unknown`: Unrecognized or malformed indicators.

> [!NOTE]
> **Syntactic Validity vs. Maliciousness:** Syntactic validation confirms that a string conforms to formal RFC specifications. It does not determine whether an indicator is benign or malicious. Deterministic correlation and risk scoring occur in subsequent phases.

### CLI Usage Example

```bash
python main.py validate --file feeds/samples/sample_feed.csv feeds/samples/sample_feed.txt feeds/samples/sample_feed.json
```

---

## IOC Normalization & Cross-Feed Deduplication (Phase 5)

The **IOC Normalization Engine** (`modules/normalizer.py`) converts structurally valid IOC candidates into deterministic canonical forms, identifies semantic duplicates across disparate feeds, and tracks observation frequencies while preserving complete source provenance and metadata.

### Canonicalization Rules & Examples
| IOC Type | Raw Input Example | Canonical Normalized Form | Transformation Rules |
|:---|:---|:---|:---|
| **IPv4** | ` 192.0.2.1 ` | `192.0.2.1` | Strips whitespace; validates via `IPv4Address` to standard dotted-decimal. |
| **IPv6** | `2001:0DB8:0000:0000:0000:0000:0000:0001` | `2001:db8::1` | Compressed lowercase canonical notation via `IPv6Address`. |
| **Domain** | `MALICIOUS-BEACON.EXAMPLE.COM.` | `malicious-beacon.example.com` | Lowercased, strips trailing DNS root dot, applies safe IDNA conversion. |
| **Domain (IDN)** | `münchen.de` | `xn--mnchen-3ya.de` | Converts internationalized domain names to standard ASCII punycode. |
| **URL** | `HTTPS://EXAMPLE.COM:443/gate.php?id=1` | `https://example.com/gate.php?id=1` | Lowercases scheme & host; removes default ports (80/443); preserves query/path. |
| **Email** | `ThreatOps+Drop@EXAMPLE.COM.` | `ThreatOps+Drop@example.com` | Preserves local part case sensitivity (RFC 5321); lowercases domain portion. |
| **MD5** | `D41D8CD98F00B204E9800998ECF8427E` | `d41d8cd98f00b204e9800998ecf8427e` | Converts hex characters to lowercase; preserves length. |
| **SHA1/256** | `E3B0C44298FC...` | `e3b0c44298fc...` | Converts hex characters to lowercase; preserves length. |

### Deduplication & Provenance Preservation
- **Deduplication Key:** Strictly evaluated as `(ioc_type, normalized_value)`. Different IOC types are never merged together.
- **Distinct Source Tracking:** Repeated occurrences of an indicator within the *same* feed do not artificially inflate the distinct source count.
- **Full Lineage:** Each `DeduplicatedIOC` preserves distinct sources list, total observation counts across feeds, first/last seen timestamps, and an array of all underlying `NormalizedIOC` records.

### CLI Usage Example

```bash
python main.py normalize --file feeds/samples/sample_feed.csv feeds/samples/sample_feed.txt feeds/samples/sample_feed.json
```

---

## SQLite Relational Database Manager (Phase 6)

The **SQLite Database Manager** (`modules/database_manager.py`) provides robust, ACID-compliant relational persistence for threat indicators, intelligence feeds, and individual observation audits at `database/threat_intelligence.db`.

### Relational Schema & Table Architecture
```text
  +------------------+         +-------------------------------+         +------------------+
  |     sources      |         |     indicator_observations    |         |    indicators    |
  +------------------+         +-------------------------------+         +------------------+
  | id (PK)          | <---+   | id (PK)                       |   +---> | id (PK)          |
  | source_name      |     +-- | source_id (FK)                |   |     | ioc_type         |
  | source_type      |         | indicator_id (FK) ------------+   |     | normalized_value |
  | source_location  |         | original_value                |         | first_seen       |
  | feed_format      |         | observed_at                   |         | last_seen        |
  | first_seen       |         | metadata (JSON)               |         | distinct_sources |
  +------------------+         +-------------------------------+         | total_occurrence |
                                                                         | severity         |
                                                                         | is_valid         |
                                                                         +------------------+
```

### Key Capabilities
- **Parameterized Queries:** All SQL queries strictly utilize parameterized placeholders (`?`), preventing SQL injection.
- **Foreign Key Enforcement:** Enforced with `PRAGMA foreign_keys = ON;` and `PRAGMA journal_mode = WAL;`.
- **Audit Provenance:** Individual feed observations are preserved in `indicator_observations` alongside JSON-serialized feed metadata.
- **Deterministic Heuristic Severity:** Distinct observing feeds are calculated automatically across sources:
  - **HIGH:** $\ge 5$ distinct sources
  - **MEDIUM:** $2 \dots 4$ distinct sources
  - **LOW:** $1$ distinct source

### CLI Database Commands

1. **Initialize database schema and indexes:**
   ```bash
   python main.py db init
   ```

2. **Ingest and persist threat feeds into database:**
   ```bash
   python main.py db ingest --file feeds/samples/sample_feed.csv feeds/samples/sample_feed.txt feeds/samples/sample_feed.json
   ```

3. **Display repository statistics:**
   ```bash
   python main.py db stats
   ```

4. **List indicators with severity and type filtering:**
   ```bash
   python main.py db list --severity MEDIUM
   python main.py db list --type ipv4 --limit 20
   ```

5. **Show detailed provenance and feed observation trail for an indicator:**
   ```bash
   python main.py db show 4
   ```

---

## Cross-Feed Correlation & Deterministic Risk Scoring (Phase 7)

The **Correlation Engine** (`modules/correlation.py`) performs cross-feed intelligence matching, analyzes multi-source corroboration, and computes deterministic severity ratings across the SQLite repository.

### Correlation Logic & Definitions
- **Cross-Feed Indicator:** An indicator observed by $\ge 2$ independent, distinct intelligence sources.
- **Distinct Source Counting:** Computed strictly as the cardinality of unique `source_id` observations:
  $$\text{Distinct Sources} = |\{ \text{source\_id} \mid \text{observation} \in \text{indicator} \}|$$
  Repeated sightings of an indicator within the *same* feed (e.g. 5 occurrences in one firewall log) do **not** artificially inflate the distinct source count.
- **Strict IOC Type Isolation:** Indicators of different types (e.g., domain `192.0.2.1` vs IP `192.0.2.1`) are never merged or correlated together.

### Deterministic Severity Scoring Model
| Severity Tier | Heuristic Condition | Operational Meaning |
|:---:|:---:|:---|
| **HIGH** | $\ge 5$ distinct reporting sources | Widespread consensus across 5+ independent threat feeds. Direct candidate for automated blocklists. |
| **MEDIUM** | $2 \dots 4$ distinct reporting sources | Corroborated cross-feed threat indicator. Ideal for heightened monitoring and SIEM rules. |
| **LOW** | $1$ distinct reporting source | Isolated threat indicator observed by a single source. Suitable for watchlist tracking. |

> [!NOTE]
> **Heuristic Scoring Disclaimer:** Severity ratings are deterministic mathematical metrics based on multi-feed corroboration and reporting density. They do **not** constitute absolute proof that an indicator is malicious.

### CLI Correlation Commands

1. **Perform full cross-feed correlation analysis:**
   ```bash
   python main.py correlate
   ```

2. **Filter by minimum observing sources (cross-feed indicators only):**
   ```bash
   python main.py correlate --min-sources 2
   ```

3. **Filter by severity tier or IOC type:**
   ```bash
   python main.py correlate --severity MEDIUM
   python main.py correlate --type domain
   ```

4. **Inspect individual indicator correlation profile:**
   ```bash
   python main.py correlate --indicator-id 4
   ```

---

## IOC Blocklist Generator (Phase 8)

The **Blocklist Generator** (`modules/blocklist_generator.py`) generates categorized, production-ready blocklists from correlated indicators stored in SQLite. It allows Blue Team defenders to export indicators by individual IOC category or across all categories in line-delimited plain text (`TXT`), comma-separated values (`CSV`), or structured `JSON`.

### Supported Categories
- **IPv4 Addresses** (`ipv4`)
- **IPv6 Addresses** (`ipv6`)
- **Domain Names** (`domain`)
- **URLs** (`url`)
- **Email Addresses** (`email`)
- **MD5 Hashes** (`md5`)
- **SHA1 Hashes** (`sha1`)
- **SHA256 Hashes** (`sha256`)

### Supported Output Formats
1. **TXT (`.txt`)**: One canonical indicator per line. Ideal for firewall address groups, DNS sinkhole zones (e.g. Pi-hole / Bind9 RPZ), and network intrusion detection rule sets.
2. **CSV (`.csv`)**: Tabular export containing full threat intelligence metadata:
   - `ioc_type`
   - `indicator`
   - `severity`
   - `distinct_sources_count`
   - `total_occurrences`
   - `first_seen`
   - `last_seen`
3. **JSON (`.json`)**: Structured export with top-level metadata (`generated_at`, `total_indicators`, `filters`) and an array of indicator objects including reporting source feeds.

### Granular Filtering Capabilities
- **Category Filter (`--type` / `-t`)**: Export one specific IOC category (e.g., `ipv4`, `domain`) or all categories (`all`).
- **All Categories Export (`--all` / `-a`)**: Generates 8 separate blocklist files (one per IOC type) or a unified file when combined with `--combined`.
- **Severity Filter (`--severity` / `-s`)**: Select only `HIGH`, `MEDIUM`, or `LOW` severity indicators.
- **Minimum Sources (`--min-sources` / `-m`)**: Restrict export to indicators seen across at least $N$ distinct threat feeds.
- **Exclude Low Severity (`--exclude-low`)**: Automatically filters out all single-source / LOW severity indicators.
- **Cross-Feed Only (`--cross-feed-only`)**: Restricts export to corroborated multi-feed indicators ($\ge 2$ distinct sources).
- **Custom Output Destination (`--output` / `-o`)**: Specify a custom directory or file destination; parent directories are created automatically if missing.

### Safety Boundaries
> [!IMPORTANT]
> - **Zero Network Activity:** Blocklist generation is strictly local and offline. No HTTP requests, socket connections, or DNS queries are performed.
> - **Non-Destructive & Read-Only:** Database records are never modified, deleted, or altered during blocklist export.
> - **No System Modification:** Does not alter host firewall rules, hosts files, or network adapters.
> - **No Indicator Execution:** Indicator strings are never executed or passed to shell evaluators.

### CLI Blocklist Examples

1. **Export IPv4 TXT blocklist (default destination: `output/blocklists/blocklist_ipv4.txt`):**
   ```bash
   python main.py blocklist --type ipv4 --format txt
   ```

2. **Export corroborated domain indicators (seen in $\ge 2$ sources) as CSV:**
   ```bash
   python main.py blocklist --type domain --format csv --cross-feed-only
   ```

3. **Export high-severity SHA256 hashes as JSON:**
   ```bash
   python main.py blocklist --type sha256 --format json --severity HIGH
   ```

4. **Export all 8 categories to separate TXT files, excluding low-severity noise:**
   ```bash
   python main.py blocklist --all --format txt --exclude-low
   ```

5. **Export unified blocklist of all categories into a single CSV:**
   ```bash
   python main.py blocklist --all --combined --format csv
   ```

6. **Export to a custom destination directory:**
   ```bash
   python main.py blocklist --type ipv4 --format txt --output C:\exports\firewall\
   ```

---

## Threat Intelligence Report Generator (Phase 9)

The **Report Generator** (`modules/report_generator.py`) produces comprehensive, audit-grade cybersecurity threat intelligence reports across Markdown (`.md`), JSON (`.json`), and CSV (`.csv`) formats. It synthesizes repository statistics, multi-source consensus, data quality, and feed provenance without external AI/LLM models or network lookups.

### Report Sections
1. **Executive Summary**: High-level overview of unique indicators, total observations, active feed sources, multi-source consensus rate ($\ge 2$ feeds), and overall severity distribution.
2. **IOC Category Statistics**: Breakdown across all 8 supported indicator types (`ipv4`, `ipv6`, `domain`, `url`, `email`, `md5`, `sha1`, `sha256`) with absolute counts and percentage shares.
3. **Severity Analysis & Scoring Model**: Evaluation of indicators across HIGH, MEDIUM, and LOW tiers with heuristic threshold definitions and operational guidelines.
4. **Cross-Feed Correlation & Consensus**: Detailed breakdown of indicators corroborating across multiple feeds, including observing sources and observation intervals.
5. **Intelligence Source Analysis**: Contribution metrics per registered feed (format, feed location, total observations, unique indicators contributed).
6. **Top Repeated Indicators**: Ranked list of the most frequently observed indicators across all feeds.
7. **Data Quality & Integrity Audit**: Analysis of syntactic validity, duplicate observation deduplication, metadata completeness, and data limitations.
8. **Feed Processing Summary**: Audit trail of feed ingestion runs, success/failure counts, and parser/network errors.

### Supported Export Formats
- **Markdown (`.md`)**: Professional, readable GitHub Flavored Markdown cybersecurity report with tables, callout blocks, and executive metrics.
- **JSON (`.json`)**: Machine-readable structured object hierarchy adhering to the full intelligence schema.
- **CSV (`.csv`)**: Tabular export of indicator correlation findings with reporting sources and observation metrics.

### Granular Filtering & Customization
- `--format / -f`: Choose `md`, `json`, or `csv` (default: `md`).
- `--output / -o`: Custom file path or target directory (auto-creates directories; avoids silent file overwrites).
- `--severity / -s`: Filter findings by severity tier (`HIGH`, `MEDIUM`, `LOW`).
- `--type / -t`: Filter findings by indicator category (`ipv4`, `domain`, etc.).
- `--cross-feed-only`: Restrict findings to corroborated multi-feed indicators ($\ge 2$ sources).
- `--top`: Number of top repeated indicators to display (default: 10).
- `--overwrite`: Allow overwriting an existing report file if collision occurs.

### Heuristic Scoring & Data Limitations
> [!NOTE]
> - **Heuristic Scoring Model:** Severity ratings are mathematical metrics based on multi-feed corroboration and observation density. They do **not** constitute absolute proof of maliciousness.
> - **Syntactic Validation:** Validation confirms syntactic adherence to RFC/cryptographic standards; indicators are not live-probed or scanned.
> - **Feed History:** Feed run audit records reflect verified CLI ingestion runs.

### CLI Report Examples

1. **Generate default Markdown report (saved to `output/reports/threat_report_YYYY-MM-DD_HHMMSS.md`):**
   ```bash
   python main.py report
   ```

2. **Generate structured machine-readable JSON report:**
   ```bash
   python main.py report --format json
   ```

3. **Generate tabular CSV report of indicators and source provenance:**
   ```bash
   python main.py report --format csv
   ```

4. **Filter report to HIGH severity indicators only:**
   ```bash
   python main.py report --severity HIGH
   ```

5. **Filter report to corroborated cross-feed indicators ($\ge 2$ sources):**
   ```bash
   python main.py report --cross-feed-only
   ```

6. **Filter report by IOC type and limit top repeated indicators to 20:**
   ```bash
   python main.py report --type domain --top 20
   ```

7. **Export report to custom output destination:**
   ```bash
   python main.py report --format md --output C:\reports\weekly_audit.md
   ```

---

## End-to-End CLI Pipeline (Phase 10)

The **Threat Intelligence Pipeline** (`modules/pipeline.py`) provides a unified, end-to-end command-line workflow that chains all phases of the intelligence aggregation lifecycle in a single deterministic operation.

### Pipeline Stages
1. **Feed Collection (`FeedCollector`):** Retrieves threat intelligence feeds from local files (CSV, TXT, JSON) or remote HTTP/HTTPS endpoints with timeout limits, streaming size boundaries, and error isolation.
2. **IOC Parsing (`IOCParser`):** Extracts raw candidate indicators across all 8 supported categories using structure-aware parsers and span-masking regex algorithms.
3. **Syntax Validation (`IOCValidator`):** Verifies indicators against RFC specifications and cryptographic standards. Flags private/documentation networks and separates structurally invalid strings.
4. **Canonical Normalization (`IOCNormalizer`):** Converts valid indicators into deterministic canonical representations (e.g. lowercase domains/hashes/emails, defanging removal, standard URL paths, IPv6 compression).
5. **Deduplication & Provenance (`IOCNormalizer.deduplicate`):** Merges duplicate indicator occurrences within the batch while capturing complete multi-feed observation provenance.
6. **Database Persistence (`DatabaseManager`):** Safely persists canonical records, observations, and feed audit runs to the SQLite repository using atomic transactions and parameterized statements.
7. **Cross-Feed Correlation (`CorrelationEngine`):** Recalculates multi-source consensus metrics and deterministic severity ratings across the entire database.
8. **Optional Downstream Generation:** Automatically invokes the **Report Generator** (`--generate-report`) and **Blocklist Generator** (`--generate-blocklists`) upon successful pipeline execution.

### CLI Pipeline Arguments
- `--file / -f PATH [PATH ...]`: Local feed file path (CSV, TXT, JSON). Repeatable and accepts multiple arguments.
- `--url / -u URL [URL ...]`: Remote feed URL (HTTP/HTTPS). Repeatable and accepts multiple arguments.
- `--generate-report`: Generates a comprehensive Markdown report in `output/reports/` upon ingestion completion.
- `--generate-blocklists`: Generates categorized TXT blocklists in `output/blocklists/` across all 8 IOC categories.

### Pipeline Usage Examples (PowerShell / Command Prompt)

1. **Ingest single or multiple local feed files:**
   ```powershell
   python main.py pipeline --file feeds/samples/sample_feed.csv feeds/samples/sample_feed.txt feeds/samples/sample_feed.json
   ```

2. **Ingest feeds using repeatable `-f` flags:**
   ```powershell
   python main.py pipeline -f feeds/samples/sample_feed.csv -f feeds/samples/sample_feed.txt
   ```

3. **Ingest from remote HTTP/HTTPS threat feeds:**
   ```powershell
   python main.py pipeline --url https://example.com/feeds/threats.csv https://example.org/iocs.txt
   ```

4. **Execute complete pipeline with automatic report and blocklist generation:**
   ```powershell
   python main.py pipeline -f feeds/samples/sample_feed.csv -f feeds/samples/sample_feed.txt -f feeds/samples/sample_feed.json --generate-report --generate-blocklists
   ```

5. **Execute pipeline targeting a custom database destination:**
   ```powershell
   python main.py --db database/custom_threat.db pipeline -f feeds/samples/sample_feed.csv
   ```

---

## Security, Reliability & Quality Assurance (Phase 11)

A comprehensive security, quality assurance, and edge case audit was completed to ensure operational resilience and defensive integrity across the toolkit.

### Key Hardening & Architectural Guarantees

1. **Server-Side Request Forgery (SSRF) Mitigation (`FeedCollector`):**
   - **Automatic Redirects Disabled:** `allow_redirects=False` is enforced. All HTTP redirects (`301`, `302`, `303`, `307`, `308`) are intercepted and evaluated manually against a strict maximum redirect count (default: 5).
   - **Pre-Connection Destination Validation:** Every target URL and redirect hop is validated *prior* to establishing a network connection. No HTTP request is dispatched to a rejected destination.
   - **Direct & Resolved Address Rejection:** Rejects `localhost`, loopback addresses (`127.0.0.0/8`, `::1`), RFC 1918 private subnets (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`), IPv6 unique local addresses (`fc00::/7`, `fd00::/8`), link-local / cloud metadata services (`169.254.0.0/16`, `fe80::/10`), multicast (`224.0.0.0/4`, `ff00::/8`), reserved ranges (`240.0.0.0/4`), unspecified addresses (`0.0.0.0`, `::`), and local domain suffixes (`.localhost`, `.local`, `.internal`).
   - **IPv4-Mapped IPv6 Inspection:** Evaluates embedded IPv4 addresses in IPv6 mappings (e.g., `::ffff:127.0.0.1`, `::ffff:10.0.0.1`, `::ffff:169.254.169.254`) to prevent dual-stack circumvention.
   - **Multi-Answer DNS Inspection:** Inspects all IP addresses returned by `socket.getaddrinfo()`. If any resolved IP belongs to a prohibited category, the request is rejected immediately.
   - **Proxy Environment Isolation:** Explicitly passes `proxies={"http": None, "https": None}` to prevent ambient environment variables (`HTTP_PROXY`, `HTTPS_PROXY`, `ALL_PROXY`) from intercepting or rerouting outbound requests.

2. **DNS Pre-Validation & Known DNS Rebinding TOCTOU Limitation:**
   - Hostnames are resolved and checked via `socket.getaddrinfo()` before issuing network requests.
   - **Known Limitation (TOCTOU):** The underlying HTTP engine (`requests` / `urllib3`) performs a second, independent DNS resolution during socket connection establishment. If an adversary operates an authoritative nameserver that returns a benign public IP during pre-validation and subsequently returns an internal/loopback address with a 0-second TTL during connection, the underlying TCP connection will connect to the re-bound IP. True DNS rebinding prevention requires low-level socket IP pinning or custom transport adapters.

3. **Private Network Access Override (`allow_private_networks`):**
   - The `allow_private_networks: bool` configuration defaults to `False` throughout all CLI subcommands and modules.
   - Setting `allow_private_networks=True` is an intentional debugging and testing override that **explicitly weakens** SSRF protections, permitting the collector to query local, private, and internal addresses in controlled laboratory environments.

4. **CSV Formula Injection Neutralization (`BlocklistGenerator` & `ReportGenerator`):**
   - Exported CSV blocklists and analytical reports sanitize cells starting with formula trigger characters (`=`, `+`, `-`, `@`, `\t`, `\r`) by prepending a single quote (`'`).
   - Prevents Dynamic Data Exchange (DDE) and formula execution in Microsoft Excel, LibreOffice Calc, and Google Sheets.

5. **Repeated Ingestion & Observation Semantics (`DatabaseManager`):**
   - When a feed is ingested again, each sighting records a timestamped record in `indicator_observations`.
   - `total_occurrences` accurately reflects the cumulative sightings across all runs.
   - `distinct_sources_count` tracks unique feed sources (`COUNT(DISTINCT source_id)`) and is **never** inflated by repeated ingestion of the same feed.
   - Severity calculation is strictly driven by `distinct_sources_count`, preventing artificial score inflation over time.
   - `last_seen` timestamp is automatically synchronized to the latest observation time.

6. **Feed Runs Audit Table Symmetry (`feed_ingestion_runs` & `feed_runs` View):**
   - The primary audit log is stored in `feed_ingestion_runs`.
   - A SQLite view `feed_runs` provides backward and query symmetry without schema migration.
   - `get_feed_runs_summary` alias is provided on `DatabaseManager`.

7. **Academic MVP Scope & Security Disclaimer:**
   > [!IMPORTANT]
   > This toolkit is an **academic minimum viable product (MVP)** designed for local educational, research, and non-critical Blue Team testing. It is **not** a production-hardened cybersecurity service or enterprise gateway.
   > - Syntactic and structural validation confirms conformance to RFC specifications and cryptographic hash formats; it does not scan or probe targets.
   > - Severity ratings represent multi-source consensus metrics, **not** definitive proof of malicious intent. Indicators must always be investigated within organizational context.

---

## Development Roadmap & Phases

- [x] **Phase 1: Workspace and Architecture** (Filesystem, base configuration, .gitignore, requirements)
- [x] **Phase 2: Feed Collector** (CSV, TXT, JSON, HTTP/S feed handling)
- [x] **Phase 3: IOC Parser** (Regex & structured extraction for 8 IOC types)
- [x] **Phase 4: IOC Validator** (IP, domain, URL, email, hash validation & sanitization)
- [x] **Phase 5: Normalization** (Standard schemas, deduplication, metadata binding)
- [x] **Phase 6: SQLite Database** (Parameterized relational persistence & history)
- [x] **Phase 7: Correlation Engine** (Cross-feed matching & deterministic scoring)
- [x] **Phase 8: Blocklist Generator** (Categorized TXT, CSV, and JSON blocklist outputs)
- [x] **Phase 9: Report Generator** (Blue Team analytical & executive reports)
- [x] **Phase 10: End-to-End CLI Integration** (Unified pipeline command, repeatable feed inputs, automated reporting & blocklists)
- [x] **Phase 11: Security Review, Debugging & Quality Assurance** (SSRF mitigation, manual redirects, CSV injection defense, audit schema view, observation semantics, TOCTOU documentation, 154 tests)
- [x] **Phase 12: Documentation and GitHub Preparation** (Final polish and delivery)

