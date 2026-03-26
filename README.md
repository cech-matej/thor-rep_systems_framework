# Threat Intelligence Aggregator

This project collects and aggregates threat intelligence data from multiple external services, enriches domain/IP data, and provides visualization of the results.

---

## Setup

### 1. Create `.env` file

Copy the example file:

```bash
cp .env.example .env
```

Then fill in your API keys and configuration values.

---

### 2. Configure settings

Review and adjust:

```
config/settings.py
```

This file contains:

* API keys (loaded from `.env`)
* Mock API configuration
* Feature flags (e.g. `USE_MOCK_API`)

---

### 3. Install dependencies

```bash
pip install -r requirements.txt
```

---

## Usage

### Specify input file in `main.py`
Before running the data collection, you need to provide a JSON file containing the domains to analyze.
Update the `main.py` call to `load_domains()` with the path to your input file.

#### Input file format (example test_domains.json)
```json
[
  {
    "domain_name": "test.com",
    "A": [
      "8.8.8.8",
      "9.9.9.9"
    ],
    "AAAA": [
      "2001:4860:4860::8888"
    ]
  },
  {
    "domain_name": "test2.com",
    "A": [
      "8.8.8.8"
    ],
    "AAAA": [
      "2001:4860:4860::8888"
    ]
  }
]
```

### Run data collection

```bash
python main.py
```

This will:

* Collect data from all registered collectors
* Save results into the output directory (e.g. `output/`)

---

### Generate visualizations

```python
from utils.visualize import visualize

visualize("output_folder_path")
```

This will:

* Load existing JSON files
* Classify results
* Generate bar charts for:

  * Domains
  * IPv4
  * IPv6

---

## Adding a New Collector

Collectors are the core building blocks of this project. Each collector integrates one external service.

---

### 1. Create a new collector file

Create a new file in:

```
collectors/<my_collector>.py
```

---

### 2. Inherit from `BaseCollector`

```python
from collectors.base import BaseCollector
from utils.verdict import Verdict


class myCollector(BaseCollector):
    name = "my_collector"

    # Set these flags based on the types of data the service provides:
    # - supports_domain: True if the service can provide data about domain names
    # - supports_ipv4: True if the service can provide data about IPv4 addresses
    # - supports_ipv6: True if the service can provide data about IPv6 addresses
    # Only the supported data types will be included in the visualizations
    supports_domain = True
    supports_ipv4 = True
    supports_ipv6 = False
```

---

### 3. Implement `collect()`

This method fetches raw data from the API.

```python
def collect(self, target: str) -> dict:
    response = self.session.get("https://api.example.com", params={"q": target})

    if not response.ok:
        return {}

    data = response.json()

    return {
        "score": data.get("score", 0),
        "flagged": data.get("flagged", False),
    }
```

**Important:**

* Always return a dictionary
* Do NOT classify here
* Keep raw data for later processing

---

### 4. Implement `classify()`

This converts raw data into a standardized verdict.

```python
def classify(self, data: dict) -> Verdict:
    score = data.get("score", -1)

    if score < 0:
        return Verdict.NO_DATA
    elif score < 10:
        return Verdict.BENIGN
    elif score < 50:
        return Verdict.SUSPICIOUS
    else:
        return Verdict.MALICIOUS
```

Must return one of:

* `Verdict.NO_DATA`
* `Verdict.BENIGN`
* `Verdict.SUSPICIOUS`
* `Verdict.MALICIOUS`

---

### 5. Register the collector

Add your collector to:

```
collectors/registry.py
```

```python
from collectors.my_collector import MyCollector

def get_all_collectors():
    return [
        ...
        MyCollector(),
    ]
```

---

### 6. Done

Your collector will now automatically:

* Run during `main.py`
* Produce its own JSON file
* Be included in visualizations (if it supports the data type)

---

## Visualization Rules

* Only collectors that support a data type are included:

  * `supports_domain`
  * `supports_ipv4`
  * `supports_ipv6`
* Only collectors with actual data appear in graphs
* Classification is applied **only during visualization**

---

## Notes

* Some collectors do not support all data types (e.g. domain vs IP)
* Such collectors are automatically excluded from irrelevant graphs
* Missing or invalid API keys may result in empty outputs

### Caching and Rate Limits

To minimize unnecessary API requests and avoid hitting rate limits, the framework caches collector responses by IP or domain.

* If multiple domains share the same IPv4 or IPv6 address, the collector will query the service only once for that IP.
* Subsequent lookups for the same IP or domain will use the cached result.
* Domain names and IP addresses are handled separately depending on the collector’s capabilities.

This ensures efficient data collection while keeping API usage under control.