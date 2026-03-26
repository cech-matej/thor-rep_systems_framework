import json
from pathlib import Path
from collections import Counter

from collectors.registry import get_collector_map
from collectors.visualization.barplot import plot_stacked


def _load_json(path: Path):
    with open(path, "r") as f:
        return json.load(f)


def _extract_stats(data, collector):
    dn_counter = Counter()
    ipv4_counter = Counter()
    ipv6_counter = Counter()

    seen_ipv4 = set()
    seen_ipv6 = set()

    for entry in data:
        # --- domain ---
        if collector.supports_domain:
            dn_data = entry.get("dn_data")
            if dn_data:
                verdict = collector.classify(dn_data)
                dn_counter[verdict] += 1

        # --- IPv4 ---
        if collector.supports_ipv4:
            for ip in entry.get("A", []):
                if ip in seen_ipv4:
                    continue

                ip_data = entry.get(ip)
                if ip_data:
                    verdict = collector.classify(ip_data)
                    ipv4_counter[verdict] += 1
                    seen_ipv4.add(ip)

        # --- IPv6 ---
        if collector.supports_ipv6:
            for ip in entry.get("AAAA", []):
                if ip in seen_ipv6:
                    continue

                ip_data = entry.get(ip)
                if ip_data:
                    verdict = collector.classify(ip_data)
                    ipv6_counter[verdict] += 1
                    seen_ipv6.add(ip)

    return dn_counter, ipv4_counter, ipv6_counter


def visualize(output_dir: str | Path, show: bool = True, show_values: bool = False):
    output_path = Path(output_dir)

    if not output_path.exists():
        raise FileNotFoundError(f"Output directory not found: {output_path}")

    collector_map = get_collector_map()

    collector_stats = {
        "dn": {},
        "ipv4": {},
        "ipv6": {}
    }

    for file_path in output_path.glob("*.json"):
        collector_name = file_path.stem

        collector = collector_map.get(collector_name)

        if not collector:
            print(f"No collector found for {collector_name}, skipping")
            continue

        print(f"Processing {collector_name}")

        data = _load_json(file_path)

        dn_counter, ipv4_counter, ipv6_counter = _extract_stats(data, collector)

        # ONLY include if supported AND has data

        if collector.supports_domain and sum(dn_counter.values()) > 0:
            collector_stats["dn"][collector_name] = dn_counter

        if collector.supports_ipv4 and sum(ipv4_counter.values()) > 0:
            collector_stats["ipv4"][collector_name] = ipv4_counter

        if collector.supports_ipv6 and sum(ipv6_counter.values()) > 0:
            collector_stats["ipv6"][collector_name] = ipv6_counter

    # --- plots (only if not empty) ---
    plots_output_path = output_path / "plots"

    if collector_stats["dn"]:
        plot_stacked(collector_stats["dn"], "Domain Classification", save_path=f"{plots_output_path}/dn_barplot.png",
                     show=show, show_values=show_values)
    else:
        print("No domain data to plot")

    if collector_stats["ipv4"]:
        plot_stacked(collector_stats["ipv4"], "IPv4 Classification", save_path=f"{plots_output_path}/ipv4_barplot.png",
                     show=show, show_values=show_values)
    else:
        print("No IPv4 data to plot")

    if collector_stats["ipv6"]:
        plot_stacked(collector_stats["ipv6"], "IPv6 Classification", save_path=f"{plots_output_path}/ipv6_barplot.png",
                     show=show, show_values=show_values)
    else:
        print("No IPv6 data to plot")

    return collector_stats