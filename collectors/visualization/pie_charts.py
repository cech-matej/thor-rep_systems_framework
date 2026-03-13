import matplotlib.pyplot as plt

from collectors.base import BaseCollector


def make_collector_pie_charts(collector: BaseCollector, malicious_data: list, benign_data: list):
    fig, ax = plt.subplots(ncols=2, figsize=(12, 5))
    fig.suptitle(collector.name.capitalize(), fontsize=18)

    # Malicious
    malicious_counts = collector.classify_data(malicious_data)
    ax[0].pie(malicious_counts, labels=collector.vis_labels, autopct="%1.1f%%", colors=collector.vis_colors)
    ax[0].set_title("Malicious samples")

    # Benign
    benign_counts = collector.classify_data(benign_data)
    ax[1].pie(benign_counts, labels=collector.vis_labels, autopct="%1.1f%%", colors=collector.vis_colors)
    ax[1].set_title("Benign samples")

    return fig, ax