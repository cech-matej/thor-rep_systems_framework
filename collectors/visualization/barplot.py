import matplotlib.pyplot as plt
from utils.verdict import VERDICT_ORDER, VERDICT_COLORS
from pathlib import Path

def plot_stacked(
    data: dict,
    title: str,
    save_path: str | Path = None,
    show: bool = True,
    bar_height: float = 0.6,
    show_values: bool = False,
):
    """
    Create a horizontal stacked bar chart for collectors vs verdicts.

    Args:
        data: dict
            {
                "collector_name": Counter({Verdict: count, ...}),
                ...
            }
        title: str
            Plot title
        save_path: str, optional
            File path to save the plot as an image (PNG, PDF, etc.)
        show: bool, default True
            Whether to display the plot interactively
        bar_height: float
            Thickness of each bar (default 0.6); stays constant regardless of number of collectors
        show_values: bool, default False
            Whether to display the numeric count of each verdict on the bars
    """
    names = list(data.keys())
    n = len(names)

    # Adjust figure height based on number of collectors
    fig_height = max(6, n * bar_height * 1.5)  # 1.5 factor for spacing
    plt.figure(figsize=(12, fig_height))

    bottom = [0] * n

    for verdict in VERDICT_ORDER:
        values = [data[name].get(verdict, 0) for name in names]

        bars = plt.barh(
            y=names,
            width=values,
            left=bottom,
            height=bar_height,
            label=verdict.value,
            color=VERDICT_COLORS[verdict],
        )

        # Optionally add numeric values
        if show_values:
            for bar, value, b in zip(bars, values, bottom):
                if value > 0:
                    x = b + value / 2  # center of the segment
                    y = bar.get_y() + bar.get_height() / 2
                    plt.text(
                        x, y, str(value),
                        ha="center", va="center",
                        color="black", fontsize=9
                    )

        bottom = [b + v for b, v in zip(bottom, values)]

    plt.xlabel("Count")
    plt.ylabel("Collector")
    plt.title(title)
    plt.legend(title="Verdict", loc="upper right")
    plt.tight_layout()

    # Save if a path is provided
    if save_path:
        save_path = Path(save_path)
        save_path.parent.mkdir(parents=True, exist_ok=True)
        plt.savefig(save_path, dpi=300)
        print(f"Saved plot to {save_path}")

    if show:
        plt.show()
    else:
        plt.close()
