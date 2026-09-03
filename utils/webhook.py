import requests

from config.settings import EXECUTION_LIMIT_PER_SERVICE, WEBHOOK_URL


CURRENT_STATUS = {
    "success": "🟢 Success",
    "rate_limit": "🟡 Rate Limit",
    "failed": "🔴 Failed",
}

ALL_TIME_STATUS = {
    "success": "🟢 Finished",
    "failed": "🔴 Unfinished",
}

COLORS = {
    "success": 0x2ECC71,
    "rate_limit": 0xf7e305,
    "failed": 0xf2070f
}

SERVICE_W = 22
STATUS_W = 18
VALUE_W = 15


def pick_color(rate_limit_cnt, failed_cnt):
    if failed_cnt > 0:
        return COLORS["failed"]
    if rate_limit_cnt > 0:
        return COLORS["rate_limit"]

    return COLORS["success"]


def make_table(services, status_map, value_header):
    lines = [
        f"{'Service':<{SERVICE_W}}{'Status':<{STATUS_W}}{value_header:>{VALUE_W}}",
        "─" * (SERVICE_W + STATUS_W + VALUE_W),
    ]

    rate_limit_cnt = 0
    failed_cnt = 0

    for service, status, value in services:
        lines.append(
            f"{service:<{SERVICE_W}}"
            f"{status_map[status]:<{STATUS_W}}"
            f"{value:>{VALUE_W - 1}}"
        )

        if status == "rate_limit":
            rate_limit_cnt += 1
        elif status == "failed":
            failed_cnt += 1


    return "```text\n" + "\n".join(lines) + "\n```", pick_color(rate_limit_cnt, failed_cnt)


def post_to_webhook(current_services, all_time_services):
    curr_exec_table, curr_color = make_table(current_services, CURRENT_STATUS, "Collected now")
    all_exec_table, all_color = make_table(all_time_services, ALL_TIME_STATUS, "Collected")

    payload = {
        "embeds": [
            {
                "title": "Current execution status",
                "description": curr_exec_table,
                "color": curr_color,
                "footer": {
                    "text": f"Execution limit is set to: {EXECUTION_LIMIT_PER_SERVICE}"
                },
            },
            {
                "title": "All time execution status",
                "description": all_exec_table,
                "color": all_color,
            },
        ]
    }

    response = requests.post(WEBHOOK_URL, json=payload)

    if response.status_code in (200, 204):
        print("Webhook sent successfully!")
    else:
        print(f"Error {response.status_code}: {response.status_code}")
        print(response.text)
