from enum import Enum


class Verdict(Enum):
    BENIGN = "Benign"
    SUSPICIOUS = "Suspicious"
    MALICIOUS = "Malicious"
    NO_DATA = "No data"


VERDICT_ORDER = [
    Verdict.BENIGN,
    Verdict.SUSPICIOUS,
    Verdict.MALICIOUS,
    Verdict.NO_DATA
]


VERDICT_COLORS = {
    Verdict.BENIGN: "green",
    Verdict.SUSPICIOUS: "orange",
    Verdict.MALICIOUS: "red",
    Verdict.NO_DATA: "grey"
}