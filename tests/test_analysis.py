import queue
from typing import Any

from models.observable import Observable, ObservableType
from utils import analysis


class ReverseDnsPivotEngine:
    @property
    def name(self) -> str:
        return "reverse_dns"

    @property
    def supported_types(self) -> ObservableType:
        return ObservableType.FQDN | ObservableType.URL

    @property
    def is_pivot_engine(self) -> bool:
        return True

    @property
    def execute_after_reverse_dns(self) -> bool:
        return False

    def analyze(self, observable: Observable) -> dict[str, list[str]]:
        return {"reverse_dns": ["93.184.216.34"]}


class PostPivotEngine:
    @property
    def name(self) -> str:
        return "post_pivot_engine"

    @property
    def supported_types(self) -> ObservableType:
        return ObservableType.IPV4 | ObservableType.IPV6 | ObservableType.BOGON

    @property
    def is_pivot_engine(self) -> bool:
        return False

    @property
    def execute_after_reverse_dns(self) -> bool:
        return True

    def analyze(self, observable: Observable) -> dict[str, Any]:
        return {
            "seen_value": observable.value,
            "seen_type": str(observable.type),
        }


class ContextAwareEngine:
    @property
    def name(self) -> str:
        return "context_engine"

    @property
    def supported_types(self) -> ObservableType:
        return ObservableType.FQDN

    @property
    def is_pivot_engine(self) -> bool:
        return False

    @property
    def execute_after_reverse_dns(self) -> bool:
        return False

    def analyze(self, observable: Observable) -> dict[str, str]:
        return {"status": "seen"}


class AiVerdictOrderEngine:
    @property
    def name(self) -> str:
        return "ai_verdict"

    @property
    def supported_types(self) -> ObservableType:
        return ObservableType.FQDN

    @property
    def is_pivot_engine(self) -> bool:
        return False

    @property
    def execute_after_reverse_dns(self) -> bool:
        return False

    def analyze(self, observable: Observable, context: dict[str, object]) -> dict[str, object]:
        return {
            "context_engine_seen": context.get("context_engine"),
            "ai_verdict_seen_before_run": context.get("ai_verdict"),
        }


def test_reverse_dns_pivot_preserves_returned_observable(monkeypatch) -> None:
    monkeypatch.setattr(
        analysis,
        "LOADED_ENGINES",
        {
            "reverse_dns": ReverseDnsPivotEngine(),
            "post_pivot_engine": PostPivotEngine(),
        },
    )

    result_queue: queue.Queue = queue.Queue()
    observable = Observable(value="example.com", type=ObservableType.FQDN)

    analysis.analyze_observable(
        observable=observable,
        index=0,
        selected_engines=["reverse_dns", "post_pivot_engine"],
        result_queue=result_queue,
    )

    _, result = result_queue.get_nowait()

    assert result["observable"].value == "example.com"
    assert result["observable"].type is ObservableType.FQDN
    assert result["reversed_success"] is True
    assert result["reverse_dns"] == {"reverse_dns": ["93.184.216.34"]}
    assert result["post_pivot_engine"]["seen_value"] == "93.184.216.34"
    assert result["post_pivot_engine"]["seen_type"] == "IPV4"


def test_ai_verdict_runs_after_selected_engines(monkeypatch) -> None:
    monkeypatch.setattr(
        analysis,
        "LOADED_ENGINES",
        {
            "context_engine": ContextAwareEngine(),
            "ai_verdict": AiVerdictOrderEngine(),
        },
    )

    result_queue: queue.Queue = queue.Queue()
    observable = Observable(value="example.com", type=ObservableType.FQDN)

    analysis.analyze_observable(
        observable=observable,
        index=0,
        selected_engines=["ai_verdict", "context_engine"],
        result_queue=result_queue,
    )

    _, result = result_queue.get_nowait()

    assert result["context_engine"] == {"status": "seen"}
    assert result["ai_verdict"]["context_engine_seen"] == {"status": "seen"}
    assert result["ai_verdict"]["ai_verdict_seen_before_run"] is None
