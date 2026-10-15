from typing import Any

import pytest

from notline.graph.audit import AUDIT_QUERIES, GraphAudit, collect_graph_audit


class RecordingDriver:
    def __init__(self, values: dict[str, int]) -> None:
        self.values = values
        self.queries: list[str] = []

    def execute_query(self, query: str, **parameters: Any) -> Any:
        self.queries.append(query)
        metric = next(
            name for name, statement in AUDIT_QUERIES.items() if statement == query
        )
        return type("Result", (), {"records": [{"value": self.values[metric]}]})()


def test_collect_graph_audit_reads_all_metrics() -> None:
    values = {metric: 1 for metric in AUDIT_QUERIES}
    audit = collect_graph_audit(RecordingDriver(values))

    assert isinstance(audit, GraphAudit)
    assert audit.ready_for_simulation is True
    assert audit.ready_for_full_security_simulation is False
    assert audit.readiness_blockers == ()
    assert audit.package_components == 1
    assert audit.retired_assets == 1


def test_graph_audit_reports_missing_simulation_prerequisites() -> None:
    values = {metric: 1 for metric in AUDIT_QUERIES}
    values["asset_communications"] = 0
    values["resolved_services"] = 0

    audit = collect_graph_audit(RecordingDriver(values))

    assert audit.ready_for_simulation is False
    assert audit.readiness_blockers == (
        "no asset communication edges",
        "no services mapped to verified CPEs",
    )


def test_graph_audit_requires_a_result_for_each_metric() -> None:
    class EmptyDriver:
        def execute_query(self, query: str, **parameters: Any) -> Any:
            return type("Result", (), {"records": []})()

    with pytest.raises(RuntimeError, match="Audit query returned no value"):
        collect_graph_audit(EmptyDriver())
