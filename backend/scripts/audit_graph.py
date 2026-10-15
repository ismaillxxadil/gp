from dataclasses import fields

from notline.graph.audit import GraphAudit, collect_graph_audit
from notline.graph.connection import Neo4jConnection


def main() -> None:
    db = Neo4jConnection()

    try:
        db.verify()
        audit = collect_graph_audit(db.driver)
    finally:
        db.close()

    _print_audit(audit)


def _print_audit(audit: GraphAudit) -> None:
    status = "READY" if audit.ready_for_simulation else "NOT READY"
    print(f"Verified-path simulation readiness: {status}")
    coverage = "COMPLETE" if audit.security_coverage_complete else "PARTIAL"
    print(f"Security coverage: {coverage}")
    full_status = "READY" if audit.ready_for_full_security_simulation else "NOT READY"
    print(f"Full security simulation readiness: {full_status}")

    for field in fields(audit):
        print(f"{field.name}: {getattr(audit, field.name)}")

    if audit.readiness_blockers:
        print("Blockers:")
        for blocker in audit.readiness_blockers:
            print(f"- {blocker}")

    warnings = []
    if audit.unresolved_services:
        warnings.append(f"{audit.unresolved_services} services have unresolved CPEs")
    if audit.unresolved_components:
        warnings.append(
            f"{audit.unresolved_components} components have unresolved CPEs"
        )
    if audit.unscanned_package_components:
        warnings.append(
            f"{audit.unscanned_package_components} npm components lack an OSV scan"
        )
    if audit.osv_scan_errors:
        warnings.append(f"{audit.osv_scan_errors} npm components have OSV scan errors")
    if audit.unresolved_components_without_osv:
        warnings.append(
            f"{audit.unresolved_components_without_osv} components lack both "
            "a verified CPE and an alternative advisory source"
        )

    if warnings:
        print("Warnings:")
        for warning in warnings:
            print(f"- {warning}")


if __name__ == "__main__":
    main()
