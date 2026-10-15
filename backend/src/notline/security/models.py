from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, Field

ConfigurationOperator = Literal["AND", "OR"]


class NvdCpeName(BaseModel):
    """A CPE dictionary entry returned by the NVD API."""

    cpe_name_id: str
    cpe_name: str
    deprecated: bool = False
    title: str | None = None
    created: str | None = None
    last_modified: str | None = None

    @classmethod
    def from_nvd(cls, payload: dict[str, Any]) -> NvdCpeName:
        titles = payload.get("titles", [])
        english_title = next(
            (title.get("title") for title in titles if title.get("lang") == "en"),
            None,
        )
        return cls(
            cpe_name_id=payload["cpeNameId"],
            cpe_name=payload["cpeName"],
            deprecated=payload.get("deprecated", False),
            title=english_title,
            created=payload.get("created"),
            last_modified=payload.get("lastModified"),
        )


class NvdCpeMatchCriterion(BaseModel):
    """A version-range CPE criterion returned by the NVD match API."""

    match_criteria_id: str
    criteria: str
    status: str
    version_start_including: str | None = None
    version_start_excluding: str | None = None
    version_end_including: str | None = None
    version_end_excluding: str | None = None
    matched_cpes: list[NvdCpeName] = Field(default_factory=list)

    @classmethod
    def from_nvd(cls, payload: dict[str, Any]) -> NvdCpeMatchCriterion:
        match_string = payload.get("matchString", payload)
        return cls(
            match_criteria_id=match_string["matchCriteriaId"],
            criteria=match_string["criteria"],
            status=match_string.get("status", "Unknown"),
            version_start_including=match_string.get("versionStartIncluding"),
            version_start_excluding=match_string.get("versionStartExcluding"),
            version_end_including=match_string.get("versionEndIncluding"),
            version_end_excluding=match_string.get("versionEndExcluding"),
            matched_cpes=[
                NvdCpeName(
                    cpe_name_id=match["cpeNameId"],
                    cpe_name=match["cpeName"],
                )
                for match in match_string.get("matches", [])
            ],
        )


class NvdCpeMatch(BaseModel):
    """One CPE applicability rule from an NVD CVE configuration."""

    criteria: str
    match_criteria_id: str | None = None
    vulnerable: bool = False

    version_start_including: str | None = None
    version_start_excluding: str | None = None
    version_end_including: str | None = None
    version_end_excluding: str | None = None

    @classmethod
    def from_nvd(cls, payload: dict[str, Any]) -> NvdCpeMatch:
        return cls(
            criteria=payload["criteria"],
            match_criteria_id=payload.get("matchCriteriaId"),
            vulnerable=payload.get("vulnerable", False),
            version_start_including=payload.get("versionStartIncluding"),
            version_start_excluding=payload.get("versionStartExcluding"),
            version_end_including=payload.get("versionEndIncluding"),
            version_end_excluding=payload.get("versionEndExcluding"),
        )


class NvdConfigurationNode(BaseModel):
    """A configuration node whose boolean structure must be preserved."""

    operator: ConfigurationOperator = "OR"
    negate: bool = False
    matches: list[NvdCpeMatch] = Field(default_factory=list)
    children: list[NvdConfigurationNode] = Field(default_factory=list)

    @classmethod
    def from_nvd(cls, payload: dict[str, Any]) -> NvdConfigurationNode:
        return cls(
            operator=payload.get("operator", "OR"),
            negate=payload.get("negate", False),
            matches=[
                NvdCpeMatch.from_nvd(match) for match in payload.get("cpeMatch", [])
            ],
            children=[cls.from_nvd(child) for child in payload.get("children", [])],
        )


class NvdCveRecord(BaseModel):
    """Normalized CVE metadata needed for later graph enrichment."""

    cve_id: str
    published: str | None = None
    last_modified: str | None = None
    description: str | None = None
    cvss_base_score: float | None = None
    configurations: list[NvdConfigurationNode] = Field(default_factory=list)

    @classmethod
    def from_nvd(cls, payload: dict[str, Any]) -> NvdCveRecord:
        cve = payload.get("cve", payload)
        descriptions = cve.get("descriptions", [])
        english_description = next(
            (
                description.get("value")
                for description in descriptions
                if description.get("lang") == "en"
            ),
            None,
        )

        metrics = cve.get("metrics", {})
        cvss_base_score = None
        for metric_name in (
            "cvssMetricV40",
            "cvssMetricV31",
            "cvssMetricV30",
            "cvssMetricV2",
        ):
            metric_entries = metrics.get(metric_name, [])
            if metric_entries:
                cvss_base_score = metric_entries[0].get("cvssData", {}).get("baseScore")
                break

        return cls(
            cve_id=cve["id"],
            published=cve.get("published"),
            last_modified=cve.get("lastModified"),
            description=english_description,
            cvss_base_score=cvss_base_score,
            configurations=[
                NvdConfigurationNode.from_nvd(configuration_node)
                for configuration in cve.get("configurations", [])
                for configuration_node in configuration.get("nodes", [])
            ],
        )
