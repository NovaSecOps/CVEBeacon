"""Catalog for delivered watch alert, digest, notice and test messages.

The plain-text and HTML renderers both read these entries, so a language is
translated once. CLI output and the stable generic-webhook JSON stay English
by design. Values are named placeholders passed through ``str.format_map``.
"""

from __future__ import annotations

from typing import Mapping

from ..errors import ConfigurationError

DEFAULT_LANGUAGE = "en"
SUPPORTED_LANGUAGES = ("en", "pt-PT")

CATALOGS: dict[str, dict[str, str]] = {
    "en": {
        "unknown": "unknown",
        "unknown_date": "unknown",
        "date_line": "Published {published} · first seen {first_seen}",
        "reported_line": "Reported to clients by {by} at {at}",
        "cvss_score": "CVSS {score} ({provider})",
        "cvss_not_scored": "CVSS not scored",
        "nvd_pending": "NVD pending",
        "epss_field": "EPSS {score}",
        "epss_band_none": "none",
        "kev_field": "KEV: {kev}",
        "kev_value": "CISA {cisa} {eu_name} {eu}",
        "kev_catalog_eu": "EU",
        "exploitation_field": "Exploitation: {value}",
        "exploitation_active": "active",
        "exploitation_poc": "poc",
        "exploitation_none": "none",
        "severity_none": "none",
        "severity_low": "low",
        "severity_medium": "medium",
        "severity_high": "high",
        "severity_critical": "critical",
        "due": "Due {date}",
        "rule_line": "Rule: {rules} · {links}",
        "rule_line_plural": "Rule: {rules} · {links}",
        "rule_label": "Rule",
        "rule_label_plural": "Rules",
        "link_nvd": "NVD",
        "link_cve": "CVE.org",
        "link_euvd": "EUVD",
        "link_kev": "KEV catalog",
        "provider_cna": "CNA: {name}",
        "provider_nvd": "NVD",
        "provider_cisa_adp": "CISA-ADP",
        "provider_euvd": "EUVD",
        "provider_other": "Other",
        "label_match": "[NEW]",
        "label_kev_added": "[KEV ADDED: {catalog}]",
        "label_exploited": "[ACTIVELY EXPLOITED]",
        "label_severity_up": "[SEVERITY UP {previous}->{current}]",
        "label_severity_up_plain": "[SEVERITY UP]",
        "label_epss_up": "[EPSS UP {previous}->{current}]",
        "label_epss_up_plain": "[EPSS UP]",
        "label_nvd_scored": "[NVD SCORED {score}]",
        "label_nvd_scored_plain": "[NVD SCORED]",
        "label_rejected": "[REJECTED]",
        "label_reported": "[REPORTED]",
        "label_unreported": "[UNREPORTED]",
        "label_unknown": "[{kind}]",
        "count_match_one": "{count} new",
        "count_match_other": "{count} new",
        "count_kev_added_one": "{count} KEV added",
        "count_kev_added_other": "{count} KEV added",
        "count_exploitation_active_one": "{count} actively exploited",
        "count_exploitation_active_other": "{count} actively exploited",
        "count_severity_increase_one": "{count} severity up",
        "count_severity_increase_other": "{count} severity up",
        "count_epss_increase_one": "{count} EPSS up",
        "count_epss_increase_other": "{count} EPSS up",
        "count_nvd_score_added_one": "{count} NVD scored",
        "count_nvd_score_added_other": "{count} NVD scored",
        "count_rejected_one": "{count} rejected",
        "count_rejected_other": "{count} rejected",
        "count_events_one": "{count} event(s)",
        "count_events_other": "{count} event(s)",
        "item_match_one": "match",
        "item_match_other": "matches",
        "item_kev_added_one": "KEV added",
        "item_kev_added_other": "KEV added",
        "item_exploitation_active_one": "actively exploited",
        "item_exploitation_active_other": "actively exploited",
        "item_severity_increase_one": "severity up",
        "item_severity_increase_other": "severity up",
        "item_epss_increase_one": "EPSS up",
        "item_epss_increase_other": "EPSS up",
        "item_nvd_score_added_one": "NVD scored",
        "item_nvd_score_added_other": "NVD scored",
        "item_rejected_one": "rejected",
        "item_rejected_other": "rejected",
        "rule_count_other": "{count} rules",
        "cve_word_one": "CVE",
        "cve_word_other": "CVEs",
        "rule_word_one": "rule",
        "rule_word_other": "rules",
        "since_suffix": " since {since}",
        "per_rule_line": "{rule}: {counts}",
        "subject_initial": (
            "CVEBeacon initial summary: {cves} {cve_word} across {rules} "
            "{rule_word}{since}"
        ),
        "subject_initial_one": (
            "CVEBeacon initial summary: {cves} {cve_word} across {rules} "
            "{rule_word}{since}"
        ),
        "subject_run": "CVEBeacon: {counts} ({rules})",
        "subject_event": "CVEBeacon: {label} {cve}",
        "subject_notice": "CVEBeacon: {label} {cve}",
        "notice_reported": (
            "{label} {cve} reported to clients by {by} at {at}"
        ),
        "notice_unreported": "{label} {cve} report withdrawn by {by} at {at}",
        "and_more": "and {count} more. Run `cvebeacon watch events` to list all.",
        "list_all": "Run `cvebeacon watch events` to list all.",
        "list_all_rule": (
            "Run `cvebeacon watch events --rule {rule}` to list all."
        ),
        "test_subject": "CVEBeacon test message",
        "test_message": "CVEBeacon test message — no action needed",
        "html_column_cve": "CVE",
        "html_column_severity": "Severity",
        "html_column_epss": "EPSS",
        "html_column_kev": "KEV",
        "html_column_exploitation": "Exploitation",
        "html_column_published": "Published",
        "html_column_first_seen": "First seen",
    },
    "pt-PT": {
        "unknown": "autor desconhecido",
        "unknown_date": "data desconhecida",
        "date_line": "Publicado: {published} · visto pela primeira vez: {first_seen}",
        "reported_line": "Comunicado aos clientes por {by} em {at}",
        "cvss_score": "CVSS {score} ({provider})",
        "cvss_not_scored": "Sem pontuação CVSS",
        "nvd_pending": "NVD pendente",
        "epss_field": "EPSS {score}",
        "epss_band_none": "nenhuma",
        "kev_field": "KEV: {kev}",
        "kev_value": "CISA {cisa} {eu_name} {eu}",
        "kev_catalog_eu": "UE",
        "exploitation_field": "Exploração: {value}",
        "exploitation_active": "ativa",
        "exploitation_poc": "PoC",
        "exploitation_none": "nenhuma",
        "severity_none": "nenhuma",
        "severity_low": "baixa",
        "severity_medium": "média",
        "severity_high": "alta",
        "severity_critical": "crítica",
        "due": "Prazo: {date}",
        "rule_line": "Regra: {rules} · {links}",
        "rule_line_plural": "Regras: {rules} · {links}",
        "rule_label": "Regra",
        "rule_label_plural": "Regras",
        "link_nvd": "NVD",
        "link_cve": "CVE.org",
        "link_euvd": "EUVD",
        "link_kev": "Catálogo KEV",
        "provider_cna": "CNA: {name}",
        "provider_nvd": "NVD",
        "provider_cisa_adp": "CISA-ADP",
        "provider_euvd": "EUVD",
        "provider_other": "Outro",
        "label_match": "[NOVO]",
        "label_kev_added": "[ADICIONADO AO KEV: {catalog}]",
        "label_exploited": "[EXPLORADA ATIVAMENTE]",
        "label_severity_up": "[GRAVIDADE AUMENTOU {previous}->{current}]",
        "label_severity_up_plain": "[GRAVIDADE AUMENTOU]",
        "label_epss_up": "[EPSS AUMENTOU {previous}->{current}]",
        "label_epss_up_plain": "[EPSS AUMENTOU]",
        "label_nvd_scored": "[PONTUAÇÃO NVD ADICIONADA {score}]",
        "label_nvd_scored_plain": "[PONTUAÇÃO NVD ADICIONADA]",
        "label_rejected": "[REJEITADO]",
        "label_reported": "[COMUNICADO]",
        "label_unreported": "[NÃO COMUNICADO]",
        "label_unknown": "[{kind}]",
        "count_match_one": "{count} novo",
        "count_match_other": "{count} novos",
        "count_kev_added_one": "{count} adicionado ao KEV",
        "count_kev_added_other": "{count} adicionados ao KEV",
        "count_exploitation_active_one": "{count} explorada ativamente",
        "count_exploitation_active_other": "{count} exploradas ativamente",
        "count_severity_increase_one": "{count} aumento de gravidade",
        "count_severity_increase_other": "{count} aumentos de gravidade",
        "count_epss_increase_one": "{count} aumento de EPSS",
        "count_epss_increase_other": "{count} aumentos de EPSS",
        "count_nvd_score_added_one": "{count} pontuação NVD adicionada",
        "count_nvd_score_added_other": "{count} pontuações NVD adicionadas",
        "count_rejected_one": "{count} rejeitado",
        "count_rejected_other": "{count} rejeitados",
        "count_events_one": "{count} evento",
        "count_events_other": "{count} eventos",
        "item_match_one": "correspondência",
        "item_match_other": "correspondências",
        "item_kev_added_one": "adicionado ao KEV",
        "item_kev_added_other": "adicionados ao KEV",
        "item_exploitation_active_one": "explorada ativamente",
        "item_exploitation_active_other": "exploradas ativamente",
        "item_severity_increase_one": "aumento de gravidade",
        "item_severity_increase_other": "aumentos de gravidade",
        "item_epss_increase_one": "aumento de EPSS",
        "item_epss_increase_other": "aumentos de EPSS",
        "item_nvd_score_added_one": "pontuação NVD adicionada",
        "item_nvd_score_added_other": "pontuações NVD adicionadas",
        "item_rejected_one": "rejeitado",
        "item_rejected_other": "rejeitados",
        "rule_count_other": "{count} regras",
        "cve_word_one": "CVE",
        "cve_word_other": "CVEs",
        "rule_word_one": "regra",
        "rule_word_other": "regras",
        "since_suffix": " desde {since}",
        "per_rule_line": "{rule}: {counts}",
        "subject_initial": (
            "Resumo inicial do CVEBeacon: {cves} {cve_word} repartidos por "
            "{rules} {rule_word}{since}"
        ),
        "subject_initial_one": (
            "Resumo inicial do CVEBeacon: {cves} {cve_word} repartido por "
            "{rules} {rule_word}{since}"
        ),
        "subject_run": "CVEBeacon: {counts} ({rules})",
        "subject_event": "CVEBeacon: {label} {cve}",
        "subject_notice": "CVEBeacon: {label} {cve}",
        "notice_reported": (
            "{label} {cve} comunicado aos clientes por {by} em {at}"
        ),
        "notice_unreported": (
            "{label} {cve} comunicação aos clientes retirada por {by} em {at}"
        ),
        "and_more": "e mais {count}. Execute `cvebeacon watch events` para listar todos.",
        "list_all": "Execute `cvebeacon watch events` para listar todos.",
        "list_all_rule": (
            "Execute `cvebeacon watch events --rule {rule}` para listar todos."
        ),
        "test_subject": "Mensagem de teste do CVEBeacon",
        "test_message": "Mensagem de teste do CVEBeacon — nenhuma ação necessária",
        "html_column_cve": "CVE",
        "html_column_severity": "Gravidade",
        "html_column_epss": "EPSS",
        "html_column_kev": "KEV",
        "html_column_exploitation": "Exploração",
        "html_column_published": "Publicado",
        "html_column_first_seen": "Visto pela primeira vez",
    },
}



class _Values(dict):
    """Leave an unknown placeholder visible instead of raising at send time."""

    def __missing__(self, key: str) -> str:
        return "{" + key + "}"


def canonical_language(value: object, *, label: str = "language") -> str:
    """Return the canonical language name, or reject it with the full list."""
    if not isinstance(value, str):
        raise ConfigurationError(
            f"{label} must be one of " + ", ".join(SUPPORTED_LANGUAGES)
        )
    folded = value.strip().casefold()
    for name in SUPPORTED_LANGUAGES:
        if name.casefold() == folded:
            return name
    raise ConfigurationError(
        f"{label} must be one of " + ", ".join(SUPPORTED_LANGUAGES)
    )


def catalog_for(language: str | None = None) -> Mapping[str, str]:
    name = canonical_language(
        DEFAULT_LANGUAGE if language is None else language
    )
    return CATALOGS[name]


def translate(table: Mapping[str, str], key: str, **values: object) -> str:
    """Format one catalog entry with named placeholders."""
    return table[key].format_map(_Values(values))
