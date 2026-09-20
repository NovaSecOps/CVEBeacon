"""Independent Microsoft Teams and Graph mail notification channels."""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Iterable, Mapping, Any
from urllib.parse import quote

from .config import AppConfig
from .errors import ConfigurationError, NotificationError, SourceError
from .http import HttpClient


@dataclass(frozen=True, slots=True)
class AlertItem:
    event_id: int
    asset_id: str
    cve_id: str
    event_type: str
    applicability: str
    cvss_score: float | None
    cisa_kev: bool
    eu_kev: bool


def alert_items(rows: Iterable[Mapping[str, Any]]) -> list[AlertItem]:
    output = []
    for row in rows:
        payload = json.loads(str(row["payload_json"]))
        vuln = payload["vulnerability"]
        output.append(AlertItem(
            int(row["event_id"]), str(row["asset_id"]), str(row["cve_id"]), str(row["event_type"]),
            str(payload["applicability"]), vuln.get("cvss_score"), bool(vuln.get("cisa_kev")), bool(vuln.get("eu_kev")),
        ))
    return output


def render_text(items: Iterable[AlertItem], *, max_items: int = 100) -> str:
    values = list(items)
    lines = [f"CVEBeacon detected {len(values)} material vulnerability change(s)."]
    for item in values[:max_items]:
        priority = []
        if item.cisa_kev: priority.append("CISA KEV")
        if item.eu_kev: priority.append("EU KEV")
        score = f" CVSS {item.cvss_score:g}" if item.cvss_score is not None else ""
        suffix = f" [{', '.join(priority)}]" if priority else ""
        lines.append(f"- {item.asset_id}: {item.cve_id} — {item.event_type}, {item.applicability}{score}{suffix}")
    if len(values) > max_items:
        lines.append(f"- {len(values) - max_items} additional change(s) omitted from this message; use history or export for the complete set.")
    return "\n".join(lines)


class TeamsNotifier:
    def __init__(self, http: HttpClient, webhook_url: str) -> None:
        if not webhook_url.startswith("https://"):
            raise ConfigurationError("Teams webhook URL must use HTTPS")
        self.http = http
        self.webhook_url = webhook_url

    def send(self, items: list[AlertItem]) -> None:
        body = {
            "type": "message",
            "attachments": [{
                "contentType": "application/vnd.microsoft.card.adaptive",
                "content": {
                    "$schema": "http://adaptivecards.io/schemas/adaptive-card.json",
                    "type": "AdaptiveCard", "version": "1.4",
                    "body": [{"type": "TextBlock", "weight": "Bolder", "text": "CVEBeacon alert"},
                             {"type": "TextBlock", "wrap": True, "text": render_text(items, max_items=50)}],
                },
            }],
        }
        try:
            self.http.post_json(self.webhook_url, source="teams", json=body, expected=(200, 202), max_retries=0, decode_json=False)
        except SourceError as exc:
            raise NotificationError(f"Teams channel did not accept the alert: {exc}") from exc


class GraphMailNotifier:
    def __init__(self, http: HttpClient, *, tenant_id: str, client_id: str, client_secret: str, sender: str, recipients: tuple[str, ...]) -> None:
        if not all((tenant_id, client_id, client_secret, sender, recipients)):
            raise ConfigurationError("Graph mail requires tenant, client, secret, sender, and recipients")
        self.http, self.tenant_id, self.client_id, self.client_secret = http, tenant_id, client_id, client_secret
        self.sender, self.recipients = sender, recipients

    def send(self, items: list[AlertItem]) -> None:
        token_url = f"https://login.microsoftonline.com/{quote(self.tenant_id, safe='')}/oauth2/v2.0/token"
        try:
            token = self.http.request_json("POST", token_url, source="graph_token", data={
                "client_id": self.client_id, "client_secret": self.client_secret,
                "scope": "https://graph.microsoft.com/.default", "grant_type": "client_credentials",
            })
            access_token = token.get("access_token") if isinstance(token, dict) else None
            if not access_token:
                raise NotificationError("Graph token response did not contain an access token")
            message = {
                "message": {
                    "subject": f"CVEBeacon: {len(items)} material change(s)",
                    "body": {"contentType": "Text", "content": render_text(items)},
                    "toRecipients": [{"emailAddress": {"address": value}} for value in self.recipients],
                },
                "saveToSentItems": False,
            }
            self.http.post_json(
                f"https://graph.microsoft.com/v1.0/users/{quote(self.sender, safe='')}/sendMail",
                source="graph_mail", headers={"Authorization": f"Bearer {access_token}"},
                json=message, expected=(202,), max_retries=0,
                decode_json=False,
            )
        except SourceError as exc:
            raise NotificationError(f"Graph mail channel did not accept the alert: {exc}") from exc


def configured_channels(config: AppConfig) -> tuple[str, ...]:
    return tuple(name for name, enabled in (("teams", config.teams.enabled), ("email", config.email.enabled)) if enabled)
