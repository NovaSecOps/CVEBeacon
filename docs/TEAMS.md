# Teams bot alerts

`teams_bot` is an optional watch channel for direct messages and existing team
conversations. The existing `teams` Workflow webhook channel keeps its current
configuration and payload. Existing installations need no bot registration.

## Protocol choice

The implementation uses Azure Bot Service registration and the Bot Connector
REST API, without an additional SDK. Microsoft documents direct HTTPS token
acquisition and Connector calls in its
[authentication guide](https://learn.microsoft.com/en-us/azure/bot-service/rest-api/bot-framework-rest-connector-authentication?view=azure-bot-service-4.0).
Ordinary Graph chat sending does not provide a general app-only notification
path: its application permission is `Teamwork.Migrate.All`. See
[Graph chat send permissions](https://learn.microsoft.com/en-us/graph/api/chat-post-messages?view=graph-rest-1.0).

## Register and install

1. Create a **single-tenant Azure Bot** resource and its Microsoft Entra app
   registration. Record the directory (tenant) UUID and application UUID. New
   multitenant bot registrations are deprecated. See Microsoft's
   [Azure Bot registration steps](https://learn.microsoft.com/en-us/azure/bot-service/bot-service-quickstart-registration?view=azure-bot-service-4.0).
2. Enable the **Microsoft Teams** channel on the Azure Bot resource. Create an
   app client secret, copy its **value**, and store it in an owner-only file
   readable by the CVEBeacon service account, for example
   `/opt/cvebeacon/secrets/teams-bot-secret` with mode `0600`. Set a rotation
   reminder before expiry. This implementation uses a client secret; certificate
   assertions and managed identities are not implemented.
3. Copy [the manifest template](../deploy/teams/manifest.template.json) to an
   untracked `manifest.json`. Replace `{{TEAMS_APP_ID}}` with a Teams application
   UUID and `{{BOT_APP_ID}}` with the Azure application UUID. Replace the example
   developer URLs. Supply `color.png` (192×192) and `outline.png` (32×32), and zip
   those two files with `manifest.json` at the archive root. Validate the package
   in Teams Developer Portal. The template declares personal and team scopes
   and notification-only behavior. See the
   [Teams manifest schema](https://learn.microsoft.com/en-us/microsoftteams/platform/resources/schema/manifest-schema).
4. Upload the package to the organization app catalog, allow it under the
   applicable Teams app policy, and install it in **personal scope for every
   recipient**. Manual installation or an administrator's app setup policy is
   sufficient. A direct message addressed by an Entra object ID requires a
   personal installation. For a team conversation, install the app in that team.
   See [proactive messaging prerequisites](https://learn.microsoft.com/en-us/microsoftteams/platform/bots/how-to/conversations/send-proactive-messages).

CVEBeacon is an outbound sender. It does not expose an inbound bot messaging
endpoint or handle install activities, user replies, or card actions. If an
existing bot host receives activities, use its authenticated conversation
references. Leave the Azure Bot messaging endpoint blank if the portal permits,
or use a placeholder such as `https://example.com/api/messages` for this outbound-only
configuration. Receiving activities requires a separate bot host. Do not point Azure Bot's messaging endpoint at the dashboard.

For optional administrator-managed installation through Graph, use
`POST /users/{user-id}/teamwork/installedApps` with
`teamsApp@odata.bind` pointing to the **catalog-generated Teams app ID**. This
catalog ID is the Graph `teamsApp.id`; the developer's manifest ID is
`teamsApp.externalId` for an organization catalog app. Store-distributed apps
can use the manifest ID as their catalog ID. Neither is the Azure bot app ID.
See [Teams app identifiers](https://learn.microsoft.com/en-us/graph/api/resources/teamsapp?view=graph-rest-1.0).
The least application permission for installing the app itself is
`TeamsAppInstallation.ReadWriteSelfForUser.All`, with administrator consent and
the app identity linked in `webApplicationInfo`. That optional installation
flow requires adding `webApplicationInfo` to the manifest with the Azure app ID
and the app registration's exposed resource URI; the notification-only template
omits it because ordinary manual installation needs no SSO. Installation is a separate
administrative step; CVEBeacon never installs applications automatically. See
[Graph app installation](https://learn.microsoft.com/en-us/graph/api/userteamwork-post-installedapps?view=graph-rest-1.0).

## Configure recipients

```toml
[watch.channels.teams-direct]
type = "teams_bot"
tenant_id = "11111111-1111-4111-8111-111111111111"
app_id = "22222222-2222-4222-8222-222222222222"
client_secret_file = "/opt/cvebeacon/secrets/teams-bot-secret"
recipients = ["33333333-3333-4333-8333-333333333333", "alerts@example.com"]
format = "adaptive_card"
# Optional trusted Connector endpoint; otherwise the public Teams endpoint:
# service_url = "https://smba.trafficmanager.net/teams/"
```

Add `teams-direct` to the intended watch rule's `channels` array. All other
watch channel controls, including `enabled`, `grouping`, `max_items`,
`timeout_seconds`, language, pacing and reported notices, apply. The only
supported bot format is `adaptive_card`. Secrets cannot be inline or named by
an environment variable for this channel.

The interactive setup also offers `teams_bot` after the existing channel choices.
It asks for the registered tenant, app and recipients, then writes the secret
through the protected file mechanism. Complete registration and installation
before choosing to send a setup test.

Use Entra object UUIDs when possible: Connector delivery requires no Graph
directory permissions for those recipients. A user principal name such as
`alerts@example.com` is resolved with `GET /users/{UPN}?$select=id` using a
separate Graph access token. That lookup requires the app's Graph application
permission `User.Read.All` and administrator consent. Object IDs and UPNs must both belong to the
configured tenant; cross-tenant recipients are unsupported. See [Get user permissions](https://learn.microsoft.com/en-us/graph/api/user-get?view=graph-rest-1.0).

To send to an existing personal or team conversation, add references instead
of, or alongside, `recipients`:

```toml
conversation_references = [
  { conversation_id = "conversation-id", service_url = "https://smba.trafficmanager.net/teams/" }
]
```

Obtain the conversation ID and service URL from an authenticated activity or
trusted bot host for this bot and tenant. A reference's URL defaults to the
channel's `service_url`. A Teams channel URL from the client is not a Connector
conversation reference. Existing channel references can represent a channel or
thread; this sender does not discover teams, create channels, or create threads.
See [conversation addressing](https://learn.microsoft.com/en-us/microsoftteams/platform/bots/how-to/conversations/send-proactive-messages).
There must be 1–100 total destinations. Avoid listing the same person both by
UPN and object ID or by an additional conversation reference.

Service URLs must use HTTPS on the explicit public-cloud origin allowlist:
`smba.trafficmanager.net`, with the default port or port 443. Foreign hosts,
lookalike suffixes, nonstandard ports and HTTP URLs are refused before token
acquisition, for both channel URLs and conversation references. This matches the
[documented public Teams service URL](https://learn.microsoft.com/en-us/microsoftteams/platform/bots/how-to/conversations/send-proactive-messages).
Regional base paths such as `/amer/`, `/emea/` and `/apac/` are preserved on
that origin. Redirects are refused, and response-provided URLs are ignored.
This release targets the public Microsoft cloud and single-tenant authority;
changing the service URL alone does not enable sovereign cloud authentication.
`allow_insecure` does not bypass the bot service URL policy. Local acceptance
checks map permitted URLs to disposable loopback endpoints inside their test transport.

## Delivery and testing

Tokens are cached in memory per HTTP client, tenant, app, credential and scope,
with early expiry refresh. DMs are created without a card using
`POST {service_url}/v3/conversations`, then reused from the watch database.
Cards go to `POST {service_url}/v3/conversations/{id}/activities`.

The watch database migrates transactionally to schema 8, adding the Teams bot
storage alongside the provider/search tables in the same upgrade. It stores
conversation references, rendered card batches and per-destination delivery
states; it never stores the client secret or access token. Failed card batches
retain their original content so newly queued events cannot merge into a retry.
Each confirmed destination/part is skipped on retry. A timeout during an
activity send is ambiguous and needs `watch notify --retry-ambiguous`; a token,
lookup or empty conversation-creation timeout is an unsent failure. Crash
recovery preserves ambiguity. An ambiguous multipart batch can require explicit
retry even if only a later part failed. An explicit retry may duplicate an
unconfirmed delivery, as with other watch channels.

HTTP 401/403 use the existing bounded authentication-attempt limit. A 401 also
invalidates the cached tokens. HTTP 429 honors `Retry-After` within the delivery
budget; a longer wait is saved for a later run. Waiting without a request
does not consume the failure budget. Other rejected sends, including
5xx, use the normal failed-delivery backoff. Errors contain safe categories and
status codes, never upstream bodies, tokens or secrets. Per-recipient outcomes
appear as bounded counts and destination/part numbers in notification and test
output, including dashboard test job logs. Raw conversation IDs are omitted.
Completed card copies and destination rows are removed after their events are
confirmed sent; unresolved and ambiguous batches remain durable.

The dashboard's channel editor includes `teams_bot` and its field descriptions.
Editing any credential-bearing row, including changing its recipients, requires
`manage_secrets`. The existing `test_channel` permission controls the channel
test operation. A test sends one labelled card to every configured destination
and reuses stored DM references; running another test sends another card.

```console
cvebeacon --config cvebeacon.toml watch notify test teams-direct
```

Run that command only when real delivery is intended. Development verification
uses offline fake token/Connector responses, plus a loopback acceptance check:

```console
.venv/bin/python tools/test_offline.py -q tests/test_watch_teams_bot.py tests/test_dashboard_teams_bot.py tests/test_setup_teams_bot.py
.venv/bin/python tools/teams_bot_smoke.py
```

## Troubleshooting

| Symptom | Check |
| --- | --- |
| 401 | Tenant/application UUIDs, secret **value** and expiry, Azure Bot identity, and Bot Connector scope. |
| 403 on creation | Personal installation, Teams app policy, recipient tenant, and whether the app was removed or blocked. |
| Graph lookup fails | `User.Read.All` administrator consent and the exact UPN; prefer a known object UUID. |
| 404 or stale reference | The saved reference must belong to this bot and service. Correct an explicit reference; for a stale stored DM, stop notification processes, back up the watch database and remove only that recipient's row from `watch_teams_bot_conversation` before retrying. |
| 429 | Let the saved delay expire; reduce batch size or increase the channel's pacing interval. |
| Ambiguous | Inspect the destination before opting into `--retry-ambiguous`; normal runs preserve it. |
| Secret rejected | Use an owner-only regular file and keep its parent directory private. |

Changing a channel name, bot app, service URL or destination creates a different
delivery identity. Resolve outstanding deliveries before changing those values
to avoid unintentionally replaying them.
