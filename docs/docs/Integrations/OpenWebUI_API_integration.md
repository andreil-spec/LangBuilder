# OpenWebUI API Integration

This guide explains how to expose LangBuilder flows through the built-in OpenAI-compatible shim so they can be used directly inside [Open WebUI](https://github.com/open-webui/open-webui).

## Prerequisites

- LangBuilder running locally (for example `make backend` or `langbuilder run`)
- Open WebUI `v0.6.34` or newer
- One of:
  - LangBuilder API key (legacy mode), or
  - Keycloak/OpenID Connect configured for LangBuilder + Open WebUI (preferred)

## 1. Start LangBuilder

```bash
make init     # one-time dependency install
make backend  # FastAPI + shim on http://127.0.0.1:7860
```

Optionally run the Vite dev UI in another terminal with `make frontend`.

## 2. Prepare a flow

1. Open the LangBuilder UI.
2. Create or open the flow you want to expose.
3. Choose **Share ▾ → API access** and set an **Endpoint Name** (for example `support-bot`). The shim will expose it as `lb:<endpoint-name>`.
4. (Optional) If other users will call it with their own API keys, set the flow access to **PUBLIC** in **Share ▾ → Flow settings**.

Verify the shim by listing models:

```bash
curl -H "Authorization: Bearer <LANGBUILDER_API_KEY>" \
     http://127.0.0.1:7860/v1/models
```

Your flow should appear as `lb:<endpoint-name>` (or `lb:<flow-id>` if no endpoint name is defined).

## 2.1. Enable Keycloak SSO (OIDC) *(optional, recommended)*

LangBuilder can now validate the Open WebUI session token directly, so you do not need to distribute API keys. Configure the following environment variables for the LangBuilder backend:

| Variable | Description |
| --- | --- |
| `LANGBUILDER_OIDC_ENABLED=true` | Turn on OIDC validation. |
| `LANGBUILDER_OIDC_ISSUER=https://<keycloak-host>/realms/<realm>` | Keycloak realm issuer URL. |
| `LANGBUILDER_OIDC_AUDIENCE=langbuilder-api` | Client ID/Audience expected in the access token. |
| `LANGBUILDER_OIDC_ADDITIONAL_AUDIENCES=openwebui` | (Optional) Accept additional audiences, comma separated. |
| `LANGBUILDER_OIDC_RESOURCE_CLIENT_IDS=langbuilder-api` | (Optional) Collect client-specific roles for RBAC. |
| `LANGBUILDER_OIDC_RBAC_TAG_PREFIX=group:` | (Optional) Prefix used when tagging flows with required groups. |

Keycloak already forwards Open WebUI’s access token to LangBuilder. When OIDC is enabled:

- Requests **without** a bearer token receive **401 Unauthorized**.
- Requests with a valid token are accepted; roles/groups from the token enforce RBAC.

To restrict a flow to a group, add a tag with the configured prefix. With the default prefix, adding the tag `group:builder` makes that flow visible only to users whose token lists the `builder` group or role.

## 3. Run Open WebUI against LangBuilder

```bash
docker run -d --name openwebui \
  -p 8000:8080 \
  -v open-webui:/app/backend/data \
  -e WEBUI_AUTH=False \
  -e OPENAI_API_BASE_URL="http://<langbuilder-host>:7860/v1" \
  -e OPENAI_API_KEY="<LANGBUILDER_API_KEY>" \
  -e WEBUI_URL="http://localhost:8000" \
  --restart always \
  ghcr.io/open-webui/open-webui:v0.6.34
```

Replace `<langbuilder-host>` with:

- `host.docker.internal` on macOS or Windows (Docker Desktop).
- The LAN IP of your LangBuilder machine on Linux (for example `192.168.x.x`). You can discover it with `hostname -I`.

After the container starts:

1. Open `http://localhost:8000`.
2. Go to **Admin Settings → Connections → OpenAI** and verify the connection using the same base URL and API key.
3. Models returned by `/v1/models` appear automatically and are prefixed with `lb:`. Select the desired `lb:` entry in the chat sidebar and start chatting—LangBuilder will run the corresponding flow.

## Troubleshooting

- **401 Unauthorized** – Provide either a valid LangBuilder API key or an OIDC bearer token. When OIDC is enabled, the token must match the configured issuer/audience.
- **No models listed** – Confirm the flow has an endpoint name and the `curl /v1/models` check returns it.
- **Model missing for a specific user** – Verify the flow tags include the appropriate group prefix (`group:<name>`) and that the user’s Keycloak token contains that group or role.
- **Empty responses** – The shim responds with non-streaming completions but gracefully ignores `stream=true`; refresh LangBuilder to ensure you have the latest build.
- **Docker networking** – Use the appropriate host when setting `OPENAI_API_BASE_URL`; Linux containers cannot resolve `host.docker.internal`.

Once configured, any new flow with an endpoint name automatically appears as a selectable model in Open WebUI. Remove or rename flows in LangBuilder to control availability.
