# 12 — VPN/Proxy Source Flagging

## Trigger Signal

The agent cross-references source IPs of incoming traffic against databases of known VPN providers, commercial proxy services, Tor exit nodes, and residential proxy networks. When traffic from these sources targets sensitive endpoints (admin panels, APIs, login pages), it flags the activity.

## Predictive Angle

Legitimate users rarely access admin panels or internal APIs through commercial VPN providers. Traffic from these sources — especially to sensitive endpoints — is a strong signal for credential stuffing, account takeover attempts, scraping, or reconnaissance. The agent acts on the *source reputation* before any malicious payload is observed.

## Agent Response

The agent opens a PR with one of several graduated responses depending on the endpoint sensitivity and traffic pattern:

1. **Log + tag** — for general traffic, add a header/tag for downstream analysis
2. **Rate limit** — for login endpoints, throttle VPN-sourced requests
3. **Block** — for admin panels or internal APIs, drop VPN-sourced traffic entirely
4. **Challenge** — require CAPTCHA or step-up auth for VPN-sourced sessions

## Files

- `vpn_checker.py` — sketch: check source IPs against VPN/proxy databases
- `vpn-providers.yaml` — example list of known VPN/proxy CIDR ranges and data sources
- `template-block-vpn.nft` — nftables block template for VPN sources hitting sensitive endpoints
- `template-rate-limit-vpn.yaml` — rate-limit template for VPN sources on login endpoints
- `endpoint-sensitivity.yaml` — endpoint classification (which endpoints trigger which response level)

## Example PR the Agent Would Open

> **Title:** `predict: block VPN-sourced traffic to /admin — 47 requests from NordVPN/ExpressVPN ranges`
>
> **Body:** Over the last 2 hours, 47 requests to `/admin` and `/admin/api/*` originated from IPs belonging to known VPN providers:
>
> | Provider | IPs | Requests | Endpoints |
> |---|---|---|---|
> | NordVPN | 5 | 28 | /admin, /admin/api/users |
> | ExpressVPN | 3 | 14 | /admin/api/config |
> | Tor exit | 2 | 5 | /admin |
>
> No legitimate admin users are expected to connect via commercial VPN. Proposing a block rule for VPN-sourced traffic to `/admin*` endpoints. Login endpoints (`/auth/*`) are being rate-limited rather than blocked.
