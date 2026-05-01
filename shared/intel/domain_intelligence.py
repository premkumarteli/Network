from __future__ import annotations

SERVICE_MAPPINGS = {
    "youtube.com": ("YouTube", "streaming"),
    "googlevideo.com": ("YouTube Video", "streaming"),
    "netflix.com": ("Netflix", "streaming"),
    "twitch.tv": ("Twitch", "streaming"),
    "vimeo.com": ("Vimeo", "streaming"),
    "facebook.com": ("Facebook", "social"),
    "instagram.com": ("Instagram", "social"),
    "whatsapp.com": ("WhatsApp", "chat"),
    "x.com": ("X (Twitter)", "social"),
    "twitter.com": ("X (Twitter)", "social"),
    "linkedin.com": ("LinkedIn", "social"),
    "discord.com": ("Discord", "chat"),
    "web.whatsapp.com": ("WhatsApp Web", "chat"),
    "openai.com": ("OpenAI / ChatGPT", "ai"),
    "chatgpt.com": ("ChatGPT", "ai"),
    "anthropic.com": ("Claude AI", "ai"),
    "claude.ai": ("Claude AI", "ai"),
    "gemini.google.com": ("Google Gemini", "ai"),
    "copilot.microsoft.com": ("Microsoft Copilot", "ai"),
    "perplexity.ai": ("Perplexity AI", "ai"),
    "github.com": ("GitHub", "dev"),
    "githubusercontent.com": ("GitHub Assets", "dev"),
    "stackoverflow.com": ("Stack Overflow", "dev"),
    "gitlab.com": ("GitLab", "dev"),
    "npmjs.com": ("NPM", "dev"),
    "google.com": ("Google Search", "search"),
    "bing.com": ("Bing Search", "search"),
    "duckduckgo.com": ("DuckDuckGo", "search"),
    "search.brave.com": ("Brave Search", "search"),
    "events.data.microsoft.com": ("Windows Telemetry", "system"),
    "activity.windows.com": ("Windows Activity", "system"),
    "googleapis.com": ("Google APIs", "system"),
    "azure.com": ("Azure Services", "system"),
    "applicationinsights.azure.com": ("App Insights", "system"),
    "cloudapp.azure.com": ("Azure CloudApp", "system"),
    "azureedge.net": ("Azure Edge", "system"),
    "windows.net": ("Microsoft Azure", "system"),
    "gvt2.com": ("Google Services", "system"),
    "vscode-cdn.net": ("Visual Studio Code", "dev"),
    "grammarly.com": ("Grammarly", "productivity"),
    "grammarly.io": ("Grammarly", "productivity"),
    "sentry.io": ("Sentry", "dev"),
    "akamaized.net": ("Akamai", "cdn"),
    "cloudfront.net": ("Amazon CloudFront", "cdn"),
    "img-s-msn-com.akamaized.net": ("MSN", "news"),
    "c.pki.goog": ("Google PKI", "system"),
    "crl3.digicert.com": ("DigiCert CRL", "security"),
    "lencr.org": ("Let's Encrypt", "security"),
}

NOISE_DOMAINS = [
    "events.data.microsoft.com",
    "activity.windows.com",
    "firebaselogging-pa.googleapis.com",
    "lencr.org",
    "digicert.com",
    "in-addr.arpa",
]

SENSITIVE_DOMAINS = [
    "paypal.com",
    "stripe.com",
    "squareup.com",
    "shopify.com",
    "wellsfargo.com",
    "chase.com",
    "bankofamerica.com",
    "citibank.com",
    "capitalone.com",
    "usbank.com",
    "discover.com",
    "appleid.apple.com",
    "id.apple.com",
    "account.apple.com",
    "accounts.google.com",
    "mail.google.com",
    "drive.google.com",
    "calendar.google.com",
    "login.microsoftonline.com",
    "account.microsoft.com",
    "login.live.com",
    "auth0.com",
    "okta.com",
    "onelogin.com",
    "pingidentity.com",
    "duo.com",
]


def is_noise(domain: str) -> bool:
    if not domain:
        return True
    return any(noise in domain for noise in NOISE_DOMAINS)


def is_sensitive_destination(domain: str) -> bool:
    if not domain:
        return False

    normalized = domain.lower().strip()
    for marker in SENSITIVE_DOMAINS:
        marker = marker.lower().strip()
        if not marker:
            continue
        if normalized == marker or normalized.endswith(f".{marker}"):
            return True
    return False


def get_service_info(domain: str) -> tuple[str, str]:
    if not domain:
        return "Unknown Website", "web"

    normalized = str(domain).strip().lower().rstrip(".")
    if not normalized:
        return "Unknown Website", "web"

    for known_domain, (name, category) in sorted(
        SERVICE_MAPPINGS.items(),
        key=lambda item: (-len(item[0]), item[0]),
    ):
        if normalized == known_domain or normalized.endswith(f".{known_domain}"):
            return name, category

    return normalized, "web"


def classify_domain(domain: str) -> str:
    _, category = get_service_info(domain)
    return category
