
NOISE_DOMAINS = [
    "events.data.microsoft.com",
    "activity.windows.com",
    "firebaselogging-pa.googleapis.com",
    "oauth2.googleapis.com",
    "cloudcode-pa.googleapis.com",
    "applicationinsights.azure.com",
    "play.googleapis.com",
    "update.microsoft.com",
    "ctldl.windowsupdate.com",
    "lencr.org",
    "digicert.com",
    "in-addr.arpa",
    "googleapis.com"
]

IMPORTANT_DOMAINS = [
    "youtube.com",
    "googlevideo.com",
    "ytimg.com",
    "web.whatsapp.com",
    "chatgpt.com",
    "openai.com",
    "github.com",
    "instagram.com",
    "facebook.com"
]

def is_noise(domain: str) -> bool:
    if not domain:
        return True
    return any(noise in domain for noise in NOISE_DOMAINS)

def classify_domain(domain: str) -> str:
    if not domain:
        return "unknown"
    if "youtube" in domain or "googlevideo" in domain:
        return "video"
    if "whatsapp" in domain:
        return "chat"
    if "chatgpt" in domain or "openai" in domain:
        return "ai"
    if "github" in domain:
        return "dev"
    if "microsoft" in domain or "windows" in domain or "azure" in domain:
        return "system"
    return "web"
