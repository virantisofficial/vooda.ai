# SPDX-FileCopyrightText: 2026 Virantis
# SPDX-License-Identifier: LicenseRef-Vooda-Community-1.0

from __future__ import annotations
"""Social media and consumer platform detectors."""

from services.secret_scan.detectors.base import SecretRule

RULES: list[SecretRule] = [
    SecretRule(rule_id="VOODA-SEC-TWITTER-001", title="Twitter/X API Key", secret_type="twitter_api_key", severity="high",
        pattern=r'(?:twitter[_-]?(?:api[_-]?)?(?:key|secret)|TWITTER_(?:API_)?(?:KEY|SECRET))\s*[=:]\s*["\']?([A-Za-z0-9]{25,})["\']?',
        keywords=["twitter", "TWITTER"], confidence=0.75, description="Twitter/X API key or secret.", fix_hint="Regenerate at developer.twitter.com → Projects & Apps."),
    SecretRule(rule_id="VOODA-SEC-TWITTER-002", title="Twitter/X Bearer Token", secret_type="twitter_bearer", severity="high",
        pattern=r'(?:twitter[_-]?bearer|TWITTER_BEARER)\s*[=:]\s*["\']?(AAAAAAAAAAAAAAAAAAA[A-Za-z0-9%]+)["\']?',
        keywords=["AAAAAAAAAAAAAAAAAAA", "twitter_bearer", "TWITTER_BEARER"], confidence=0.90, description="Twitter/X OAuth 2.0 bearer token.", fix_hint="Regenerate at developer.twitter.com."),
    SecretRule(rule_id="VOODA-SEC-FB-001", title="Facebook App Secret", secret_type="facebook_app_secret", severity="high",
        pattern=r'(?:facebook[_-]?(?:app[_-]?)?secret|FB_(?:APP_)?SECRET|FACEBOOK_SECRET)\s*[=:]\s*["\']?([a-f0-9]{32})["\']?',
        keywords=["facebook", "FACEBOOK", "FB_SECRET", "FB_APP"], confidence=0.80, description="Facebook/Meta app secret.", fix_hint="Reset at developers.facebook.com → App Settings → Basic."),
    SecretRule(rule_id="VOODA-SEC-FB-002", title="Facebook Access Token", secret_type="facebook_access_token", severity="high",
        pattern=r'(?:^|[^A-Za-z0-9])(EAA[A-Za-z0-9]{100,})(?:[^A-Za-z0-9]|$)',
        keywords=["EAA"], confidence=0.85, description="Facebook/Meta Graph API access token.", fix_hint="Token will expire. Revoke at Facebook Business Settings → System Users."),
    SecretRule(rule_id="VOODA-SEC-INSTA-001", title="Instagram Access Token", secret_type="instagram_token", severity="high",
        pattern=r'(?:instagram[_-]?(?:access[_-]?)?token|INSTAGRAM_TOKEN)\s*[=:]\s*["\']?(IGQV[A-Za-z0-9\-_]{50,})["\']?',
        keywords=["IGQV", "instagram", "INSTAGRAM"], confidence=0.85, description="Instagram Graph API access token.", fix_hint="Regenerate via Facebook Developer portal."),
    SecretRule(rule_id="VOODA-SEC-LINKEDIN-001", title="LinkedIn Client Secret", secret_type="linkedin_secret", severity="high",
        pattern=r'(?:linkedin[_-]?(?:client[_-]?)?secret|LINKEDIN_SECRET)\s*[=:]\s*["\']?([A-Za-z0-9]{16})["\']?',
        keywords=["linkedin", "LINKEDIN"], confidence=0.75, description="LinkedIn OAuth client secret.", fix_hint="Regenerate at LinkedIn Developer Portal → App credentials."),
    SecretRule(rule_id="VOODA-SEC-SPOTIFY-001", title="Spotify Client Secret", secret_type="spotify_secret", severity="medium",
        pattern=r'(?:spotify[_-]?(?:client[_-]?)?secret|SPOTIFY_(?:CLIENT_)?SECRET)\s*[=:]\s*["\']?([a-f0-9]{32})["\']?',
        keywords=["spotify", "SPOTIFY"], confidence=0.75, description="Spotify OAuth client secret.", fix_hint="Regenerate at developer.spotify.com → Dashboard."),
    SecretRule(rule_id="VOODA-SEC-TWITCH-001", title="Twitch Client Secret", secret_type="twitch_secret", severity="medium",
        pattern=r'(?:twitch[_-]?(?:client[_-]?)?secret|TWITCH_(?:CLIENT_)?SECRET)\s*[=:]\s*["\']?([a-z0-9]{30})["\']?',
        keywords=["twitch", "TWITCH"], confidence=0.75, description="Twitch API client secret.", fix_hint="Regenerate at dev.twitch.tv → Console → Applications."),
    SecretRule(rule_id="VOODA-SEC-REDDIT-001", title="Reddit Client Secret", secret_type="reddit_secret", severity="medium",
        pattern=r'(?:reddit[_-]?(?:client[_-]?)?secret|REDDIT_SECRET)\s*[=:]\s*["\']?([A-Za-z0-9\-_]{27})["\']?',
        keywords=["reddit", "REDDIT"], confidence=0.75, description="Reddit API OAuth secret.", fix_hint="Regenerate at reddit.com/prefs/apps."),
    SecretRule(rule_id="VOODA-SEC-TIKTOK-001", title="TikTok App Secret", secret_type="tiktok_secret", severity="medium",
        pattern=r'(?:tiktok[_-]?(?:app[_-]?)?secret|TIKTOK_SECRET)\s*[=:]\s*["\']?([a-f0-9]{32,})["\']?',
        keywords=["tiktok", "TIKTOK"], confidence=0.75, description="TikTok for Developers app secret.", fix_hint="Regenerate at developers.tiktok.com."),
    SecretRule(rule_id="VOODA-SEC-PINTEREST-001", title="Pinterest App Secret", secret_type="pinterest_secret", severity="medium",
        pattern=r'(?:pinterest[_-]?(?:app[_-]?)?secret|PINTEREST_SECRET)\s*[=:]\s*["\']?([a-f0-9]{32,})["\']?',
        keywords=["pinterest", "PINTEREST"], confidence=0.75, description="Pinterest API app secret.", fix_hint="Regenerate at developers.pinterest.com."),
]
