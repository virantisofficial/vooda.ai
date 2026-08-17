# SPDX-FileCopyrightText: 2026 Virantis
# SPDX-License-Identifier: LicenseRef-Vooda-Community-1.0

from __future__ import annotations
"""Analytics and monitoring detectors."""

from services.secret_scan.detectors.base import SecretRule

RULES: list[SecretRule] = [
    SecretRule(rule_id="VOODA-SEC-SEGMENT-001", title="Segment Write Key", secret_type="segment_write_key", severity="medium",
        pattern=r'(?:segment[_-]?write[_-]?key|SEGMENT_WRITE_KEY)\s*[=:]\s*["\']?([A-Za-z0-9]{32,})["\']?',
        keywords=["segment_write", "SEGMENT_WRITE"], confidence=0.75, description="Segment analytics write key.", fix_hint="Rotate at Segment → Sources → Settings."),
    SecretRule(rule_id="VOODA-SEC-AMPLITUDE-001", title="Amplitude API Key", secret_type="amplitude_api_key", severity="medium",
        pattern=r'(?:amplitude[_-]?api[_-]?key|AMPLITUDE_API_KEY)\s*[=:]\s*["\']?([a-f0-9]{32})["\']?',
        keywords=["amplitude", "AMPLITUDE"], confidence=0.75, description="Amplitude analytics API key.", fix_hint="Rotate at Amplitude → Settings → Projects → API Keys."),
    SecretRule(rule_id="VOODA-SEC-MIXPANEL-001", title="Mixpanel API Secret", secret_type="mixpanel_secret", severity="medium",
        pattern=r'(?:mixpanel[_-]?(?:api[_-]?)?secret|MIXPANEL_SECRET)\s*[=:]\s*["\']?([a-f0-9]{32})["\']?',
        keywords=["mixpanel", "MIXPANEL"], confidence=0.75, description="Mixpanel API secret.", fix_hint="Rotate at Mixpanel → Settings → Project Settings."),
    SecretRule(rule_id="VOODA-SEC-LD-001", title="LaunchDarkly SDK Key", secret_type="launchdarkly_sdk_key", severity="high",
        pattern=r'(?:^|[^A-Za-z0-9])(sdk-[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12})(?:[^A-Za-z0-9]|$)',
        keywords=["sdk-"], confidence=0.85, description="LaunchDarkly SDK key.", fix_hint="Rotate at LaunchDarkly → Account settings → Environments."),
    SecretRule(rule_id="VOODA-SEC-LD-002", title="LaunchDarkly API Access Token", secret_type="launchdarkly_api_token", severity="high",
        pattern=r'(?:^|[^A-Za-z0-9])(api-[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12})(?:[^A-Za-z0-9]|$)',
        keywords=["api-"], confidence=0.70, description="LaunchDarkly API access token.", fix_hint="Rotate at LaunchDarkly → Account settings → Authorization."),
    SecretRule(rule_id="VOODA-SEC-MAPBOX-003", title="Mapbox Access Token", secret_type="mapbox_token", severity="medium",
        pattern=r'(?:^|[^A-Za-z0-9])(pk\.[A-Za-z0-9]{60,}\.[A-Za-z0-9\-_]{20,})(?:[^A-Za-z0-9]|$)',
        keywords=["pk."], confidence=0.85, description="Mapbox public access token.", fix_hint="Rotate at Mapbox → Account → Access tokens."),
    SecretRule(rule_id="VOODA-SEC-MAPBOX-002", title="Mapbox Secret Token", secret_type="mapbox_secret_token", severity="high",
        pattern=r'(?:^|[^A-Za-z0-9])(sk\.[A-Za-z0-9]{60,}\.[A-Za-z0-9\-_]{20,})(?:[^A-Za-z0-9]|$)',
        keywords=["sk."], confidence=0.80, description="Mapbox secret token.", fix_hint="Rotate at Mapbox → Account → Access tokens."),
]
