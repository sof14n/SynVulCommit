from __future__ import annotations


COMPACT_PROFILE = "compact"
WINDOW_BALANCED_PROFILE = "window_balanced"
GENERATION_PROFILES = (COMPACT_PROFILE, WINDOW_BALANCED_PROFILE)

WINDOW_BALANCED_MIN_TOKENS = 420
WINDOW_BALANCED_MAX_TOKENS = 900
WINDOW_BALANCED_MAX_BADPART_RATIO = 0.15
WINDOW_BALANCED_MIN_FIXED_TOKEN_RETENTION = 0.75


def normalize_generation_profile(value: str | None) -> str:
    profile = (value or COMPACT_PROFILE).strip().lower()
    if profile not in GENERATION_PROFILES:
        raise ValueError(f"unknown generation profile: {value}")
    return profile


def is_window_balanced(profile: str | None) -> bool:
    return normalize_generation_profile(profile) == WINDOW_BALANCED_PROFILE
