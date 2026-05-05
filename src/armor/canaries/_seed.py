"""Generate a default canary catalogue with deterministic, seeded values.

This module generates fake-but-realistic canaries for testing and as a
default package payload. All values are deterministically generated from
a fixed seed, ensuring reproducibility.

Canary kinds:
- aws: AWS access keys (AKIA + 16 alphanumeric)
- github: GitHub PATs (ghp_ + 36 alphanumeric)
- stripe: Stripe live keys (sk_live_ + 24 alphanumeric)
- url: Canary URLs (.armor-trap.invalid domain, RFC 6761 reserved)
- path: Fake filesystem paths (/etc/armor-canary-*.pem)
- hostname: Fake hostnames (*.canary.armor-trap.invalid)
- email: Fake email addresses (canary-*@armor-trap.invalid)
- wallet: Fake cryptocurrency wallet addresses

All values are obviously fake and safe to commit to git.
"""

import random
import string
from datetime import datetime

from armor.canaries.catalogue import CanaryEntry, Catalogue


def generate_default_catalogue() -> Catalogue:
    """Generate a seeded default catalogue.

    Returns:
        Catalogue with ≥3 entries per kind.
    """
    # Fixed seed for reproducibility. Bumped after the previous seed's values
    # leaked publicly through committed corpus rows / test specs; the leaked
    # values no longer match any active canary in this catalogue.
    random.seed(0xCAFEBABE)

    entries: list[CanaryEntry] = []
    now = datetime.utcnow().isoformat() + "Z"

    # AWS access keys: AKIA + 16 chars [A-Z0-9]
    for i in range(3):
        canary_id = f"aws-key-{i:03d}"
        value = "AKIA" + "".join(random.choice(string.ascii_uppercase + string.digits) for _ in range(16))
        entries.append(
            CanaryEntry(
                canary_id=canary_id,
                kind="credential",
                service="aws",
                value=value,
                marker_rule=r"^AKIA[A-Z0-9]{16}$",
                active=True,
                created_at=now,
            )
        )

    # GitHub PATs: ghp_ + 36 chars [A-Za-z0-9]
    for i in range(3):
        canary_id = f"github-pat-{i:03d}"
        value = "ghp_" + "".join(random.choice(string.ascii_letters + string.digits) for _ in range(36))
        entries.append(
            CanaryEntry(
                canary_id=canary_id,
                kind="credential",
                service="github",
                value=value,
                marker_rule=r"^ghp_[A-Za-z0-9]{36}$",
                active=True,
                created_at=now,
            )
        )

    # Stripe live keys: sk_live_ + 24 chars [A-Za-z0-9]
    for i in range(3):
        canary_id = f"stripe-key-{i:03d}"
        value = "sk_live_" + "".join(random.choice(string.ascii_letters + string.digits) for _ in range(24))
        entries.append(
            CanaryEntry(
                canary_id=canary_id,
                kind="credential",
                service="stripe",
                value=value,
                marker_rule=r"^sk_live_[A-Za-z0-9]{24}$",
                active=True,
                created_at=now,
            )
        )

    # Fake URLs: https://canary.armor-trap.invalid/<id>
    for i in range(3):
        canary_id = f"url-{i:03d}"
        value = f"https://canary.armor-trap.invalid/{canary_id}"
        entries.append(
            CanaryEntry(
                canary_id=canary_id,
                kind="url",
                service="generic",
                value=value,
                marker_rule=r"^https://canary\.armor-trap\.invalid/[a-z0-9\-]+$",
                active=True,
                created_at=now,
            )
        )

    # Fake paths: /etc/armor-canary-<id>.pem
    for i in range(3):
        canary_id = f"path-{i:03d}"
        value = f"/etc/armor-canary-{canary_id}.pem"
        entries.append(
            CanaryEntry(
                canary_id=canary_id,
                kind="path",
                service="generic",
                value=value,
                marker_rule=r"^/etc/armor-canary-[a-z0-9\-]+\.pem$",
                active=True,
                created_at=now,
            )
        )

    # Fake hostnames: <id>.canary.armor-trap.invalid
    for i in range(3):
        canary_id = f"hostname-{i:03d}"
        value = f"{canary_id}.canary.armor-trap.invalid"
        entries.append(
            CanaryEntry(
                canary_id=canary_id,
                kind="hostname",
                service="generic",
                value=value,
                marker_rule=r"^[a-z0-9\-]+\.canary\.armor-trap\.invalid$",
                active=True,
                created_at=now,
            )
        )

    # Fake email addresses: canary-<id>@armor-trap.invalid
    for i in range(3):
        canary_id = f"email-{i:03d}"
        value = f"canary-{canary_id}@armor-trap.invalid"
        entries.append(
            CanaryEntry(
                canary_id=canary_id,
                kind="email",
                service="generic",
                value=value,
                marker_rule=r"^canary-[a-z0-9\-]+@armor-trap\.invalid$",
                active=True,
                created_at=now,
            )
        )

    # Fake wallet addresses: 1ARMORTRAP + 32 hex chars
    for i in range(3):
        canary_id = f"wallet-{i:03d}"
        hex_part = "".join(random.choice(string.hexdigits[:-6]) for _ in range(32))
        value = f"1ARMORTRAP{hex_part}"
        entries.append(
            CanaryEntry(
                canary_id=canary_id,
                kind="wallet",
                service="crypto",
                value=value,
                marker_rule=r"^1ARMORTRAP[0-9a-f]{32}$",
                active=True,
                created_at=now,
            )
        )

    return Catalogue(entries)
