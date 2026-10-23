# Copyright 2026 Provance
# SPDX-License-Identifier: Apache-2.0
"""provance-verify: check Provance evidence bundles offline (A-079).

Depends on ``cryptography`` and the standard library only, and trusts only
what you give it: the key set you downloaded from Provance and the
timestamp authority's certificate.
"""

__version__ = "1.0.0b1"

from provance_verify.bundle import Report, verify_bundle  # noqa: E402
from provance_verify.seal import verify_seal  # noqa: E402

__all__ = ["Report", "__version__", "verify_bundle", "verify_seal"]
