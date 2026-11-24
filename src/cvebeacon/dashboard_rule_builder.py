"""Hooks that let the visual rule builder reuse the text-form pipeline.

The configuration page owns the request flow.  The rule builder fills these
hooks: ``prepare_rules_form`` rewrites posted builder fields into the same
field values the text form posts, and ``match_preview`` answers the read-only
"which recent CVEs match this rule" check.  Until the builder is installed
both hooks are identities, so the text form behaves exactly as before.
"""

from __future__ import annotations


def prepare_rules_form(form, document, current_config, count):
    """Return the posted rule fields unchanged while the builder is absent."""
    return form


def match_preview(form, document, current_config):
    """Return preview data for a read-only rule check, or None to continue."""
    return None
