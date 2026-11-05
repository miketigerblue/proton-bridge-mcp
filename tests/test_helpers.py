"""Unit tests for the pure helpers in proton_bridge_mcp.

These tests deliberately exercise only the side-effect-free helpers: header
decoding, address parsing, IMAP-quoting, body extraction, and IMAP-search
criteria construction. Anything that touches the network (IMAP, SMTP) or the
keychain is out of scope here -- those need integration coverage with a real
or simulated Bridge.
"""
from __future__ import annotations

import email
import json
import os
import re
import subprocess
import sys
from email.message import EmailMessage
from pathlib import Path

import pytest
from pydantic import ValidationError

import proton_bridge_mcp as pbm


# ----------------------------------------------------------------------------
# _decode_header
# ----------------------------------------------------------------------------
class TestDecodeHeader:
    def test_none_returns_empty_string(self):
        assert pbm._decode_header(None) == ""

    def test_plain_ascii_passes_through(self):
        assert pbm._decode_header("Hello, world") == "Hello, world"

    def test_bytes_decoded_as_utf8(self):
        assert pbm._decode_header("Olá".encode("utf-8")) == "Olá"

    def test_latin1_fallback_on_invalid_utf8(self):
        # Bytes that are not valid UTF-8 should still decode to *some* string
        # rather than raise. The current implementation replaces invalid
        # sequences; the property under test is "no exception, returns str".
        out = pbm._decode_header(b"\xc3\x28")  # invalid utf-8
        assert isinstance(out, str)
        assert out  # non-empty

    def test_rfc2047_qp_encoded_word(self):
        # =?UTF-8?Q?Caf=C3=A9?= → "Café"
        assert pbm._decode_header("=?UTF-8?Q?Caf=C3=A9?=") == "Café"

    def test_rfc2047_base64_encoded_word(self):
        # "Hello" in UTF-8 base64
        assert pbm._decode_header("=?utf-8?B?SGVsbG8=?=") == "Hello"

    def test_mixed_encoded_and_plain(self):
        out = pbm._decode_header("=?UTF-8?Q?Caf=C3=A9?= - lunch")
        assert "Café" in out
        assert "lunch" in out


# ----------------------------------------------------------------------------
# _iso_date
# ----------------------------------------------------------------------------
class TestIsoDate:
    def test_none_returns_none(self):
        assert pbm._iso_date(None) is None

    def test_empty_string_returns_none(self):
        assert pbm._iso_date("") is None

    def test_valid_rfc2822_returns_iso(self):
        out = pbm._iso_date("Mon, 09 Mar 2026 14:30:00 +0000")
        # We don't pin the exact tz offset (depends on the runner) but we
        # require: ISO format, 2026, March, the 9th.
        assert out is not None
        assert "2026-03-09" in out
        assert "T" in out  # ISO 8601 separator

    def test_malformed_returns_input_unchanged_or_none(self):
        # Implementation choice: parsedate_to_datetime may return None for
        # garbage. Whatever happens, the helper must not raise.
        out = pbm._iso_date("not a date at all")
        assert out is None or "not a date" in out


# ----------------------------------------------------------------------------
# _quote (IMAP string quoting)
# ----------------------------------------------------------------------------
class TestQuote:
    def test_simple_string(self):
        assert pbm._quote("hello") == '"hello"'

    def test_escapes_double_quote(self):
        assert pbm._quote('say "hi"') == r'"say \"hi\""'

    def test_escapes_backslash(self):
        assert pbm._quote(r"a\b") == r'"a\\b"'

    def test_escapes_both_backslash_and_quote(self):
        assert pbm._quote(r'a\"b') == r'"a\\\"b"'

    def test_empty_string(self):
        assert pbm._quote("") == '""'


# ----------------------------------------------------------------------------
# _addr_struct
# ----------------------------------------------------------------------------
class TestAddrStruct:
    def test_empty_returns_empty_list(self):
        assert pbm._addr_struct("") == []

    def test_single_bare_address(self):
        out = pbm._addr_struct("alice@example.com")
        assert out == [{"name": "", "email": "alice@example.com"}]

    def test_single_with_display_name(self):
        out = pbm._addr_struct("Alice <alice@example.com>")
        assert out == [{"name": "Alice", "email": "alice@example.com"}]

    def test_multiple_addresses(self):
        out = pbm._addr_struct("Alice <alice@example.com>, bob@example.com")
        assert {"name": "Alice", "email": "alice@example.com"} in out
        assert {"name": "", "email": "bob@example.com"} in out
        assert len(out) == 2

    def test_rfc2047_in_display_name(self):
        out = pbm._addr_struct("=?UTF-8?Q?Caf=C3=A9?= <cafe@example.com>")
        assert out == [{"name": "Café", "email": "cafe@example.com"}]

    def test_drops_entries_without_email(self):
        # Display-only entries with no actual mailbox shouldn't survive.
        out = pbm._addr_struct("undisclosed-recipients:;")
        assert all(e["email"] for e in out)


# ----------------------------------------------------------------------------
# _parse_flags
# ----------------------------------------------------------------------------
class TestParseFlags:
    def test_no_flags_returns_empty(self):
        assert pbm._parse_flags("UID 42 RFC822.SIZE 1234") == []

    def test_seen_flag(self):
        assert pbm._parse_flags(r"FLAGS (\Seen) UID 42") == [r"\Seen"]

    def test_multiple_flags(self):
        assert pbm._parse_flags(r"FLAGS (\Seen \Flagged) UID 42") == [r"\Seen", r"\Flagged"]

    def test_empty_flags(self):
        assert pbm._parse_flags("FLAGS () UID 42") == []


# ----------------------------------------------------------------------------
# _extract_body
# ----------------------------------------------------------------------------
class TestExtractBody:
    def test_plain_only(self):
        msg = EmailMessage()
        msg["From"] = "a@b.com"
        msg["To"] = "c@d.com"
        msg["Subject"] = "test"
        msg.set_content("hello world")
        plain, html, attachments = pbm._extract_body(msg)
        assert "hello world" in plain
        assert html == ""
        assert attachments == []

    def test_html_only(self):
        msg = EmailMessage()
        msg["Subject"] = "test"
        msg.set_content("<p>hi</p>", subtype="html")
        plain, html, attachments = pbm._extract_body(msg)
        assert "<p>hi</p>" in html
        assert plain == ""
        assert attachments == []

    def test_multipart_alternative(self):
        msg = EmailMessage()
        msg["Subject"] = "test"
        msg.set_content("plain version")
        msg.add_alternative("<p>html version</p>", subtype="html")
        plain, html, attachments = pbm._extract_body(msg)
        assert "plain version" in plain
        assert "html version" in html
        assert attachments == []

    def test_attachment_metadata_only_no_payload(self):
        msg = EmailMessage()
        msg["Subject"] = "with attach"
        msg.set_content("see attached")
        msg.add_attachment(b"PDFCONTENT", maintype="application",
                           subtype="pdf", filename="report.pdf")
        plain, html, attachments = pbm._extract_body(msg)
        assert "see attached" in plain
        assert len(attachments) == 1
        attach = attachments[0]
        assert attach["filename"] == "report.pdf"
        assert attach["content_type"] == "application/pdf"
        assert attach["size_bytes"] > 0
        # Critical: attachment payload must NOT leak into the body.
        assert "PDFCONTENT" not in plain
        assert "PDFCONTENT" not in html

    def test_body_truncated_at_max_chars(self):
        big = "x" * (pbm.MAX_BODY_CHARS + 5000)
        msg = EmailMessage()
        msg["Subject"] = "huge"
        msg.set_content(big)
        plain, _, _ = pbm._extract_body(msg)
        assert len(plain) <= pbm.MAX_BODY_CHARS


# ----------------------------------------------------------------------------
# _build_search
# ----------------------------------------------------------------------------
class TestBuildSearch:
    def test_empty_returns_all(self):
        assert pbm._build_search() == ["ALL"]

    def test_single_from_filter(self):
        out = pbm._build_search(from_addr="alice@example.com")
        assert out[0] == "FROM"
        assert "alice@example.com" in out[1]

    def test_subject_filter_is_quoted(self):
        out = pbm._build_search(subject='hello "world"')
        assert "SUBJECT" in out
        # Embedded double-quotes must be escaped in the IMAP-quoted string.
        joined = " ".join(out)
        assert r'\"world\"' in joined

    def test_unseen_flag(self):
        out = pbm._build_search(unseen=True)
        assert "UNSEEN" in out

    def test_seen_flag(self):
        out = pbm._build_search(seen=True)
        assert "SEEN" in out

    def test_flagged_flag(self):
        out = pbm._build_search(flagged=True)
        assert "FLAGGED" in out

    def test_multiple_filters_combined(self):
        out = pbm._build_search(
            from_addr="alice@example.com",
            subject="invoice",
            unseen=True,
        )
        assert "FROM" in out
        assert "SUBJECT" in out
        assert "UNSEEN" in out

    def test_since_iso_date_converted_to_imap_format(self):
        out = pbm._build_search(since="2026-03-09")
        assert "SINCE" in out
        idx = out.index("SINCE")
        # IMAP wants DD-Mon-YYYY (e.g., "09-Mar-2026"); RFC 3501 §6.4.4.
        assert out[idx + 1] == "09-Mar-2026"

    def test_since_iso_datetime_with_z_converted(self):
        out = pbm._build_search(since="2026-03-09T14:30:00Z")
        idx = out.index("SINCE")
        assert out[idx + 1] == "09-Mar-2026"

    def test_not_keyword_emits_three_tokens(self):
        out = pbm._build_search(not_keyword="$Junk")
        assert out == ["NOT", "KEYWORD", "$Junk"]

    def test_keyword_is_sent_as_bare_atom(self):
        # Proton Bridge rejects a quoted keyword: "Invalid character detected
        # in atom". RFC 3501 defines the KEYWORD argument as an atom.
        assert pbm._build_search(keyword="$Label1") == ["KEYWORD", "$Label1"]

    @pytest.mark.parametrize(
        "bad",
        ["a b", 'a"b', "a\\b", "a(b", "a)b", "a{b", "a%b", "a*b", "a]b",
         "a\r\nX1 LOGOUT", "a\x00b", "a\x7fb", "käse"],
    )
    def test_keyword_rejects_non_atom_characters(self, bad):
        with pytest.raises(ValueError):
            pbm._build_search(keyword=bad)
        with pytest.raises(ValueError):
            pbm._build_search(not_keyword=bad)


# ----------------------------------------------------------------------------
# _strip_invisibles (anti-prompt-injection: zero-width / bidi removal)
# ----------------------------------------------------------------------------
class TestStripInvisibles:
    def test_passes_through_normal_text(self):
        assert pbm._strip_invisibles("hello world") == "hello world"

    def test_preserves_ordinary_whitespace(self):
        assert pbm._strip_invisibles("a\tb\nc d") == "a\tb\nc d"

    def test_strips_zero_width_space(self):
        # U+200B between letters is invisible to humans, visible to models.
        assert pbm._strip_invisibles("hel​lo") == "hello"

    def test_strips_zero_width_joiner(self):
        assert pbm._strip_invisibles("a‍z") == "az"

    def test_strips_zero_width_non_joiner(self):
        assert pbm._strip_invisibles("a‌z") == "az"

    def test_strips_bidi_rlo(self):
        # RLO (U+202E) flips text rendering; classic spoofing vector.
        assert pbm._strip_invisibles("admin‮txt.exe") == "admintxt.exe"

    def test_strips_bidi_lro(self):
        assert pbm._strip_invisibles("a‭b") == "ab"

    def test_strips_isolate_chars(self):
        # U+2066-U+2069 are the newer bidi isolate controls.
        assert pbm._strip_invisibles("a⁦b⁩c") == "abc"

    def test_strips_bom_in_middle(self):
        assert pbm._strip_invisibles("a﻿b") == "ab"

    def test_strips_soft_hyphen(self):
        assert pbm._strip_invisibles("co­operate") == "cooperate"

    def test_strips_word_joiner(self):
        assert pbm._strip_invisibles("a⁠b") == "ab"

    def test_strips_line_separator(self):
        assert pbm._strip_invisibles("a b") == "ab"

    def test_empty_input_returns_empty(self):
        assert pbm._strip_invisibles("") == ""

    def test_combined_attack_string(self):
        # Mix of zero-width + bidi + soft hyphen, simulating a steg payload.
        attack = "se​nd­ mo‮ney"
        assert pbm._strip_invisibles(attack) == "send money"


# ----------------------------------------------------------------------------
# _wrap_untrusted (provenance-tagged data delimiters)
# ----------------------------------------------------------------------------
class TestWrapUntrusted:
    def test_includes_preamble_signalling_data_not_instructions(self):
        out = pbm._wrap_untrusted("hi")
        assert "untrusted" in out.lower()
        assert "data" in out.lower()
        assert "instructions" in out.lower()

    def test_open_and_close_tags_share_nonce(self):
        out = pbm._wrap_untrusted("hi")
        m = re.search(r"<UNTRUSTED_EMAIL_BODY_([a-f0-9]+)", out)
        assert m, f"open tag not found in: {out!r}"
        nonce = m.group(1)
        assert len(nonce) >= 4  # secrets.token_hex(3) -> 6 hex chars
        assert f"</UNTRUSTED_EMAIL_BODY_{nonce}>" in out

    def test_nonce_changes_per_call(self):
        # 8 calls; 6-hex-char nonces collide with prob ~1/16M per pair.
        # Failing this test almost certainly means the RNG is broken.
        nonces = set()
        for _ in range(8):
            out = pbm._wrap_untrusted("x")
            m = re.search(r"<UNTRUSTED_EMAIL_BODY_([a-f0-9]+)", out)
            nonces.add(m.group(1))
        assert len(nonces) >= 7

    def test_provenance_attributes_in_open_tag(self):
        out = pbm._wrap_untrusted("hi", source="alice@example.com", subject="invoice")
        assert 'source="alice@example.com"' in out
        assert 'subject="invoice"' in out

    def test_invisibles_stripped_from_provenance_attrs(self):
        # Even attribute values must be sanitised, since they're part of
        # what the model reads.
        out = pbm._wrap_untrusted("hi", subject="in​voice")
        assert 'subject="invoice"' in out

    def test_double_quotes_in_attr_replaced_to_avoid_breaking_tag(self):
        # The wrapper uses double-quoted attrs; an attacker-controlled
        # subject containing " must not be able to close the attr early.
        out = pbm._wrap_untrusted("hi", subject='evil"injected')
        assert 'evil"injected' not in out  # raw " must be replaced
        # ' substitution keeps the value visible without breaking the tag.
        assert "evil'injected" in out

    def test_kind_can_be_overridden(self):
        out = pbm._wrap_untrusted("hi", kind="EMAIL_BODY_HTML")
        assert "<UNTRUSTED_EMAIL_BODY_HTML_" in out
        assert "</UNTRUSTED_EMAIL_BODY_HTML_" in out

    def test_content_passed_through_verbatim(self):
        # The wrapper sanitises *attrs*; the *content* is the caller's
        # responsibility (in practice it has already passed through
        # _strip_invisibles via _decode_header / _extract_body).
        out = pbm._wrap_untrusted("inner content here")
        assert "inner content here" in out

    def test_empty_provenance_attrs_omitted(self):
        # falsy values (None, "") shouldn't appear as empty attrs.
        out = pbm._wrap_untrusted("hi", source="alice@example.com", subject="")
        assert 'source="alice@example.com"' in out
        assert 'subject=""' not in out


# ----------------------------------------------------------------------------
# _parse_authentication_results (RFC 8601 spf/dkim/dmarc extraction)
# ----------------------------------------------------------------------------
class TestParseAuthenticationResults:
    @staticmethod
    def _msg(headers: str) -> "email.message.Message":
        return email.message_from_string(headers + "\nSubject: hi\n\nbody\n")

    def test_no_header_returns_empty(self):
        assert pbm._parse_authentication_results(self._msg("")) == {}

    def test_all_pass(self):
        m = self._msg(
            "Authentication-Results: mx.proton.me; "
            "spf=pass smtp.mailfrom=alice@example.com; "
            "dkim=pass header.d=example.com header.s=sel1; "
            "dmarc=pass action=none header.from=example.com"
        )
        assert pbm._parse_authentication_results(m) == {
            "spf": "pass", "dkim": "pass", "dmarc": "pass",
        }

    def test_mixed_pass_and_fail(self):
        m = self._msg(
            "Authentication-Results: mx.proton.me; spf=fail; dkim=pass; dmarc=fail"
        )
        assert pbm._parse_authentication_results(m) == {
            "spf": "fail", "dkim": "pass", "dmarc": "fail",
        }

    def test_uppercase_normalised_to_lowercase(self):
        m = self._msg("Authentication-Results: mx.proton.me; SPF=PASS; DKIM=Fail")
        assert pbm._parse_authentication_results(m) == {"spf": "pass", "dkim": "fail"}

    def test_only_some_methods_present(self):
        m = self._msg("Authentication-Results: mx.proton.me; spf=pass")
        assert pbm._parse_authentication_results(m) == {"spf": "pass"}

    def test_first_header_wins_per_method(self):
        # Multiple A-R headers from different MTAs. The closer one (added by
        # our own MX, conventionally topmost) takes precedence.
        m = self._msg(
            "Authentication-Results: mx.proton.me; spf=pass; dkim=pass\n"
            "Authentication-Results: relay.upstream.example; spf=fail; dkim=fail"
        )
        out = pbm._parse_authentication_results(m)
        assert out["spf"] == "pass"
        assert out["dkim"] == "pass"

    def test_garbage_header_returns_empty(self):
        m = self._msg("Authentication-Results: not a structured header value")
        assert pbm._parse_authentication_results(m) == {}

    def test_dmarc_none_passes_through(self):
        # `dmarc=none` is a real value (no DMARC policy published);
        # not the same as the header being missing.
        m = self._msg("Authentication-Results: mx.proton.me; dmarc=none")
        assert pbm._parse_authentication_results(m) == {"dmarc": "none"}

    def test_softfail_and_temperror_preserved(self):
        m = self._msg(
            "Authentication-Results: mx.proton.me; "
            "spf=softfail; dkim=temperror; dmarc=permerror"
        )
        assert pbm._parse_authentication_results(m) == {
            "spf": "softfail", "dkim": "temperror", "dmarc": "permerror",
        }


# ----------------------------------------------------------------------------
# Integration: invisibles get stripped through the public helpers
# ----------------------------------------------------------------------------
class TestSanitisationIntegration:
    def test_decode_header_strips_zero_width(self):
        # An attacker-controlled subject with embedded ZWSP should arrive at
        # the LLM cleanly, not with the steg payload intact.
        assert pbm._decode_header("Pa​yPal alert") == "PayPal alert"

    def test_decode_header_strips_bidi_override(self):
        assert pbm._decode_header("admin‮txt.exe") == "admintxt.exe"

    def test_extract_body_strips_invisibles_in_plain_text(self):
        msg = EmailMessage()
        msg["Subject"] = "test"
        msg.set_content("se​nd mo‮ney")
        plain, _, _ = pbm._extract_body(msg)
        assert "send money" in plain
        assert "​" not in plain
        assert "‮" not in plain

    def test_extract_body_strips_invisibles_in_html(self):
        msg = EmailMessage()
        msg["Subject"] = "test"
        msg.set_content("<p>se​nd</p>", subtype="html")
        _, html, _ = pbm._extract_body(msg)
        assert "<p>send</p>" in html
        assert "​" not in html

    def test_addr_struct_strips_invisibles_in_display_name(self):
        # Display names go through _decode_header, so they inherit the
        # sanitisation. A spoofed display name carrying RLO should arrive
        # cleaned up.
        out = pbm._addr_struct("Pa​yPal <attacker@evil.com>")
        assert out == [{"name": "PayPal", "email": "attacker@evil.com"}]


# ----------------------------------------------------------------------------
# Destructive-tool acknowledgement gating
# ----------------------------------------------------------------------------
class TestSendEmailInputRequiresAck:
    """`acknowledged` is a server-enforced anti-coercion check on send."""

    def test_omitting_acknowledged_raises(self):
        with pytest.raises(ValidationError):
            pbm.SendEmailInput(
                to=["a@b.com"], subject="hi", body_text="hello",
            )

    def test_acknowledged_true_validates(self):
        m = pbm.SendEmailInput(
            to=["a@b.com"], subject="hi", body_text="hello", acknowledged=True,
        )
        assert m.acknowledged is True

    def test_acknowledged_false_validates_at_input_layer(self):
        # The bool itself is structurally valid; refusal happens in the
        # tool body (verified separately by TestRefusedUnack).
        m = pbm.SendEmailInput(
            to=["a@b.com"], subject="hi", body_text="hello", acknowledged=False,
        )
        assert m.acknowledged is False


class TestDeleteInputRequiresAck:
    """`acknowledged` is a server-enforced anti-coercion check on delete."""

    def test_omitting_acknowledged_raises(self):
        with pytest.raises(ValidationError):
            pbm.DeleteInput(uid="42")

    def test_omitting_acknowledged_raises_even_with_expunge(self):
        # The expunge flag does not satisfy the requirement; explicit
        # acknowledged=true is still required for a permanent delete.
        with pytest.raises(ValidationError):
            pbm.DeleteInput(uid="42", expunge=True)

    def test_acknowledged_true_validates(self):
        m = pbm.DeleteInput(uid="42", acknowledged=True)
        assert m.acknowledged is True

    def test_acknowledged_false_validates_at_input_layer(self):
        m = pbm.DeleteInput(uid="42", acknowledged=False)
        assert m.acknowledged is False


class TestRefusedUnack:
    def test_refusal_shape_for_send(self):
        data = json.loads(pbm._refused_unack("proton_send_email"))
        assert data["status"] == "refused"
        assert data["reason"] == "acknowledged_required"
        assert data["action"] == "proton_send_email"
        assert "acknowledged" in data["message"].lower()
        assert "prompt injection" in data["message"].lower()

    def test_refusal_shape_for_delete(self):
        data = json.loads(pbm._refused_unack("proton_delete_email"))
        assert data["action"] == "proton_delete_email"
        assert data["status"] == "refused"

    def test_refusal_shape_for_create_draft(self):
        data = json.loads(pbm._refused_unack("proton_create_draft"))
        assert data["action"] == "proton_create_draft"
        assert data["status"] == "refused"
        assert data["reason"] == "acknowledged_required"

    def test_refusal_shape_for_download_attachment(self):
        data = json.loads(pbm._refused_unack("proton_download_attachment"))
        assert data["action"] == "proton_download_attachment"
        assert data["status"] == "refused"


class TestCreateDraftInputRequiresAck:
    """`acknowledged` is required at the input layer so a model has to
    consciously decide. The body-level external-recipient gate decides
    whether `acknowledged=False` is actually refused."""

    def test_omitting_acknowledged_raises(self):
        with pytest.raises(ValidationError):
            pbm.CreateDraftInput(to=["a@b.com"], subject="hi", body_text="hello")

    def test_acknowledged_true_validates(self):
        m = pbm.CreateDraftInput(
            to=["a@b.com"], subject="hi", body_text="hello", acknowledged=True,
        )
        assert m.acknowledged is True

    def test_acknowledged_false_validates_at_input_layer(self):
        # Structurally valid; the tool body decides whether to refuse based
        # on whether any recipient is external.
        m = pbm.CreateDraftInput(
            to=["a@b.com"], subject="hi", body_text="hello", acknowledged=False,
        )
        assert m.acknowledged is False


class TestDownloadAttachmentInputRequiresAck:
    """Writing attachment bytes to a user-supplied path is a side effect
    outside the model's sandbox; the field is required."""

    def test_omitting_acknowledged_raises(self):
        with pytest.raises(ValidationError):
            pbm.DownloadAttachmentInput(
                uid="42", filename="report.pdf", save_path="/tmp/r.pdf",
            )

    def test_acknowledged_true_validates(self):
        m = pbm.DownloadAttachmentInput(
            uid="42", filename="report.pdf", save_path="/tmp/r.pdf",
            acknowledged=True,
        )
        assert m.acknowledged is True

    def test_acknowledged_false_validates_at_input_layer(self):
        m = pbm.DownloadAttachmentInput(
            uid="42", filename="report.pdf", save_path="/tmp/r.pdf",
            acknowledged=False,
        )
        assert m.acknowledged is False


class TestExternalRecipients:
    """Self-address detection for the draft-recipient gate."""

    def test_no_self_addresses_treats_all_as_external(self, monkeypatch):
        monkeypatch.setattr(pbm, "BRIDGE_USER", "")
        monkeypatch.setattr(pbm, "DEFAULT_FROM", "")
        out = pbm._external_recipients(["a@b.com"], None, None)
        assert out == ["a@b.com"]

    def test_self_address_excluded(self, monkeypatch):
        monkeypatch.setattr(pbm, "BRIDGE_USER", "me@example.com")
        monkeypatch.setattr(pbm, "DEFAULT_FROM", "me@example.com")
        out = pbm._external_recipients(["me@example.com"], None, None)
        assert out == []

    def test_mixed_self_and_external(self, monkeypatch):
        monkeypatch.setattr(pbm, "BRIDGE_USER", "me@example.com")
        monkeypatch.setattr(pbm, "DEFAULT_FROM", "me@example.com")
        out = pbm._external_recipients(
            ["me@example.com", "attacker@evil.com"], None, None,
        )
        assert out == ["attacker@evil.com"]

    def test_case_insensitive_self_match(self, monkeypatch):
        monkeypatch.setattr(pbm, "BRIDGE_USER", "Me@Example.com")
        monkeypatch.setattr(pbm, "DEFAULT_FROM", "me@example.com")
        out = pbm._external_recipients(["me@EXAMPLE.com"], None, None)
        assert out == []

    def test_default_from_alias_treated_as_self(self, monkeypatch):
        # User has BRIDGE_USER as primary but DEFAULT_FROM as an alias they
        # also own -- both should be treated as self.
        monkeypatch.setattr(pbm, "BRIDGE_USER", "primary@example.com")
        monkeypatch.setattr(pbm, "DEFAULT_FROM", "alias@example.com")
        assert pbm._external_recipients(["primary@example.com"], None, None) == []
        assert pbm._external_recipients(["alias@example.com"], None, None) == []

    def test_cc_and_bcc_also_checked(self, monkeypatch):
        monkeypatch.setattr(pbm, "BRIDGE_USER", "me@example.com")
        monkeypatch.setattr(pbm, "DEFAULT_FROM", "me@example.com")
        out = pbm._external_recipients(
            ["me@example.com"],
            cc=["copy@evil.com"],
            bcc=["blind@evil.com"],
        )
        assert sorted(out) == ["blind@evil.com", "copy@evil.com"]

    def test_display_name_form_extracted(self, monkeypatch):
        # `Alice <alice@example.com>` should be treated by its bare address.
        monkeypatch.setattr(pbm, "BRIDGE_USER", "me@example.com")
        monkeypatch.setattr(pbm, "DEFAULT_FROM", "me@example.com")
        out = pbm._external_recipients(
            ["Alice <alice@evil.com>", "Me <me@example.com>"], None, None,
        )
        assert out == ["alice@evil.com"]


# ----------------------------------------------------------------------------
# _locate_bridge_cert (path search; no network)
# ----------------------------------------------------------------------------
class TestLocateBridgeCert:
    def test_explicit_override_path_used_when_present(self, tmp_path, monkeypatch):
        # Override path takes precedence over the candidates list.
        cert = tmp_path / "cert.pem"
        cert.write_text("-----BEGIN CERTIFICATE-----\nstub\n-----END CERTIFICATE-----\n")
        monkeypatch.setattr(pbm, "BRIDGE_CERT_PATH", str(cert))
        assert pbm._locate_bridge_cert() == cert

    def test_explicit_override_missing_returns_none(self, monkeypatch, tmp_path):
        # Override pointing at a nonexistent file should *not* fall through to
        # the candidates list -- the user clearly meant *that* path.
        nope = tmp_path / "does-not-exist.pem"
        monkeypatch.setattr(pbm, "BRIDGE_CERT_PATH", str(nope))
        assert pbm._locate_bridge_cert() is None


# ----------------------------------------------------------------------------
# Attachments: folder allow-list, size cap, MIME building
# ----------------------------------------------------------------------------
class TestLoadAttachments:
    @pytest.fixture
    def root(self, tmp_path, monkeypatch):
        root = tmp_path / "allowed"
        root.mkdir()
        monkeypatch.setattr(pbm, "ATTACHMENT_DIRS", [root])
        monkeypatch.setattr(pbm, "MAX_ATTACHMENT_BYTES", 1024)
        return root

    def test_none_and_empty_return_empty_list(self, root):
        assert pbm._load_attachments(None) == []
        assert pbm._load_attachments([]) == []

    def test_pdf_inside_allowed_folder_is_loaded(self, root):
        f = root / "sub" / "Entwurf.pdf"
        f.parent.mkdir()
        f.write_bytes(b"%PDF-1.7 test")
        [att] = pbm._load_attachments([str(f)])
        assert att == ("Entwurf.pdf", b"%PDF-1.7 test", "application", "pdf")

    def test_unknown_extension_falls_back_to_octet_stream(self, root):
        f = root / "data.unknownext"
        f.write_bytes(b"x")
        [(_, _, maintype, subtype)] = pbm._load_attachments([str(f)])
        assert (maintype, subtype) == ("application", "octet-stream")

    def test_relative_path_is_rejected(self, root):
        with pytest.raises(ValueError, match="absolute"):
            pbm._load_attachments(["Entwurf.pdf"])

    def test_missing_file_is_rejected(self, root):
        with pytest.raises(ValueError, match="not found"):
            pbm._load_attachments([str(root / "missing.pdf")])

    def test_directory_is_rejected(self, root):
        with pytest.raises(ValueError, match="regular file"):
            pbm._load_attachments([str(root)])

    def test_file_outside_allowed_folder_is_rejected(self, root, tmp_path):
        f = tmp_path / "secret.txt"
        f.write_text("key")
        with pytest.raises(ValueError, match="outside the allowed folders"):
            pbm._load_attachments([str(f)])

    def test_dotdot_escape_is_rejected(self, root, tmp_path):
        (tmp_path / "secret.txt").write_text("key")
        with pytest.raises(ValueError, match="outside the allowed folders"):
            pbm._load_attachments([str(root / ".." / "secret.txt")])

    def test_symlink_escaping_allowed_folder_is_rejected(self, root, tmp_path):
        target = tmp_path / "secret.txt"
        target.write_text("key")
        link = root / "harmless.pdf"
        link.symlink_to(target)
        with pytest.raises(ValueError, match="outside the allowed folders"):
            pbm._load_attachments([str(link)])

    def test_errors_do_not_reveal_what_exists_outside_allowed_folder(self, root, tmp_path):
        existing = tmp_path / "secret.txt"
        existing.write_text("key")
        # A file, a missing path and a directory must all get the same answer.
        for path in (existing, tmp_path / "missing.txt", tmp_path):
            with pytest.raises(ValueError, match="outside the allowed folders"):
                pbm._load_attachments([str(path)])

    def test_symlink_loop_is_rejected(self, root):
        loop = root / "loop.pdf"
        loop.symlink_to(loop)
        with pytest.raises(ValueError):
            pbm._load_attachments([str(loop)])

    def test_total_size_cap(self, root):
        a = root / "a.bin"
        b = root / "b.bin"
        a.write_bytes(b"x" * 600)
        b.write_bytes(b"x" * 600)
        assert len(pbm._load_attachments([str(a)])) == 1
        with pytest.raises(ValueError, match="exceed"):
            pbm._load_attachments([str(a), str(b)])

    def test_no_configured_folder_refuses_every_path(self, monkeypatch, tmp_path):
        monkeypatch.setattr(pbm, "ATTACHMENT_DIRS", [])
        existing = tmp_path / "a.pdf"
        existing.write_bytes(b"x")
        # A missing file gets the same answer, so the error does not reveal
        # which local paths exist.
        for path in (existing, tmp_path / "missing.pdf"):
            with pytest.raises(ValueError, match="PROTON_BRIDGE_ATTACHMENT_DIRS"):
                pbm._load_attachments([str(path)])

    def test_no_configured_folder_keeps_mail_without_attachments_working(self, monkeypatch):
        monkeypatch.setattr(pbm, "ATTACHMENT_DIRS", [])
        assert pbm._load_attachments(None) == []
        assert pbm._load_attachments([]) == []


class TestAttachmentDirsEnv:
    """ATTACHMENT_DIRS is read at import, so each case needs a fresh interpreter."""

    @staticmethod
    def _dirs(value=None):
        env = {k: v for k, v in os.environ.items() if k != "PROTON_BRIDGE_ATTACHMENT_DIRS"}
        if value is not None:
            env["PROTON_BRIDGE_ATTACHMENT_DIRS"] = value
        code = (
            "import json, proton_bridge_mcp as p; "
            "print(json.dumps([str(d) for d in p.ATTACHMENT_DIRS]))"
        )
        result = subprocess.run(
            [sys.executable, "-c", code], capture_output=True, text=True,
            env=env, cwd=Path(pbm.__file__).parent, check=True,
        )
        return json.loads(result.stdout)

    def test_unset_means_no_allowed_folder(self):
        assert self._dirs() == []

    def test_folders_are_split_on_pathsep_and_trimmed(self):
        assert self._dirs(f"/a{os.pathsep} /b {os.pathsep}") == ["/a", "/b"]


class TestBuildEmailWithAttachments:
    @staticmethod
    def _build(attachments):
        return pbm._build_email(
            sender="me@proton.me", to=["you@example.com"], subject="Angebot",
            body_text="Hallo", body_html=None, cc=None, bcc=None,
            reply_to_message_id=None, attachments=attachments,
        )

    @staticmethod
    def _parse(msg):
        from email import policy
        return email.message_from_bytes(msg.as_bytes(), _class=EmailMessage, policy=policy.default)

    def test_without_attachments_stays_single_part(self):
        msg = self._build(None)
        assert not msg.is_multipart()
        assert msg.get_content().strip() == "Hallo"

    def test_attachment_round_trips(self):
        msg = self._build([("draft.pdf", b"%PDF-1.7 data", "application", "pdf")])
        parsed = self._parse(msg)
        assert parsed.get_content_type() == "multipart/mixed"
        assert parsed.get_body(preferencelist=("plain",)).get_content().strip() == "Hallo"
        [att] = list(parsed.iter_attachments())
        assert att.get_filename() == "draft.pdf"
        assert att.get_content_type() == "application/pdf"
        assert att.get_content() == b"%PDF-1.7 data"

    def test_non_ascii_filename_round_trips(self):
        parsed = self._parse(self._build([("Präsentation.pdf", b"x", "application", "pdf")]))
        [att] = list(parsed.iter_attachments())
        assert att.get_filename() == "Präsentation.pdf"


class TestAttachmentsInputField:
    def test_send_accepts_attachments(self):
        m = pbm.SendEmailInput(to=["a@b.com"], subject="hi", body_text="x",
                               attachments=["/tmp/a.pdf"], acknowledged=True)
        assert m.attachments == ["/tmp/a.pdf"]

    def test_draft_accepts_attachments(self):
        m = pbm.CreateDraftInput(to=["a@b.com"], subject="hi", body_text="x",
                                 attachments=["/tmp/a.pdf"], acknowledged=True)
        assert m.attachments == ["/tmp/a.pdf"]

    def test_attachments_default_to_none(self):
        m = pbm.SendEmailInput(to=["a@b.com"], subject="hi", body_text="x", acknowledged=True)
        assert m.attachments is None

    def test_more_than_ten_attachments_rejected(self):
        with pytest.raises(ValidationError):
            pbm.SendEmailInput(to=["a@b.com"], subject="hi", body_text="x",
                               attachments=[f"/tmp/{i}.pdf" for i in range(11)],
                               acknowledged=True)
