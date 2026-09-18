"""Bounded reads for the ZIP-backed document formats (DOCX, EPUB).

DOCX and EPUB are ZIP archives, and the parsers read members whole. Compression
makes that asymmetric: a member costs kilobytes on disk and megabytes in memory,
so a crafted file a few hundred kilobytes in size expands to gigabytes — a
decompression bomb. Every read of untrusted archive content goes through
:class:`ArchiveBudget` so both a single huge member and a pile of merely large
ones are refused.

The check reads the size declared in the member's header and refuses *before*
decompressing anything. That is sound, not merely a hint: CPython's
``ZipExtFile`` stops producing bytes at the declared size, so a header that
understates its member yields a truncated read that then fails its CRC check
rather than expanding past what the header promised. The header is therefore an
upper bound on what the read can cost.
"""

from __future__ import annotations

import zipfile

from book_to_skill.exceptions import ExtractionError

# Per-member ceiling. A book's largest single member — `word/document.xml` for a
# long DOCX, one chapter of an EPUB — is comfortably inside this; nothing
# legitimate in a prose document approaches it.
MAX_ARCHIVE_MEMBER_BYTES = 64 * 1024 * 1024

# Ceiling across one pass over one archive, so many members each just under the
# per-member limit cannot add up to the same exhaustion.
MAX_ARCHIVE_TOTAL_BYTES = 256 * 1024 * 1024


class ArchiveBudget:
    """Byte budget for a single pass over a single archive.

    Construct one per parse (or per validation scan) and route every member
    read through :meth:`read`. The limits are read from the module globals on
    each call rather than captured at construction, so a caller — or a test —
    can lower them by patching the module.
    """

    def __init__(self) -> None:
        self.spent = 0

    def read(self, archive_file: zipfile.ZipFile, name: str) -> bytes:
        declared = archive_file.getinfo(name).file_size

        if declared > MAX_ARCHIVE_MEMBER_BYTES:
            raise ExtractionError(
                f"Refusing to read '{name}': it declares {declared:,} uncompressed "
                f"bytes, which is too large (per-member limit is "
                f"{MAX_ARCHIVE_MEMBER_BYTES:,} bytes). A document member this size "
                "is the signature of a decompression bomb."
            )

        if self.spent + declared > MAX_ARCHIVE_TOTAL_BYTES:
            raise ExtractionError(
                f"Refusing to read '{name}': the archive's uncompressed contents "
                f"exceeds the {MAX_ARCHIVE_TOTAL_BYTES:,}-byte total limit for one "
                "document. A document this size is the signature of a "
                "decompression bomb."
            )

        self.spent += declared
        return archive_file.read(name)


# XML keywords are case-sensitive in the spec, so a conforming parser only
# honours the uppercase forms; the scan uppercases anyway so a non-conforming
# one cannot be used to slip a declaration past this check.
_DOCTYPE_MARKER = "<!DOCTYPE"
_ENTITY_MARKER = "<!ENTITY"

# A DOCTYPE may be declared in any encoding an XML parser accepts, and a
# single-encoding scan would miss the others. The cost of trying all of them is
# what made this scan the decompression-bomb amplifier; ArchiveBudget caps the
# input instead, so the coverage does not have to be traded away.
_DECLARATION_ENCODINGS = ("utf-8", "utf-16", "utf-16le", "utf-16be", "utf-32")


def scan_zip_xml_for_declarations(
    archive_path: str,
    *,
    suffixes: tuple[str, ...],
    reject_doctype: bool,
) -> tuple[str, str] | None:
    """Find the first XML member carrying a forbidden markup declaration.

    Returns ``(member_name, marker)`` for the first offender, or ``None`` when
    the archive is clean. Callers word their own error, because the two formats
    need different rules and say so differently:

    * DOCX passes ``reject_doctype=True``. OOXML never legitimately carries a
      DOCTYPE, so any of them is refused.
    * EPUB passes ``reject_doctype=False``. A DOCTYPE is ubiquitous and
      legitimate there — ``<!DOCTYPE html>`` opens nearly every XHTML content
      document and EPUB 2 files carry the public XHTML 1.1 identifier — so
      refusing it would refuse most real books. An entity *declaration* is
      refused in both, which is where billion-laughs and XXE payloads live.

    Reads go through a fresh :class:`ArchiveBudget`, so a hostile archive cannot
    exhaust memory during the very scan meant to screen it.
    """
    budget = ArchiveBudget()
    markers = (_ENTITY_MARKER, _DOCTYPE_MARKER) if reject_doctype else (_ENTITY_MARKER,)

    with zipfile.ZipFile(archive_path) as archive_file:
        for name in archive_file.namelist():
            if not name.lower().endswith(suffixes):
                continue
            xml_bytes = budget.read(archive_file, name)
            for encoding in _DECLARATION_ENCODINGS:
                try:
                    content = xml_bytes.decode(encoding, errors="ignore").upper()
                except LookupError:
                    continue
                for marker in markers:
                    if marker in content:
                        return name, marker
    return None
