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
