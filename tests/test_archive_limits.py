"""Decompression-bomb limits for the ZIP-backed parsers (DOCX, EPUB).

A DOCX or EPUB is a ZIP archive, and every parser here reads members whole.
Without a ceiling, a few hundred kilobytes on disk expands to gigabytes in
memory: the archives built below are the real shape of that attack, just with
the limits lowered so the test stays cheap.

The guard reads ``ZipInfo.file_size`` and refuses *before* decompressing.
That is sound because CPython's ``ZipExtFile`` already stops at the declared
size — a member whose header understates its content is truncated and fails
its CRC check rather than expanding past the header — so the header is an
upper bound on what a read can cost, not merely a hint.
"""

import sys
import zipfile
from pathlib import Path

import pytest

ROOT_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT_DIR))

from book_to_skill import archive  # noqa: E402
from book_to_skill.exceptions import ExtractionError  # noqa: E402
from book_to_skill.parsers.docx import (
    extract_docx_with_zipfile,
    validate_docx_xml_safety,
)
from book_to_skill.parsers.epub import extract_with_zipfile  # noqa: E402

DOCUMENT_XML = (
    '<?xml version="1.0"?>'
    '<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">'
    "<w:body><w:p><w:r><w:t>{text}</w:t></w:r></w:p></w:body>"
    "</w:document>"
)


def _write_docx(path, document_xml):
    with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as archive_file:
        archive_file.writestr("word/document.xml", document_xml)
    return str(path)


def _write_epub(path, chapter_html):
    with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as archive_file:
        archive_file.writestr("mimetype", "application/epub+zip")
        archive_file.writestr(
            "META-INF/container.xml",
            '<?xml version="1.0"?><container><rootfiles>'
            '<rootfile full-path="content.opf"/></rootfiles></container>',
        )
        archive_file.writestr(
            "content.opf",
            '<?xml version="1.0"?><package><manifest>'
            '<item id="c1" href="ch1.xhtml"/></manifest>'
            '<spine><itemref idref="c1"/></spine></package>',
        )
        archive_file.writestr("ch1.xhtml", chapter_html)
    return str(path)


def _write_large_member_epub(path, member_bytes):
    """EPUB whose single chapter decompresses to *member_bytes*.

    Written in chunks through ``ZipFile.open(..., "w")`` so the test never
    holds the expanded payload in memory — the same asymmetry the attack
    relies on.
    """
    chunk = b"A" * (1024 * 1024)
    with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as archive_file:
        archive_file.writestr("mimetype", "application/epub+zip")
        archive_file.writestr(
            "META-INF/container.xml",
            '<?xml version="1.0"?><container><rootfiles>'
            '<rootfile full-path="content.opf"/></rootfiles></container>',
        )
        archive_file.writestr(
            "content.opf",
            '<?xml version="1.0"?><package><manifest>'
            '<item id="c1" href="ch1.xhtml"/></manifest>'
            '<spine><itemref idref="c1"/></spine></package>',
        )
        written = 0
        with archive_file.open("ch1.xhtml", "w") as member:
            member.write(b"<html><body>")
            while written < member_bytes:
                member.write(chunk)
                written += len(chunk)
            member.write(b"</body></html>")
    return str(path)


class TestMemberLimit:
    def test_docx_validation_refuses_member_larger_than_the_limit(
        self, tmp_path, monkeypatch
    ):
        monkeypatch.setattr(archive, "MAX_ARCHIVE_MEMBER_BYTES", 4096)
        path = _write_docx(tmp_path / "bomb.docx", DOCUMENT_XML.format(text="A" * 20_000))

        with pytest.raises(ExtractionError, match="too large"):
            validate_docx_xml_safety(path)

    def test_docx_extraction_refuses_member_larger_than_the_limit(
        self, tmp_path, monkeypatch
    ):
        monkeypatch.setattr(archive, "MAX_ARCHIVE_MEMBER_BYTES", 4096)
        path = _write_docx(tmp_path / "bomb.docx", DOCUMENT_XML.format(text="A" * 20_000))

        with pytest.raises(ExtractionError, match="too large"):
            extract_docx_with_zipfile(path)

    def test_epub_extraction_refuses_member_larger_than_the_limit(
        self, tmp_path, monkeypatch
    ):
        monkeypatch.setattr(archive, "MAX_ARCHIVE_MEMBER_BYTES", 4096)
        path = _write_epub(tmp_path / "bomb.epub", "<html><body>" + "A" * 20_000 + "</body></html>")

        with pytest.raises(ExtractionError, match="too large"):
            extract_with_zipfile(path)

    def test_shipped_default_limit_refuses_a_high_ratio_archive(self, tmp_path):
        """No monkeypatching: the limit the project actually ships must reject
        a bomb, and must do so from the header — the archive is a fraction of
        the payload it declares, so a rejection quoting the expanded size can
        only have come from the header, not from decompressing."""
        over_limit = archive.MAX_ARCHIVE_MEMBER_BYTES + (1024 * 1024)
        path = _write_large_member_epub(tmp_path / "bomb.epub", over_limit)

        on_disk = (tmp_path / "bomb.epub").stat().st_size
        assert on_disk < over_limit // 100, "fixture is not a high-ratio archive"

        with pytest.raises(ExtractionError, match="too large"):
            extract_with_zipfile(path)


class TestTotalLimit:
    def test_docx_validation_refuses_archive_exceeding_the_total_budget(
        self, tmp_path, monkeypatch
    ):
        """Many members, each individually under the per-member limit, must
        still be refused once their combined size passes the total budget."""
        monkeypatch.setattr(archive, "MAX_ARCHIVE_MEMBER_BYTES", 8192)
        monkeypatch.setattr(archive, "MAX_ARCHIVE_TOTAL_BYTES", 20_000)
        path = tmp_path / "many.docx"
        with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as archive_file:
            archive_file.writestr("word/document.xml", DOCUMENT_XML.format(text="x"))
            for index in range(10):
                archive_file.writestr(f"word/part{index}.xml", "<a>" + "B" * 5000 + "</a>")

        with pytest.raises(ExtractionError, match="exceeds"):
            validate_docx_xml_safety(str(path))


class TestLegitimateArchivesStillWork:
    def test_ordinary_docx_still_extracts(self, tmp_path):
        path = _write_docx(tmp_path / "book.docx", DOCUMENT_XML.format(text="Chapter 1"))

        assert extract_docx_with_zipfile(path) == "Chapter 1"

    def test_ordinary_epub_still_extracts(self, tmp_path):
        path = _write_epub(
            tmp_path / "book.epub", "<html><body><p>Chapter 1</p></body></html>"
        )

        assert "Chapter 1" in extract_with_zipfile(path)
