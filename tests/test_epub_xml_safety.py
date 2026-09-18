"""XML entity-declaration guard for the EPUB parsers.

DOCX has had ``validate_docx_xml_safety`` since the XXE fix; EPUB had nothing
equivalent. The stdlib EPUB path parses the OPF with regular expressions and is
safe by construction, but ``extract_with_ebooklib`` hands the archive to
ebooklib, which parses it with lxml — so entity declarations in an EPUB reached
a real XML parser unchecked.

The rule cannot simply be copied from DOCX. OOXML never legitimately carries a
DOCTYPE, so DOCX rejects it outright; in EPUB a DOCTYPE is ubiquitous and
legitimate — ``<!DOCTYPE html>`` opens nearly every XHTML content document, and
EPUB 2 files routinely carry the public XHTML 1.1 identifier. Rejecting those
would refuse most real books. What is never legitimate in either format is an
entity *declaration*, which is where both billion-laughs and XXE payloads live,
so that is what the EPUB guard refuses.
"""

import sys
import zipfile
from pathlib import Path

import pytest

ROOT_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT_DIR))

from book_to_skill.exceptions import ExtractionError  # noqa: E402
from book_to_skill.parsers.epub import extract_with_zipfile  # noqa: E402

BILLION_LAUGHS = (
    '<?xml version="1.0"?>'
    "<!DOCTYPE lolz ["
    '<!ENTITY lol "lol">'
    '<!ENTITY lol2 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;">'
    "]>"
    "<html><body><p>&lol2;</p></body></html>"
)

XXE_EXTERNAL = (
    '<?xml version="1.0"?>'
    '<!DOCTYPE package [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>'
    "<package><manifest><item id=\"c1\" href=\"ch1.xhtml\"/></manifest>"
    '<spine><itemref idref="c1"/></spine></package>'
)

PLAIN_OPF = (
    '<?xml version="1.0"?><package><manifest>'
    '<item id="c1" href="ch1.xhtml"/></manifest>'
    '<spine><itemref idref="c1"/></spine></package>'
)


def _write_epub(path, *, opf=PLAIN_OPF, chapter="<html><body><p>Chapter 1</p></body></html>"):
    with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as archive_file:
        archive_file.writestr("mimetype", "application/epub+zip")
        archive_file.writestr(
            "META-INF/container.xml",
            '<?xml version="1.0"?><container><rootfiles>'
            '<rootfile full-path="content.opf"/></rootfiles></container>',
        )
        archive_file.writestr("content.opf", opf)
        archive_file.writestr("ch1.xhtml", chapter)
    return str(path)


class TestEntityDeclarationsAreRefused:
    def test_entity_expansion_bomb_in_a_chapter_is_refused(self, tmp_path):
        path = _write_epub(tmp_path / "laughs.epub", chapter=BILLION_LAUGHS)

        with pytest.raises(ExtractionError, match="entity"):
            extract_with_zipfile(path)

    def test_external_entity_in_the_opf_is_refused(self, tmp_path):
        path = _write_epub(tmp_path / "xxe.epub", opf=XXE_EXTERNAL)

        with pytest.raises(ExtractionError, match="entity"):
            extract_with_zipfile(path)

    def test_entity_declaration_in_container_xml_is_refused(self, tmp_path):
        path = tmp_path / "container.epub"
        with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as archive_file:
            archive_file.writestr("mimetype", "application/epub+zip")
            archive_file.writestr(
                "META-INF/container.xml",
                '<?xml version="1.0"?>'
                '<!DOCTYPE container [<!ENTITY x SYSTEM "file:///etc/passwd">]>'
                "<container><rootfiles>"
                '<rootfile full-path="content.opf"/></rootfiles></container>',
            )
            archive_file.writestr("content.opf", PLAIN_OPF)
            archive_file.writestr("ch1.xhtml", "<html><body><p>Chapter 1</p></body></html>")

        with pytest.raises(ExtractionError, match="entity"):
            extract_with_zipfile(str(path))


class TestOrdinaryEpubDoctypesStillWork:
    """The guard must not refuse the DOCTYPEs real books actually carry."""

    def test_html5_doctype_in_a_chapter_still_extracts(self, tmp_path):
        path = _write_epub(
            tmp_path / "html5.epub",
            chapter="<!DOCTYPE html><html><body><p>Chapter 1</p></body></html>",
        )

        assert "Chapter 1" in extract_with_zipfile(path)

    def test_epub2_public_xhtml_doctype_still_extracts(self, tmp_path):
        path = _write_epub(
            tmp_path / "xhtml11.epub",
            chapter=(
                '<?xml version="1.0" encoding="utf-8"?>'
                '<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.1//EN" '
                '"http://www.w3.org/TR/xhtml11/DTD/xhtml11.dtd">'
                '<html xmlns="http://www.w3.org/1999/xhtml"><body>'
                "<p>Chapter 1</p></body></html>"
            ),
        )

        assert "Chapter 1" in extract_with_zipfile(path)


class TestDocxRulesAreUnchanged:
    def test_docx_still_refuses_a_bare_doctype(self, tmp_path):
        """DOCX is stricter than EPUB on purpose: OOXML has no legitimate
        DOCTYPE, so the existing outright rejection must survive this change."""
        from book_to_skill.parsers.docx import validate_docx_xml_safety

        path = tmp_path / "doctype.docx"
        with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as archive_file:
            archive_file.writestr(
                "word/document.xml",
                '<?xml version="1.0"?><!DOCTYPE w:document><w:document/>',
            )

        with pytest.raises(ExtractionError, match="DTD or entity"):
            validate_docx_xml_safety(str(path))
