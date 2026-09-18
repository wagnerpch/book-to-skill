from __future__ import annotations

import posixpath
import re
import zipfile
import sys
from book_to_skill.archive import ArchiveBudget, scan_zip_xml_for_declarations
from book_to_skill.exceptions import ExtractionError
from book_to_skill.parsers.html import _HTMLTextExtractor


# Members an XML parser will read. Content documents are included because
# ebooklib hands them to lxml, so an entity declared in a chapter reaches a real
# XML parser just as one in the OPF does.
_XML_MEMBER_SUFFIXES = (".xml", ".opf", ".ncx", ".xhtml", ".html", ".htm")


def validate_epub_xml_safety(epub_path: str) -> None:
    """Refuse an EPUB that declares XML entities.

    The stdlib path below reads the OPF with regular expressions and is safe by
    construction, but ``extract_with_ebooklib`` hands the archive to ebooklib,
    which parses it with lxml — so without this an entity declaration in an EPUB
    reached a real XML parser unchecked, the gap ``validate_docx_xml_safety``
    already closed for DOCX.

    Unlike DOCX this does *not* refuse a DOCTYPE: ``<!DOCTYPE html>`` opens
    nearly every XHTML content document and EPUB 2 files carry the public XHTML
    1.1 identifier, so refusing DOCTYPEs would refuse most real books. Entity
    declarations have no legitimate use in a book and are where both
    billion-laughs and XXE payloads live.

    Raises ``ExtractionError`` only for a security verdict. An archive that
    cannot be opened or read at all raises whatever ``zipfile`` raised —
    BadZipFile, OSError — and each caller keeps handling that the way it always
    did. Translating those here made an unreadable file indistinguishable from a
    hostile one, which broke ``extract_with_ebooklib``'s contract of returning
    ``str | None`` for ordinary failures: the caller stopped falling through to
    the stdlib parser for a file that was merely missing.
    """
    offender = scan_zip_xml_for_declarations(
        epub_path, suffixes=_XML_MEMBER_SUFFIXES, reject_doctype=False
    )
    if offender is not None:
        name, _marker = offender
        raise ExtractionError(
            f"Security validation failed: XML file '{name}' in EPUB archive "
            "declares an XML entity, which is not used by legitimate books "
            "and is the shape of an entity-expansion or XXE payload."
        )


_IMAGE_EXTENSIONS = (
    ".avif",
    ".bmp",
    ".gif",
    ".jpeg",
    ".jpg",
    ".png",
    ".svg",
    ".tif",
    ".tiff",
    ".webp",
)


def extract_with_ebooklib(epub_path: str) -> str | None:
    try:
        import ebooklib
        from ebooklib import epub
        from bs4 import BeautifulSoup

        validate_epub_xml_safety(epub_path)
        book = epub.read_epub(epub_path)
        parts = []
        for item in book.get_items_of_type(ebooklib.ITEM_DOCUMENT):
            soup = BeautifulSoup(item.get_content(), "html.parser")
            parts.append(soup.get_text(separator="\n"))
        return "\n\n".join(parts)
    except ImportError:
        return None
    except ExtractionError:
        # A security refusal must not be downgraded to "ebooklib unavailable";
        # the caller would fall through to the stdlib parser and read on.
        raise
    except Exception as e:
        print(f"  [warn] extract_with_ebooklib failed: {type(e).__name__}: {e}", file=sys.stderr)
        return None


def _find_opf_path(zf: zipfile.ZipFile, budget: ArchiveBudget | None = None) -> str | None:
    """Locate the OPF package document inside an EPUB archive.

    First tries ``META-INF/container.xml`` (the spec-defined entry point),
    then falls back to scanning the archive for any ``.opf`` file.

    ``budget`` is optional so a caller reading only this one small member does
    not have to thread one through; the extraction paths pass their own so the
    container and the OPF count against the same per-archive ceiling as the
    chapters that follow.
    """
    if budget is None:
        budget = ArchiveBudget()
    # Spec-defined: read container.xml for the rootfile path
    try:
        container = budget.read(zf, "META-INF/container.xml").decode("utf-8", errors="replace")
        match = re.search(r'full-path=["\']([^"\']+\.opf)["\']', container)
        if match:
            return match.group(1)
    except ExtractionError:
        # A size refusal must not be downgraded to "no container.xml"; that
        # would silently fall through to the .opf glob and read on.
        raise
    except Exception:
        pass

    # Fallback: glob for any .opf file
    opf_files = [n for n in zf.namelist() if n.endswith(".opf")]
    return opf_files[0] if opf_files else None


def extract_with_zipfile(epub_path: str) -> str | None:
    """stdlib-only EPUB extractor: unzip → parse HTML files."""
    budget = ArchiveBudget()
    try:
        # Self-defending, like the DOCX parsers: this path parses the OPF with
        # regular expressions rather than an XML parser, but validating here
        # means the guard does not depend on which extractor the caller reached.
        # Inside the try, so an unopenable archive still returns None through
        # the handler below instead of escaping as a bare OSError.
        validate_epub_xml_safety(epub_path)
        with zipfile.ZipFile(epub_path) as zf:
            names = zf.namelist()

            # Locate OPF and determine its directory for resolving relative hrefs
            opf_path = _find_opf_path(zf, budget)
            opf_dir = posixpath.dirname(opf_path) if opf_path else ""

            # Build reading order from the OPF spine (not the manifest's href
            # order), then append any remaining content docs as a safety net.
            spine_order: list[str] = []
            seen: set[str] = set()
            if opf_path:
                opf_text = budget.read(zf, opf_path).decode("utf-8", errors="replace")

                # Manifest: item id -> resolved href. Parse each <item> opening
                # tag so attribute order (id before/after href) does not matter;
                # both self-closing <item .../> and <item ...></item> forms work
                # because all attributes live in the opening tag.
                manifest: dict[str, str] = {}
                for item_tag in re.findall(r"<item\b[^>]*?/?>", opf_text):
                    id_m = re.search(r'\bid=["\']([^"\']+)["\']', item_tag)
                    href_m = re.search(r'\bhref=["\']([^"\']+)["\']', item_tag)
                    if id_m and href_m:
                        href = href_m.group(1)
                        resolved = posixpath.normpath(posixpath.join(opf_dir, href)) if opf_dir else href
                        manifest[id_m.group(1)] = resolved

                # Spine: ordered idrefs -> hrefs (true reading order).
                for idref in re.findall(r'<itemref\b[^>]*?\bidref=["\']([^"\']+)["\']', opf_text):
                    href = manifest.get(idref)
                    if href and href not in seen:
                        spine_order.append(href)
                        seen.add(href)

                # Safety net: append remaining manifest content documents (e.g. a
                # nav doc not in the spine) in manifest order, so nothing is lost.
                for href in manifest.values():
                    if href.endswith((".html", ".xhtml")) and href not in seen:
                        spine_order.append(href)
                        seen.add(href)

            html_files = spine_order or sorted(
                n for n in names if n.endswith((".html", ".xhtml"))
            )
            if not html_files:
                return None

            parts = []
            for name in html_files:
                try:
                    raw = budget.read(zf, name).decode("utf-8", errors="replace")
                    parser = _HTMLTextExtractor()
                    parser.feed(raw)
                    parts.append(parser.get_text())
                except ExtractionError:
                    # Skipping a refused member would keep reading the rest of a
                    # hostile archive; the whole source has to fail instead.
                    raise
                except Exception:
                    continue
            return "\n\n".join(parts) if parts else None
    except ExtractionError:
        raise
    except Exception as e:
        print(f"  [warn] extract_with_zipfile failed: {type(e).__name__}: {e}", file=sys.stderr)
        return None


def count_epub_chapters(epub_path: str) -> int:
    """Count spine items (approximate chapter count) without dependencies."""
    try:
        with zipfile.ZipFile(epub_path) as zf:
            budget = ArchiveBudget()
            opf_path = _find_opf_path(zf, budget)
            if not opf_path:
                return 0
            opf_text = budget.read(zf, opf_path).decode("utf-8", errors="replace")
            return len(re.findall(r'<itemref\b', opf_text))
    except Exception:
        return 0


def count_epub_images(epub_path: str) -> int:
    """Count image members whose content the text-only EPUB parsers omit."""
    try:
        with zipfile.ZipFile(epub_path) as zf:
            return sum(
                not info.is_dir() and info.filename.lower().endswith(_IMAGE_EXTENSIONS)
                for info in zf.infolist()
            )
    except (OSError, zipfile.BadZipFile):
        return 0

