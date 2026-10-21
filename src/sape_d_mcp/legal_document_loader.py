# SAPÉ d-MCP — controlled database access with granular permissions for LLMs
# Copyright (C) 2026 Luciano Arrezze
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, version 3.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.
#
# SPDX-License-Identifier: GPL-3.0-only

"""Legal document loader.

Loads the program's legal documents, with automatic fallback to English when
a locale-specific version is unavailable.

The documents are maintained in **English only**: SAPÉ d-MCP is licensed
under GPL-3.0-only, the GNU GPL is legally authoritative in English, and the
Free Software Foundation does not publish binding translations. A translated
licence would carry no legal force. The interface itself stays localised —
the document *labels* come from the i18n catalogue, only the document
*bodies* are English.

The directory structure keeps its per-locale shape so a locale can be added
later without a code change; today only ``en-US`` is populated and every
other language resolves to it through the fallback in :meth:`get_document`.

    legal-documents/
        en-US/
            LICENSE.md          (verbatim GNU GPL v3)
            DISCLAIMER.md
            DATA-PROTECTION.md
            LEGAL-README.md

Unlike f-MCP's loader, the default directory comes from
:func:`sape_d_mcp.gui.resources.legal_documents_dir` rather than a
hand-counted ``Path(__file__).parent.parent`` — see that module's docstring
for why the hand-counted version breaks under PyInstaller.
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import ClassVar

logger = logging.getLogger(__name__)


class LegalDocumentLoader:
    """Load and manage the program's legal documents."""

    # The four documents shipped with the program. As in f-MCP, no
    # proprietary-style documents exist here: GPL-3.0 section 7 would make
    # void any further restriction one might try to assert alongside it, so
    # there is nothing else to add without being misleading.
    DOCUMENT_TYPES: ClassVar[list[str]] = [
        'LICENSE.md',
        'DISCLAIMER.md',
        'DATA-PROTECTION.md',
        'LEGAL-README.md',
    ]

    def __init__(self, legal_docs_dir: str | Path | None = None):
        """Initialise the loader with a path to the ``legal-documents`` folder.

        Args:
            legal_docs_dir: Path to the legal-documents directory. If ``None``,
                resolved via :func:`sape_d_mcp.gui.resources.legal_documents_dir`.
        """
        if legal_docs_dir is None:
            from sape_d_mcp.gui.resources import legal_documents_dir

            legal_docs_dir = legal_documents_dir()
        self.legal_docs_dir = Path(legal_docs_dir)

    def get_document(self, lang_code: str, doc_type: str) -> str:
        """Load a document's content for ``lang_code``, falling back to English.

        Returns:
            The document text, the English fallback if the requested locale
            is missing, or a "not found" message if neither exists.

        Example:
            >>> loader = LegalDocumentLoader()
            >>> loader.get_document('es-ES', 'LICENSE.md').splitlines()[0].strip()
            'GNU GENERAL PUBLIC LICENSE'
        """
        doc_path = self.legal_docs_dir / lang_code / doc_type
        if doc_path.exists():
            return doc_path.read_text(encoding='utf-8')

        fallback_path = self.legal_docs_dir / 'en-US' / doc_type
        if fallback_path.exists():
            return fallback_path.read_text(encoding='utf-8')

        return f"Document not found: {doc_type} (requested: {lang_code}, fallback: en-US)"

    def get_all_documents(self, lang_code: str) -> dict[str, str]:
        """Load all four documents for ``lang_code`` as a dict keyed by document name.

        Example:
            >>> docs = LegalDocumentLoader().get_all_documents('es-ES')
            >>> sorted(docs)
            ['data-protection', 'disclaimer', 'legal-readme', 'license']
        """
        docs = {}
        for doc_type in self.DOCUMENT_TYPES:
            key = doc_type.replace('.md', '').lower()
            docs[key] = self.get_document(lang_code, doc_type)
        return docs

    def get_document_list(self) -> list[str]:
        """Return the document names (without ``.md``, lower-cased), for UI navigation."""
        return [d.replace('.md', '').lower() for d in self.DOCUMENT_TYPES]

    def get_supported_languages(self) -> list[str]:
        """Return the language codes that have their own ``legal-documents/`` folder.

        Only ``en-US`` is populated today (see the module docstring); every
        other language reaches these documents through the English fallback.
        """
        if not self.legal_docs_dir.exists():
            return []

        langs = []
        for item in self.legal_docs_dir.iterdir():
            if item.is_dir() and '-' in item.name and len(item.name) == 5:
                langs.append(item.name)

        return sorted(langs)

    def document_exists(self, lang_code: str, doc_type: str) -> bool:
        """Return whether ``doc_type`` exists for ``lang_code`` (no fallback)."""
        doc_path = self.legal_docs_dir / lang_code / doc_type
        return doc_path.exists()

    def get_document_path(self, lang_code: str, doc_type: str) -> Path | None:
        """Return the file path for ``doc_type`` in ``lang_code`` (no fallback)."""
        doc_path = self.legal_docs_dir / lang_code / doc_type
        if doc_path.exists():
            return doc_path
        return None

    def get_base_dir(self) -> Path:
        """Return the root ``legal-documents`` directory."""
        return self.legal_docs_dir
