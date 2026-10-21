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

"""SAPÉ design system tokens for PyQt6 — colours, typography, spacing and palettes.

Ported from SAPÉ f-MCP verbatim except for the ``ACTION_*`` block, which f-MCP
uses for filesystem verbs (create/read/write/delete/move/copy/chmod) and
d-MCP replaces with the seven database verbs the permission model actually
grants: SELECT, INSERT, UPDATE, DELETE, DDL, EXECUTE and GRANT. The hue
vocabulary is kept so a colour still means the same *kind* of danger across
both sibling applications.
"""

from __future__ import annotations

from PyQt6.QtGui import QColor, QPalette

# ===== BRAND COLOURS =====
SAPE_PRIMARY = QColor("#1C3FF0")
SAPE_PRIMARY_DARK = QColor("#122AD2")
SAPE_ACCENT = QColor("#2E86FF")
SAPE_GRAPHITE = QColor("#212832")
SAPE_GRAPHITE_LIGHT = QColor("#6B7280")

# ===== LIGHT THEME COLOURS =====
LIGHT_BG = QColor("#F4F6FA")
LIGHT_SURFACE = QColor("#FFFFFF")
LIGHT_TEXT_PRIMARY = QColor("#212832")
LIGHT_TEXT_SECONDARY = QColor("#4B5563")
LIGHT_BORDER = QColor("#E1E5EA")
LIGHT_ALT = QColor("#F9FAFB")

# ===== DARK THEME COLOURS =====
DARK_BG = QColor("#0A0C10")
DARK_SURFACE = QColor("#15181D")
DARK_TEXT_PRIMARY = QColor("#E0E2E7")
DARK_TEXT_SECONDARY = QColor("#A7ACB3")
DARK_BORDER = QColor("#2D3139")
DARK_ALT = QColor("#1F2329")

# ===== SEMANTIC COLOURS =====
COLOR_SUCCESS = QColor("#10B981")
COLOR_ERROR = QColor("#EF4444")
COLOR_WARNING = QColor("#F59E0B")
COLOR_INFO = QColor("#3B82F6")

# ===== DATABASE ACTION COLOURS =====
# f-MCP's ACTION_* block names filesystem verbs (create/read/write/delete/
# move/copy/chmod). d-MCP's permission model has no notion of any of those —
# it grants SELECT, INSERT, UPDATE, DELETE, DDL, EXECUTE and GRANT — so the
# constants are renamed to match, keeping the same hue for the same class of
# risk (blue = read, green = additive, amber = mutating, red = destructive,
# purple = structural, cyan = reserved, pink = privilege).
ACTION_SELECT = QColor("#3B82F6")  # blue   - read
ACTION_INSERT = QColor("#10B981")  # green  - create
ACTION_UPDATE = QColor("#F59E0B")  # amber  - modify
ACTION_DELETE = QColor("#EF4444")  # red    - remove
ACTION_DDL = QColor("#8B5CF6")  # purple - create/drop/alter structure
ACTION_EXECUTE = QColor("#06B6D4")  # cyan   - reserved, no execute tool ships
ACTION_GRANT = QColor("#EC4899")  # pink   - roles, users, permissions
ACTION_ERROR = QColor("#DC2626")  # dark red

# ===== TYPOGRAPHY =====
FONT_FAMILY = "IBM Plex Sans"
FONT_MONO = "JetBrains Mono"

# ===== SPACING (4 px base unit) =====
SPACING_XS = 4
SPACING_SM = 8
SPACING_MD = 12
SPACING_LG = 16
SPACING_XL = 20
SPACING_2XL = 24
SPACING_3XL = 28
SPACING_4XL = 32

# ===== BORDER RADIUS =====
RADIUS_SM = 4
RADIUS_MD = 6
RADIUS_LG = 8
RADIUS_XL = 12


def create_light_palette() -> QPalette:
    """Build the light-theme QPalette.

    A palette (rather than only the QSS) matters because native dialogs —
    QFileDialog, QColorDialog, QMessageBox icons — pick their colours from
    it, not from the stylesheet.
    """
    palette = QPalette()

    # Windows/background
    palette.setColor(QPalette.ColorRole.Window, LIGHT_BG)
    palette.setColor(QPalette.ColorRole.Base, LIGHT_SURFACE)
    palette.setColor(QPalette.ColorRole.AlternateBase, LIGHT_ALT)

    # Text
    palette.setColor(QPalette.ColorRole.WindowText, LIGHT_TEXT_PRIMARY)
    palette.setColor(QPalette.ColorRole.Text, LIGHT_TEXT_PRIMARY)
    palette.setColor(QPalette.ColorRole.PlaceholderText, LIGHT_TEXT_SECONDARY)

    # Buttons
    palette.setColor(QPalette.ColorRole.Button, LIGHT_SURFACE)
    palette.setColor(QPalette.ColorRole.ButtonText, LIGHT_TEXT_PRIMARY)

    # Highlights and selection
    palette.setColor(QPalette.ColorRole.Highlight, SAPE_PRIMARY)
    palette.setColor(QPalette.ColorRole.HighlightedText, QColor("#FFFFFF"))

    # Links
    palette.setColor(QPalette.ColorRole.Link, SAPE_PRIMARY)
    palette.setColor(QPalette.ColorRole.LinkVisited, SAPE_PRIMARY_DARK)

    # Disabled
    palette.setColor(
        QPalette.ColorGroup.Disabled, QPalette.ColorRole.WindowText, QColor("#9CA3AF")
    )

    return palette


def create_dark_palette() -> QPalette:
    """Build the dark-theme QPalette. See :func:`create_light_palette`."""
    palette = QPalette()

    # Windows/background
    palette.setColor(QPalette.ColorRole.Window, DARK_BG)
    palette.setColor(QPalette.ColorRole.Base, DARK_SURFACE)
    palette.setColor(QPalette.ColorRole.AlternateBase, DARK_ALT)

    # Text
    palette.setColor(QPalette.ColorRole.WindowText, DARK_TEXT_PRIMARY)
    palette.setColor(QPalette.ColorRole.Text, DARK_TEXT_PRIMARY)
    palette.setColor(QPalette.ColorRole.PlaceholderText, DARK_TEXT_SECONDARY)

    # Buttons
    palette.setColor(QPalette.ColorRole.Button, DARK_SURFACE)
    palette.setColor(QPalette.ColorRole.ButtonText, DARK_TEXT_PRIMARY)

    # Highlights and selection
    palette.setColor(QPalette.ColorRole.Highlight, SAPE_PRIMARY)
    palette.setColor(QPalette.ColorRole.HighlightedText, QColor("#FFFFFF"))

    # Links
    palette.setColor(QPalette.ColorRole.Link, SAPE_ACCENT)
    palette.setColor(QPalette.ColorRole.LinkVisited, SAPE_PRIMARY_DARK)

    # Disabled
    palette.setColor(
        QPalette.ColorGroup.Disabled, QPalette.ColorRole.WindowText, QColor("#6B7280")
    )

    return palette


# Built lazily would require every caller to remember to call the factory;
# f-MCP builds both eagerly at import time and every consumer just reads the
# module-level constant, so d-MCP keeps that shape.
LIGHT_THEME_PALETTE = create_light_palette()
DARK_THEME_PALETTE = create_dark_palette()
