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

"""Splash screen shown while the SAPÉ d-MCP GUI starts up.

Logo-only, theme-matched, frameless and always-on-top — ported from f-MCP
verbatim. The one substantive change is resolving the logo through
``resources.resource_path`` instead of a hand-counted ``Path(__file__)``
chain, so this still works once the application is frozen with PyInstaller
(``sys._MEIPASS``), which f-MCP's three-``.parent`` hop never accounted for.
"""

from __future__ import annotations

import logging

from PyQt6.QtCore import Qt, QTimer
from PyQt6.QtGui import QColor, QPainter, QPixmap
from PyQt6.QtWidgets import QApplication, QSplashScreen

from .resources import resource_path

logger = logging.getLogger(__name__)


class SAPESplashScreen(QSplashScreen):
    """SAPÉ branded splash screen with a logo-only design.

    The source SVG is 3660×920 (a 3.978:1 aspect ratio); ``SCALE_FACTOR``
    keeps the rendered splash to a sensible fraction of screen real estate
    rather than filling it.
    """

    SVG_NATIVE_WIDTH = 3660
    SVG_NATIVE_HEIGHT = 920
    SCALE_FACTOR = 0.2

    def __init__(self, theme: str = "dark", parent_window=None) -> None:
        """Build the composited splash pixmap for the given theme.

        Args:
            theme: "dark" or "light".
            parent_window: unused for positioning (the splash centres itself
                on the primary screen in :meth:`show_and_wait`); kept only so
                callers can pass one without it being an error.

        Raises:
            FileNotFoundError: the themed logo SVG is missing from
                ``gui_resources/logos``.
            RuntimeError: the SVG exists but Qt could not rasterise it.

        Deliberately raises rather than degrading to a text-only splash: a
        missing logo means the resource tree is broken, and a silent
        fallback would hide that until someone noticed the branding was
        wrong, exactly the failure mode ``resource_path`` exists to catch
        early.
        """
        self.theme = theme
        self.parent_window = parent_window
        self._timer: QTimer | None = None

        if theme == "dark":
            self.bg_color = QColor("#0A0C10")
            logo_file = "sape-logo-h-dark.svg"
        else:
            self.bg_color = QColor("#F4F6FA")
            logo_file = "sape-logo-h-light.svg"

        # resource_path() itself raises FileNotFoundError, naming the exact
        # path it tried, if the logo is missing — nothing further to check.
        logo_path = resource_path("logos", logo_file)

        scaled_width = int(self.SVG_NATIVE_WIDTH * self.SCALE_FACTOR)
        scaled_height = int(self.SVG_NATIVE_HEIGHT * self.SCALE_FACTOR)

        pixmap = QPixmap(str(logo_path))
        if pixmap.isNull():
            logger.error("Failed to load SVG logo: %s", logo_path)
            raise RuntimeError(f"Failed to load SVG logo: {logo_path}")

        pixmap = pixmap.scaledToWidth(
            scaled_width, Qt.TransformationMode.SmoothTransformation
        )

        canvas = QPixmap(scaled_width, scaled_height)
        canvas.fill(self.bg_color)

        logo_x = (scaled_width - pixmap.width()) // 2
        logo_y = (scaled_height - pixmap.height()) // 2

        painter = QPainter(canvas)
        painter.setRenderHint(QPainter.RenderHint.SmoothPixmapTransform, True)
        painter.drawPixmap(logo_x, logo_y, pixmap)
        painter.end()

        super().__init__(canvas)
        self.setWindowFlags(
            Qt.WindowType.SplashScreen
            | Qt.WindowType.FramelessWindowHint
            | Qt.WindowType.WindowStaysOnTopHint
        )

        logger.info(
            "Splash screen created with theme: %s (size: %dx%d)",
            theme,
            scaled_width,
            scaled_height,
        )

    def show_and_wait(self, duration_ms: int = 5000) -> QTimer:
        """Centre, show, then auto-close the splash after ``duration_ms``.

        Returns:
            The single-shot :class:`QTimer` driving the auto-close, parented
            to this splash screen so it is not garbage-collected before it
            fires — the exact bug f-MCP's unparented ``QTimer`` had.
        """
        screen_geometry = QApplication.primaryScreen().geometry()
        splash_width = self.width()
        splash_height = self.height()

        x = (screen_geometry.width() - splash_width) // 2 + screen_geometry.x()
        y = (screen_geometry.height() - splash_height) // 2 + screen_geometry.y()

        self.move(x, y)
        logger.info("Splash screen centred on screen at (%d, %d)", x, y)

        self.show()
        QApplication.processEvents()
        logger.info("Splash screen displayed for %dms", duration_ms)

        self._timer = QTimer(self)
        self._timer.setSingleShot(True)
        self._timer.timeout.connect(self.close_splash)
        self._timer.start(duration_ms)

        return self._timer

    def close_splash(self) -> None:
        """Stop the auto-close timer (if still pending) and close the splash."""
        if self._timer is not None:
            self._timer.stop()
            self._timer.deleteLater()
            self._timer = None

        self.close()
        logger.info("Splash screen closed")
