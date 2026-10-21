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

"""Generates ``src/sape_d_mcp/gui/i18n/translations.py``. Never hand-edit that file.

f-MCP's ``translations.py`` is a single 154 KB line — 175 keys times 18
locales, all on one line — precisely because it too is machine-written but
nobody kept the generator that wrote it. Editing a dict literal that long by
hand is how a stray comma silently drops an entry; this script is that
generator, checked in, and the authored strings live here in a readable
shape rather than in the generated file.

Only ``en-US`` and ``es-ES`` are genuinely authored below, one pair per key.
The other 16 locales are seeded with the English string — matching f-MCP's
translation coverage and the honesty about it already in Stack.md and the
README. Run this script whenever a key is added, changed or removed:

    python tools/generate_translations.py

The locale list itself is *not* restated here: it is read from
``LanguageRegistry.LANGUAGES``, the single source of truth, so the generator
and the registry cannot drift apart the way f-MCP's
``TRANSLATIONS["header.logo"]``-derived language list drifted from its own
registry (see ``get_supported_languages()`` in the generated module).
"""

from __future__ import annotations

import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
SRC_DIR = REPO_ROOT / "src"
sys.path.insert(0, str(SRC_DIR))

from sape_d_mcp.language_registry import LanguageRegistry  # noqa: E402

OUTPUT_PATH = SRC_DIR / "sape_d_mcp" / "gui" / "i18n" / "translations.py"

# All 18 locale codes, in registry order (not sorted — sorting would produce
# a diff-noisy reordering every time a locale is added).
LOCALE_CODES: list[str] = list(LanguageRegistry.LANGUAGES.keys())

HEADER = '''# SAPÉ d-MCP — controlled database access with granular permissions for LLMs
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

"""Translation table and lookup for the 18 supported locales.

GENERATED FILE — do not hand-edit. Produced by
``tools/generate_translations.py`` from the authored en-US/es-ES pairs kept
there; every other locale is seeded with the English string. Re-run that
script to change anything here.
"""

from __future__ import annotations

from sape_d_mcp.language_registry import LanguageRegistry
'''

FOOTER = '''

def translate(key: str, language: str = "en-US") -> str:
    """Translate ``key`` into ``language``.

    Falls back to en-US if the language is not carried for that key, and to
    the key itself if the key is not in the table at all — a missing
    translation should render as a visibly wrong (but harmless) string in
    the UI, not raise and take the page down with it.
    """
    entry = TRANSLATIONS.get(key)
    if entry is None:
        return key
    return entry.get(language, entry.get("en-US", key))


def get_supported_languages() -> dict[str, str]:
    """Return ``{code: native_name}`` for every registered locale.

    Built from :class:`LanguageRegistry.LANGUAGES`, not from a translation
    key's own set of language keys — f-MCP's ``get_supported_languages()``
    read the list off ``TRANSLATIONS["header.logo"]`` and explicitly excluded
    ``en-US``, so the language switcher itself was unable to offer the very
    language most of the catalogue is written in.
    """
    return {code: LanguageRegistry.get_native_name(code) for code in LanguageRegistry.LANGUAGES}
'''


def _entry(en: str, es: str) -> dict[str, str]:
    """Build one key's per-locale dict: es-ES authored, the rest seeded from en-US."""
    return {code: (es if code == "es-ES" else en) for code in LOCALE_CODES}


# ---------------------------------------------------------------------------
# Authored strings, one namespace per dict, (english, spanish) pairs.
# Namespaces mirror the d-MCP page set (Stack.md / DEVELOPMENT-PLAN.md):
# connections, permissions, confirmation, logs, settings, legal, help, about,
# sidebar, header, status_bar, common, window. `confirmation` is the stage-7
# destructive-operation modal, not a sidebar page. f-MCP's unused `page.*`
# namespace is deliberately not carried over.
# ---------------------------------------------------------------------------

COMMON = {
    "add": ("Add", "Añadir"),
    "cancel": ("Cancel", "Cancelar"),
    "close": ("Close", "Cerrar"),
    "confirm": ("Confirm", "Confirmar"),
    "delete": ("Delete", "Eliminar"),
    "edit": ("Edit", "Editar"),
    "error": ("Error", "Error"),
    "loading": ("Loading…", "Cargando…"),
    "no": ("No", "No"),
    "ok": ("OK", "Aceptar"),
    "refresh": ("Refresh", "Actualizar"),
    "save": ("Save", "Guardar"),
    "search": ("Search", "Buscar"),
    "success": ("Success", "Éxito"),
    "test": ("Test", "Probar"),
    "warning": ("Warning", "Advertencia"),
    "yes": ("Yes", "Sí"),
}

HEADER_NS = {
    "language_selector": ("Language", "Idioma"),
    "product_name": ("d-MCP (Data MCP)", "d-MCP (Data MCP)"),
    "theme_toggle": ("Toggle theme", "Cambiar tema"),
}

SIDEBAR = {
    "about": ("About", "Acerca de"),
    "connections": ("Connections", "Conexiones"),
    "help": ("Help", "Ayuda"),
    "legal": ("Legal", "Legal"),
    "logs": ("Logs", "Registros"),
    "permissions": ("Permissions", "Permisos"),
    "settings": ("Settings", "Configuración"),
}

WINDOW = {
    "title": ("SAPÉ d-MCP", "SAPÉ d-MCP"),
}

STATUS_BAR = {
    "error_title": ("MCP server error", "Error del servidor MCP"),
    "port_info": ("Port {port}", "Puerto {port}"),
    "port_info_alt": ("No port assigned", "Sin puerto asignado"),
    "service_running": ("MCP server running", "Servidor MCP en ejecución"),
    "service_stopped": ("MCP server stopped", "Servidor MCP detenido"),
    "start_button": ("Start server", "Iniciar servidor"),
    "stop_button": ("Stop server", "Detener servidor"),
}

CONNECTIONS = {
    "browse_button": ('Browse…', 'Examinar…'),
    "browse_dialog_title": ('Select a SQLite database file', 'Seleccionar un archivo de base de datos SQLite'),
    "credential_backend_label": ('Passwords are stored in: {backend}', 'Las contraseñas se guardan en: {backend}'),
    "delete_confirm_message": ('Delete this connection profile? Its permission rules and audit entries are removed with it.', '¿Eliminar este perfil de conexión? Sus reglas de permisos y entradas de auditoría se eliminan con él.'),
    "delete_confirm_title": ("Delete connection", "Eliminar conexión"),
    "driver_mysql_connector_python": ('mysql-connector-python', 'mysql-connector-python'),
    "driver_psycopg": ('psycopg', 'psycopg'),
    "driver_pymssql": ('pymssql (self-contained)', 'pymssql (autocontenido)'),
    "driver_pymysql": ('PyMySQL (pure Python)', 'PyMySQL (Python puro)'),
    "driver_pyodbc": ('pyodbc (needs ODBC Driver 18)', 'pyodbc (requiere ODBC Driver 18)'),
    "driver_sqlite3": ('sqlite3 (standard library)', 'sqlite3 (biblioteca estándar)'),
    "edit_connection_title": ("Edit connection", "Editar conexión"),
    "engine_mssql": ('MS-SQL Server', 'MS-SQL Server'),
    "engine_mysql": ('MySQL / MariaDB', 'MySQL / MariaDB'),
    "engine_postgresql": ('PostgreSQL', 'PostgreSQL'),
    "engine_sqlite": ('SQLite', 'SQLite'),
    "field_database": ("Database", "Base de datos"),
    "field_display_name": ("Display name", "Nombre visible"),
    "field_host": ("Host", "Host"),
    "field_password": ("Password", "Contraseña"),
    "field_port": ("Port", "Puerto"),
    "field_username": ("Username", "Usuario"),
    "help_title": ("About connections", "Acerca de las conexiones"),
    "keyring_note": ('The password is stored in the operating system keyring, never in connections.db.', 'La contraseña se guarda en el llavero del sistema operativo, nunca en connections.db.'),
    "master_password_label": ('Master password', 'Contraseña maestra'),
    "new_button": ("New connection", "Nueva conexión"),
    "new_connection_title": ("New connection", "Nueva conexión"),
    "no_connections": ("No connections defined yet", "Aún no hay conexiones definidas"),
    "password_unchanged_hint": ('Leave blank to keep the current password', 'Déjelo en blanco para conservar la contraseña actual'),
    "subtitle": ('Database connection profiles. Passwords go to the operating system keyring, never to connections.db.', 'Perfiles de conexión a bases de datos. Las contraseñas van al llavero del sistema operativo, nunca a connections.db.'),
    "table_header_actions": ("Actions", "Acciones"),
    "table_header_created": ("Created", "Creado"),
    "table_header_database": ("Database", "Base de datos"),
    "table_header_driver": ("Driver", "Controlador"),
    "table_header_engine": ("Engine", "Motor"),
    "table_header_host": ("Host", "Host"),
    "table_header_name": ("Name", "Nombre"),
    "table_header_status": ('Status', 'Estado'),
    "table_header_username": ('User', 'Usuario'),
    "test_button": ("Test connection", "Probar conexión"),
    "test_error_message": ("The connection could not be established.", "No se pudo establecer la conexión."),
    "test_error_title": ("Connection failed", "Conexión fallida"),
    "test_success_message": ('Connected. Server version {version}, {latency} ms.', 'Conectado. Versión del servidor {version}, {latency} ms.'),
    "test_success_title": ("Connection successful", "Conexión correcta"),
    "test_tooltip": ('Test this connection', 'Probar esta conexión'),
    "title": ("Connections", "Conexiones"),
    "validation_error_message": ('Fill in every required field before saving.', 'Rellene todos los campos obligatorios antes de guardar.'),
    "validation_error_title": ('Incomplete connection', 'Conexión incompleta'),
    "vault_locked_message": ('No operating system keyring is available, so passwords are kept in an encrypted vault. Enter the master password to unlock it.', 'No hay ningún llavero del sistema operativo disponible, así que las contraseñas se guardan en una bóveda cifrada. Introduzca la contraseña maestra para desbloquearla.'),
    "vault_locked_title": ('Credential store locked', 'Almacén de credenciales bloqueado'),
    "wrong_master_password_message": ('That master password did not unlock the vault.', 'Esa contraseña maestra no ha desbloqueado la bóveda.'),

    # --- Connection-setup redesign (DESIGN-CONNECTION-SETUP.md) ---------
    # The combined engine+driver picker. field_driver/field_engine (two
    # separate row labels) were dropped when the two combos were merged
    # into this one — nothing shows them any more.
    "field_engine_driver": ("Engine and driver", "Motor y controlador"),
    "driver_group_mssql": ("MS-SQL Server", "MS-SQL Server"),
    "driver_group_postgresql": ("PostgreSQL", "PostgreSQL"),
    "driver_group_mysql": ("MySQL / MariaDB", "MySQL / MariaDB"),
    "driver_group_sqlite": ("SQLite", "SQLite"),
    "driver_status_installed": ("✓ installed", "✓ instalado"),
    "driver_status_not_installed": ("✗ not installed", "✗ no instalado"),
    "driver_requirement_pip": ("Not installed yet. Install with: pip install {requirement}",
                               "Aún no está instalado. Instálelo con: pip install {requirement}"),
    "driver_requirement_pyodbc_windows": (
        "It also needs the Microsoft ODBC Driver 18 for SQL Server, a separate install "
        "requiring administrator rights (winget install --id Microsoft.msodbcsql.18 -e). "
        "Where that is not available, choose the pymssql driver instead: it needs nothing "
        "beyond pip.",
        "También necesita el controlador Microsoft ODBC Driver 18 para SQL Server, una "
        "instalación aparte que requiere derechos de administrador (winget install --id "
        "Microsoft.msodbcsql.18 -e). Si no dispone de esos derechos, elija el controlador "
        "pymssql: no necesita nada más que pip."),
    "driver_requirement_pyodbc_other": (
        "It also needs the Microsoft ODBC Driver 18 for SQL Server installed separately for "
        "this platform. Where that is inconvenient, choose the pymssql driver instead: it "
        "needs nothing beyond pip.",
        "También necesita el controlador Microsoft ODBC Driver 18 para SQL Server, instalado "
        "aparte para esta plataforma. Si eso resulta incómodo, elija el controlador pymssql: "
        "no necesita nada más que pip."),
    # Authentication mode.
    "field_auth_mode": ("Authentication", "Autenticación"),
    "auth_mode_password": ("User name and password", "Nombre de usuario y contraseña"),
    "auth_mode_integrated": ("Windows / system authentication", "Autenticación de Windows / del sistema"),
    "auth_mode_none": ("None (file permissions)", "Ninguna (permisos del archivo)"),
    "auth_sqlite_note": (
        "A SQLite database is a file. Access is controlled by the file's own permissions, "
        "so there is no user name and no password.",
        "Una base de datos SQLite es un archivo. El acceso lo controlan los permisos del "
        "propio archivo, así que no hay nombre de usuario ni contraseña."),
    "auth_integrated_identity_windows": (
        "The identity used will be the Windows account running this application.",
        "La identidad utilizada será la cuenta de Windows que ejecuta esta aplicación."),
    "auth_integrated_identity_other": (
        "System authentication on Linux and macOS uses Kerberos. You need a valid ticket — "
        "run kinit — and a krb5.conf that names your realm. Without one the server reports "
        "a login failure for the user NT AUTHORITY\\ANONYMOUS LOGON.",
        "La autenticación del sistema en Linux y macOS usa Kerberos. Necesita un ticket "
        "válido — ejecute kinit — y un krb5.conf que indique su dominio (realm). Sin ellos "
        "el servidor devuelve un fallo de inicio de sesión para el usuario "
        "NT AUTHORITY\\ANONYMOUS LOGON."),
    "auth_none_sqlite_only": (
        "'None' is only offered for SQLite; every other engine needs some form of "
        "authentication.",
        "«Ninguna» solo se ofrece para SQLite; el resto de motores necesita alguna forma de "
        "autenticación."),
    "auth_integrated_unsupported_pymssql": (
        "The pymssql driver cannot use Windows (trusted) authentication — FreeTDS has no "
        "way to present your Windows account to the server, and the attempt fails with "
        "error 20009, which looks like a network problem but is not one. Choose the pyodbc "
        "driver for system authentication, or keep pymssql and sign in with a SQL Server "
        "user name and password.",
        "El controlador pymssql no puede usar la autenticación de Windows (de confianza) — "
        "FreeTDS no tiene forma de presentar su cuenta de Windows al servidor, y el intento "
        "falla con el error 20009, que parece un problema de red sin serlo. Elija el "
        "controlador pyodbc para la autenticación del sistema, o mantenga pymssql e "
        "identifíquese con un nombre de usuario y contraseña de SQL Server."),
    "auth_integrated_unsupported_mysql": (
        "MySQL and MariaDB have no system-authentication mode d-MCP can use. The "
        "auth_socket plugin works only over a local Unix socket, and the Windows plugin "
        "ships only with MySQL Enterprise. Use a user name and password.",
        "MySQL y MariaDB no tienen ningún modo de autenticación del sistema que d-MCP pueda "
        "usar. El complemento auth_socket solo funciona sobre un socket Unix local, y el "
        "complemento de Windows solo se distribuye con MySQL Enterprise. Use un nombre de "
        "usuario y una contraseña."),
    # MS-SQL server / instance / port split.
    "field_instance": ("Instance", "Instancia"),
    "resolve_port_button": ("Resolve port", "Resolver puerto"),
    "resolve_port_tooltip": (
        "Ask this host's SQL Server Browser which port the named instance is using",
        "Preguntar al explorador de SQL Server de este host qué puerto usa la instancia "
        "indicada"),
    "resolve_port_searching": ("Asking the SQL Server Browser…", "Preguntando al explorador de SQL Server…"),
    "resolve_port_no_result": (
        "No SQL Server instance answered on that host.",
        "Ninguna instancia de SQL Server respondió en ese host."),
    "resolve_port_result": (
        "Found instance {instance} on port {port}.",
        "Instancia {instance} encontrada en el puerto {port}."),
    "split_for_me_button": ("Split it for me", "Separarlo por mí"),
    "host_parsed_note": (
        "Understood as server \"{server}\"{instance_part}{port_part}.",
        "Entendido como servidor «{server}»{instance_part}{port_part}."),
    "host_parsed_instance_part": (", instance \"{instance}\"", ", instancia «{instance}»"),
    "host_parsed_port_part": (", port {port}", ", puerto {port}"),
    "host_parse_error_label": (
        "That host could not be understood: {detail}",
        "No se pudo interpretar ese host: {detail}"),
    "port_or_instance_hint": (
        "Give a port, or a named instance for the SQL Server Browser to resolve.",
        "Indique un puerto, o una instancia con nombre para que la resuelva el explorador "
        "de SQL Server."),
    # TLS, for the certificate a driver will not trust on its own.
    "trust_server_certificate": (
        "Trust the server certificate",
        "Confiar en el certificado del servidor"),
    "trust_server_certificate_note": (
        "The connection stays encrypted, but the server's identity is not checked. Tick "
        "this only for a server you control, on a network you trust — typically an "
        "internal SQL Server with a self-signed certificate.",
        "La conexión sigue cifrada, pero no se comprueba la identidad del servidor. "
        "Marque esto solo para un servidor que usted controle, en una red de confianza: "
        "normalmente un SQL Server interno con un certificado autofirmado."),
    # Editable database combo.
    "find_databases_button": ("Find databases", "Buscar bases de datos"),
    "find_databases_running": ("Looking for databases…", "Buscando bases de datos…"),
    "database_editable_note": (
        "This list shows only the databases this account is allowed to see. You can type "
        "a name that is not listed.",
        "Esta lista solo muestra las bases de datos que esta cuenta puede ver. Puede "
        "escribir un nombre que no aparezca en ella."),
    "database_system_suffix": (" (system)", " (sistema)"),
    "find_databases_error_title": ("Could not list databases", "No se pudieron listar las bases de datos"),
    # Review marker for a migrated, ambiguous host.
    "needs_review_tooltip": (
        "This profile's host was carried over as free text and may combine a server, an "
        "instance and a port in one field. Open it and use “Split it for me”.",
        "El host de este perfil se conservó como texto libre y puede combinar servidor, "
        "instancia y puerto en un solo campo. Ábralo y use «Separarlo por mí»."),
    "table_header_auth": ("Auth", "Autenticación"),
    "table_header_review": ("Review", "Revisar"),
    # Discovery entry point on the page toolbar.
    "discover_button": ("Discover…", "Descubrir…"),
}

DISCOVERY = {
    "title": ("Discover a database server", "Descubrir un servidor de base de datos"),
    "subtitle": (
        "Look for a database server on this computer, or, on request, on the local network.",
        "Busque un servidor de base de datos en este equipo o, si lo pide, en la red local."),
    "search_local_button": ("Search this computer", "Buscar en este equipo"),
    "search_network_button": ("Search the local network", "Buscar en la red local"),
    "search_folder_button": ("Search a folder…", "Buscar en una carpeta…"),
    "folder_dialog_title": (
        "Choose a folder to search for SQLite files",
        "Elija una carpeta donde buscar archivos SQLite"),
    "use_button": ("Use this", "Usar este"),
    "section_confirmed": ("Found on this computer", "Encontrado en este equipo"),
    "section_network": (
        "Reported by the network — not verified",
        "Comunicado por la red — no verificado"),
    "confidence_confirmed": ("confirmed", "confirmado"),
    "confidence_inferred": ("inferred", "inferido"),
    "confidence_reported": ("reported", "comunicado"),
    "confidence_inferred_tooltip": (
        "Something answered on this port. The engine is guessed from the port number "
        "alone — it has not been verified against the registry, a service name or a "
        "protocol header.",
        "Algo respondió en este puerto. El motor se supone solo a partir del número de "
        "puerto — no se ha verificado con el registro, un nombre de servicio o una "
        "cabecera de protocolo."),
    "origin_windows_registry": ("Windows registry", "Registro de Windows"),
    "origin_windows_service": ("Windows service", "Servicio de Windows"),
    "origin_odbc_dsn": ("ODBC DSN", "DSN de ODBC"),
    "origin_listening_port": ("Answered on {host}:{port}", "Respondió en {host}:{port}"),
    "origin_sqlite_file": ("SQLite file", "Archivo SQLite"),
    "origin_sql_browser": (
        "SQL Server Browser reply", "Respuesta del explorador de SQL Server"),
    "dynamic_port_note": (
        "dynamic port — it changes when the service restarts",
        "puerto dinámico: cambia al reiniciar el servicio"),
    "network_confirm_title": ("Search the local network?", "¿Buscar en la red local?"),
    "network_confirm_message": (
        "d-MCP will send one small UDP message to the local network's broadcast address, "
        "port 1434, asking any Microsoft SQL Server to identify itself. It sends no user "
        "name and no password. Some corporate networks log or block this kind of message. "
        "It will wait about 2 seconds for replies.",
        "d-MCP enviará un pequeño mensaje UDP a la dirección de difusión (broadcast) de la "
        "red local, puerto 1434, pidiendo a cualquier Microsoft SQL Server que se "
        "identifique. No envía nombre de usuario ni contraseña. Algunas redes corporativas "
        "registran o bloquean este tipo de mensaje. Esperará unos 2 segundos las "
        "respuestas."),
    "network_confirm_search": ("Search", "Buscar"),
    "searching_local": ("Searching this computer…", "Buscando en este equipo…"),
    "searching_network": ("Searching the local network…", "Buscando en la red local…"),
    "no_candidates": (
        "Nothing found yet. Try “Search the local network”, or “Search a folder…”.",
        "Aún no se ha encontrado nada. Pruebe «Buscar en la red local» o «Buscar en una "
        "carpeta…»."),
    "notes_label": ("Notes:", "Notas:"),
    "failed_title": ("Discovery failed", "Fallo en la búsqueda"),
    "table_header_label": ("Candidate", "Candidato"),
    "table_header_origin": ("Origin", "Origen"),
    "table_header_confidence": ("Confidence", "Confianza"),
}

PERMISSIONS = {
    "action_assign_group": ('Assign group', 'Asignar grupo'),
    "action_assign_role": ('Assign role', 'Asignar rol'),
    "action_create": ('Create', 'Crear'),
    "action_create_group": ('Create group', 'Crear grupo'),
    "action_create_role": ('Create role', 'Crear rol'),
    "action_create_tooltip": ("Create the object", "Crear el objeto"),
    "action_create_user": ('Create user', 'Crear usuario'),
    "action_delete": ('Delete', 'Eliminar'),
    "action_delete_tooltip": ("Delete rows", "Eliminar filas"),
    "action_drop": ('Drop', 'Eliminar (drop)'),
    "action_drop_tooltip": ("Drop the object", "Eliminar el objeto (drop)"),
    "action_edit": ('Edit', 'Editar'),
    "action_edit_tooltip": ("Edit the definition", "Editar la definición"),
    "action_execute_tooltip": ("Execute", "Ejecutar"),
    "action_forbidden_tooltip": (
        "Never granted. d-MCP cannot destroy an object or replace a routine "
        "body, whatever a rule says.",
        "Nunca se concede. d-MCP no puede destruir un objeto ni reemplazar el "
        "cuerpo de una rutina, sea cual sea la regla."),
    "action_grant_tooltip": ("Grant to others", "Conceder a otros"),
    "action_insert": ('Insert', 'Insertar'),
    "action_insert_tooltip": ("Insert rows", "Insertar filas"),
    "action_list": ('List', 'Listar'),
    "action_list_tooltip": ("List objects", "Listar objetos"),
    "action_read_catalogue": ('Read catalogue', 'Leer catálogo'),
    "action_read_definition": ('Read definition', 'Leer definición'),
    "action_read_definition_tooltip": ("Read definition", "Leer definición"),
    "action_read_structure": ('Read structure', 'Leer estructura'),
    "action_read_structure_tooltip": ("Read structure", "Leer estructura"),
    "action_run_query": ('Run read query', 'Ejecutar consulta de lectura'),
    "action_select": ('Select', 'Consultar'),
    "action_select_tooltip": ("Read rows", "Leer filas"),
    "action_update": ('Update', 'Actualizar'),
    "action_update_tooltip": ("Update rows", "Actualizar filas"),
    "allow_label": ("Allow", "Permitir"),
    "category_ddl": ('Structure operations', 'Operaciones de estructura'),
    "category_delete": ('Delete operations', 'Operaciones de eliminación'),
    "category_execute": ('Execute operations', 'Operaciones de ejecución'),
    "category_grant": ('Security operations', 'Operaciones de seguridad'),
    "category_insert": ('Insert operations', 'Operaciones de inserción'),
    "category_read": ('Read operations', 'Operaciones de lectura'),
    "category_update": ('Update operations', 'Operaciones de actualización'),
    "connection_selector_label": ("Connection", "Conexión"),
    "delete_button_tooltip": ("Delete rule", "Eliminar regla"),
    "delete_confirm_message": ("This will permanently remove the rule.", "Esto eliminará la regla de forma permanente."),
    "delete_confirm_title": ("Delete rule", "Eliminar regla"),
    "delete_error_message": ("The permission rule could not be deleted.", "No se pudo eliminar la regla de permiso."),
    "delete_error_title": ("Could not delete rule", "No se pudo eliminar la regla"),
    "delete_success_message": ("The permission rule was deleted.", "La regla de permiso fue eliminada."),
    "delete_success_title": ("Rule deleted", "Regla eliminada"),
    "deny_label": ("Deny", "Denegar"),
    "edit_button_tooltip": ("Edit rule", "Editar regla"),
    "edit_rule_title": ("Edit permission rule", "Editar regla de permiso"),
    "explorer_empty": ('Select a connection to browse its schema', 'Seleccione una conexión para explorar su esquema'),
    "explorer_no_objects": ('This connection has no objects to browse.', 'Esta conexión no tiene objetos que explorar.'),
    "explorer_title": ("Schema browser", "Explorador de esquema"),
    "field_actions": ('Actions', 'Acciones'),
    "field_name_pattern": ('Name pattern', 'Patrón de nombre'),
    "field_object_type": ('Object type', 'Tipo de objeto'),
    "field_rule_name": ('Name', 'Nombre'),
    "field_schema_pattern": ('Schema pattern', 'Patrón de esquema'),
    "field_targets": ('Objects this rule covers', 'Objetos que cubre esta regla'),
    "grant_error_message": (
        'The permission rule was not saved. Check the values you entered and try again.',
        'La regla de permiso no fue guardada. Compruebe los valores introducidos e inténtelo de nuevo.',
    ),
    "grant_error_title": ("Could not save rule", "No se pudo guardar la regla"),
    "grant_success_message": (
        'The permission rule was saved and now applies to the objects it lists. '
        'Rules are deny by default: an object no rule covers is refused.',
        'La regla de permiso fue guardada y ya se aplica a los objetos que enumera. '
        'Las reglas deniegan por defecto: un objeto que ninguna regla cubre se rechaza.',
    ),
    "grant_success_title": ("Rule saved", "Regla guardada"),
    "add_target_button": ('Add object…', 'Añadir objeto…'),
    "remove_target_button": ('Remove', 'Quitar'),
    "add_target_title": ('Add an object to this rule', 'Añadir un objeto a esta regla'),
    "targets_empty": (
        'No objects yet. Add at least one — a rule that covers nothing grants nothing.',
        'Todavía no hay objetos. Añade al menos uno: una regla que no cubre nada no concede nada.',
    ),
    "mixed_types_title": ('Several kinds of object selected', 'Selección de varios tipos de objeto'),
    "mixed_types_message": (
        'This selection covers {summary}. Actions differ between tables, views, functions '
        'and procedures, so one rule covers one kind — you will be asked to set the '
        'actions for each kind in turn.',
        'Esta selección abarca {summary}. Las acciones difieren entre tablas, vistas, '
        'funciones y procedimientos, por lo que una regla cubre un solo tipo: se te pedirá '
        'que definas las acciones de cada tipo por separado.',
    ),
    "selection_empty_title": ('Nothing to add', 'Nada que añadir'),
    "selection_empty_message": (
        'Select one or more objects in the schema browser first. Schema and object-type '
        'headings are skipped, and so are objects d-MCP cannot address.',
        'Selecciona antes uno o más objetos en el explorador de esquemas. Los encabezados '
        'de esquema y de tipo se omiten, igual que los objetos que d-MCP no puede '
        'direccionar.',
    ),
    "new_rule_from_selection_button": ('New rule from selection', 'Nueva regla desde la selección'),
    "new_rule_name_placeholder": ('Customers, rpt_*, or * for every object', 'Customers, rpt_*, o * para todos los objetos'),
    "new_rule_schema_placeholder": ('dbo, sales, or * for every schema', 'dbo, sales, o * para todos los esquemas'),
    "new_rule_title": ("New permission rule", "Nueva regla de permiso"),
    "no_rules": ("No permission rules defined yet", "Aún no hay reglas de permisos definidas"),
    "object_type_database": ('Database and security', 'Base de datos y seguridad'),
    "object_type_function": ('Function', 'Función'),
    "object_type_procedure": ('Stored procedure', 'Procedimiento almacenado'),
    "object_type_table": ('Table', 'Tabla'),
    "object_type_view": ('View', 'Vista'),
    "refresh_button": ("Refresh", "Actualizar"),
    "rule_name_placeholder": (
        'Optional — helps you tell rules apart in the list below',
        'Opcional: ayuda a distinguir las reglas en la lista de abajo',
    ),
    "subtitle": ('Rules are deny by default: an object no rule covers is refused.', 'Las reglas deniegan por defecto: un objeto que ninguna regla cubre se rechaza.'),
    "table_header_actions": ("Actions", "Acciones"),
    "table_header_created": ("Created", "Creado"),
    "table_header_edit": ('Edit', 'Editar'),
    "table_header_effect": ("Effect", "Efecto"),
    "table_header_object_type": ("Object type", "Tipo de objeto"),
    # One Objects column since schema version 2 -- a rule names a collection, so
    # neither "Schema" nor "Name pattern" has a single value to head a column with.
    "table_header_objects": ("Objects", "Objetos"),
    # Leads the row, schema version 3: the operator's own label for the rule, so the
    # list says what a rule is *for* without opening it. Rendered as "—" when a rule
    # has none (permissions_page._build_rule_table), never left blank.
    "table_header_rule_name": ("Name", "Nombre"),
    "table_header_user": ("User", "Usuario"),
    "title": ("Permissions", "Permisos"),
    "validation_error_message": ('A rule needs a schema pattern, an object type and a name pattern.', 'Una regla necesita un patrón de esquema, un tipo de objeto y un patrón de nombre.'),
    "validation_error_title": ("Invalid rule", "Regla no válida"),
}

# The destructive-operation confirmation modal (DESIGN-MCP-TOOLS.md §8.2). Its
# connection name, SQL statement and impact estimate are shown verbatim, as data
# rather than as translatable chrome — only the surrounding labels, the two button
# captions and the countdown live here.
CONFIRMATION = {
    "approve_button": ("Approve", "Aprobar"),
    "dialog_title": ("Confirm destructive operation", "Confirmar operación destructiva"),
    "field_connection": ("Connection", "Conexión"),
    "field_impact": ("Estimated impact", "Impacto estimado"),
    "field_operation": ("Operation", "Operación"),
    "field_reason": ("Reason (optional)", "Motivo (opcional)"),
    "field_reason_placeholder": (
        "Why is this being refused? Shown to whoever retries the call.",
        "¿Por qué se rechaza? Se muestra a quien reintente la llamada.",
    ),
    "field_statement": ("SQL statement", "Sentencia SQL"),
    "impact_unknown": (
        "Impact could not be estimated — you are approving this blind.",
        "No se pudo estimar el impacto: está aprobando esto a ciegas.",
    ),
    "refuse_button": ("Refuse", "Rechazar"),
    "time_remaining": ("Time remaining: {seconds}s", "Tiempo restante: {seconds}s"),
    "warning_no_drop_if_exists": (
        ("This server is too old for a conditional drop, so the object is dropped "
        "outright. If it does not exist, the statement fails rather than doing nothing."),
        ("Este servidor es demasiado antiguo para un borrado condicional, así que el objeto "
        "se elimina sin más. Si no existe, la sentencia falla en vez de no hacer nada."),
    ),
    "warning_non_atomic_routine_replace": (
        ("This engine cannot replace a routine in one step: the old one is dropped and the "
        "new one created. If the second step fails, the routine is left absent."),
        ("Este motor no puede reemplazar una rutina en un solo paso: se elimina la antigua y "
        "se crea la nueva. Si el segundo paso falla, la rutina queda ausente."),
    ),
    "warning_banner_subtitle": (
        "This action cannot be undone. Review the statement below before deciding.",
        "Esta acción no se puede deshacer. Revise la sentencia siguiente antes de decidir.",
    ),
    "warning_banner_title": ("Destructive operation requested", "Se ha solicitado una operación destructiva"),
}

LOGS = {
    "clear_button": ("Clear", "Limpiar"),
    "decision_all": ('All decisions', 'Todas las decisiones'),
    "decision_allowed": ('Allowed', 'Permitido'),
    "decision_denied": ('Denied', 'Denegado'),
    "decision_denied_tooltip": (
        "A permission rule refused this: the rules said no.",
        "Una regla de permisos rechazó esto: las reglas dijeron que no.",
    ),
    "decision_error": ('Error', 'Error'),
    "decision_refused": ('Refused', 'Rechazado'),
    "decision_refused_tooltip": (
        "A human declined the confirmation, or nobody was watching to approve it.",
        "Una persona rechazó la confirmación, o no había nadie para aprobarla.",
    ),
    "denied_only_label": ("Denied only", "Solo denegados"),
    "denied_only_tooltip": (
        "Show only rows a permission rule refused.",
        "Mostrar solo las filas que una regla de permisos rechazó.",
    ),
    "export_button": ("Export", "Exportar"),
    "export_csv_header_matched_rule": ("Matched rule", "Regla aplicada"),
    "export_csv_header_session": ("Session", "Sesión"),
    "export_dialog_filter": ("CSV files (*.csv)", "Archivos CSV (*.csv)"),
    "export_dialog_title": ("Export logs", "Exportar registros"),
    "export_error_message": ("The logs could not be exported.", "No se pudieron exportar los registros."),
    "export_error_title": ("Export failed", "Error al exportar"),
    "export_success_message": ("The logs were exported successfully.", "Los registros se exportaron correctamente."),
    "export_success_title": ("Export complete", "Exportación completa"),
    "filter_placeholder": ("Filter…", "Filtrar…"),
    "no_logs": ("No log entries yet", "Aún no hay entradas de registro"),
    "subtitle": ('Every tool call, per database — allowed, denied or failed.', 'Cada llamada de herramienta, por base de datos — permitida, denegada o fallida.'),
    "tab_deleted_named": ("{name} (deleted)", "{name} (eliminada)"),
    "tab_deleted_unnamed": ("Connection #{id} (deleted)", "Conexión n.º {id} (eliminada)"),
    "tab_system": ("System", "Sistema"),
    "tab_system_tooltip": (
        "Tool calls that touch no specific connection, such as list-connections.",
        "Llamadas a herramientas que no afectan a ninguna conexión concreta, como list-connections.",
    ),
    "table_header_connection": ("Connection", "Conexión"),
    "table_header_decision": ("Decision", "Decisión"),
    "table_header_duration": ("Duration (ms)", "Duración (ms)"),
    "table_header_error": ("Error", "Error"),
    "table_header_result": ("Result", "Resultado"),
    "table_header_rows": ('Rows', 'Filas'),
    "table_header_timestamp": ("Timestamp", "Marca de tiempo"),
    "table_header_tool": ("Tool", "Herramienta"),
    "title": ("Logs", "Registros"),
}

SETTINGS = {
    "about_group": ("About", "Acerca de"),
    "about_text": ('SAPÉ d-MCP — controlled database access with granular permissions for LLMs.', 'SAPÉ d-MCP — acceso controlado a bases de datos con permisos granulares para LLM.'),
    "appearance_group": ("Appearance", "Apariencia"),
    "config_desc": ("Merge this into your MCP client's configuration file. Do not replace the file, or you will drop the other servers you have configured.", 'Combine esto con el archivo de configuración de su cliente MCP. No sustituya el archivo, o perderá los demás servidores que tenga configurados.'),
    "config_group": ("MCP client configuration", "Configuración del cliente MCP"),
    "config_unavailable": ('The client configuration could not be generated.', 'No se ha podido generar la configuración del cliente.'),
    "copy_button": ('Copy', 'Copiar'),
    "copy_button_tooltip": (
        'Copy the client configuration to the clipboard without opening the setup wizard',
        'Copiar la configuración del cliente al portapapeles sin abrir el asistente de configuración',
    ),
    "copy_success": ('Copied!', '¡Copiado!'),
    "dark_theme": ("Dark", "Oscuro"),
    "data_audit_label": ('Access audit log', 'Registro de auditoría de accesos'),
    "data_config_label": ('GUI configuration', 'Configuración de la interfaz'),
    "data_connections_label": ('Connection profiles', 'Perfiles de conexión'),
    "data_group": ("Data", "Datos"),
    "data_permissions_label": ('Permission rules', 'Reglas de permisos'),
    "light_theme": ("Light", "Claro"),
    "minimize_on_startup_label": ("Minimise on startup", "Minimizar al iniciar"),
    "mockup_group": ('Mockup', 'Maqueta'),
    "server_desc": (
        ("The MCP server runs inside this application over streamable-http, on the "
        "first free port between 8089 and 8098 — chosen automatically so it does "
        "not collide with a running SAPÉ f-MCP. Start and stop it from the status "
        "bar."),
        ("El servidor MCP se ejecuta dentro de esta aplicación mediante "
        "streamable-http, en el primer puerto libre entre el 8089 y el 8098, "
        "elegido automáticamente para no coincidir con una instancia de SAPÉ "
        "f-MCP en ejecución. Inícielo y deténgalo desde la barra de estado."),
    ),
    "server_group": ('Server', 'Servidor'),
    "setup_mcp_button": ("Set up MCP configuration", "Configurar MCP"),
    "setup_mcp_button_tooltip": (
        "Detect the installation and open the MCP client setup wizard",
        "Detectar la instalación y abrir el asistente de configuración del cliente MCP",
    ),
    "show_sample_data_desc": ('Fill the pages with fictitious data so the layout can be judged. Off by default, so a fresh installation opens on the real, empty first-run screen.', 'Rellena las páginas con datos ficticios para poder valorar la maquetación. Desactivado por defecto, para que una instalación nueva se abra en la pantalla real y vacía de primer uso.'),
    "show_sample_data_label": ("Show sample data in empty pages", "Mostrar datos de ejemplo en páginas vacías"),
    "startup_group": ("Startup", "Inicio"),
    "subtitle": ("Application preferences", "Preferencias de la aplicación"),
    "theme_desc": ("Choose the interface theme", "Elija el tema de la interfaz"),
    "title": ("Settings", "Configuración"),
}

# The MCP client configuration wizard (dialogs/mcp_config_dialog.py), opened from the
# Settings page's "Set up MCP configuration" button. f-MCP defect 7 left its whole copy
# of this dialog untranslated; every string it shows lives here instead.
MCP_CONFIG = {
    "config_desc": (
        ("Copy this JSON and merge it into your MCP client's configuration file — do "
        "not replace the file, or you will lose any other servers already "
        "configured.\n\nLocation: {path}"),
        ("Copie este JSON y combínelo con el archivo de configuración de su cliente "
        "MCP — no sustituya el archivo, o perderá los demás servidores ya "
        "configurados.\n\nUbicación: {path}"),
    ),
    "config_group": ("MCP configuration (mcpServers)", "Configuración MCP (mcpServers)"),
    "dialog_title": ("Connect an MCP client", "Conectar un cliente MCP"),
    "entry_point_label": ("Entry point:", "Punto de entrada:"),
    "error_label": ("Error:", "Error:"),
    "install_type_label": ("Installation type:", "Tipo de instalación:"),
    "instructions_group": ("Setup instructions", "Instrucciones de configuración"),
    "python_label": ("Python interpreter:", "Intérprete de Python:"),
    "status_group": ("Installation detection", "Detección de la instalación"),
    "status_invalid_message": (
        "No working installation could be detected.",
        "No se pudo detectar una instalación funcional.",
    ),
    "status_valid_message": (
        "A working installation was detected.",
        "Se detectó una instalación funcional.",
    ),
    "test_button": ("Test command", "Probar comando"),
    "test_exception_title": ("Test failed", "Prueba fallida"),
    "test_failed_message": (
        "The command exited with code {code}:\n\n{error}",
        "El comando finalizó con el código {code}:\n\n{error}",
    ),
    "test_failed_title": ("Command failed", "El comando falló"),
    "test_invalid_message": (
        "The installation could not be detected, so there is nothing to test.",
        "No se pudo detectar la instalación, así que no hay nada que probar.",
    ),
    "test_invalid_title": ("Installation not ready", "Instalación no lista"),
    "test_success_message": ("SAPÉ d-MCP responded:\n\n{output}", "SAPÉ d-MCP respondió:\n\n{output}"),
    "test_success_title": ("Command works", "El comando funciona"),
    "test_timeout_message": (
        "The command took too long to respond.",
        "El comando tardó demasiado en responder.",
    ),
    "test_timeout_title": ("Command timed out", "El comando agotó el tiempo de espera"),
    "venv_label": ("Virtual environment:", "Entorno virtual:"),
}

LEGAL = {
    "accept": (
        "I have read and understood this document",
        "He leído y entendido este documento",
    ),
    "data": ("Data protection", "Protección de datos"),
    "data_desc": ("What SAPÉ d-MCP stores and where", "Qué almacena SAPÉ d-MCP y dónde"),
    "disclaimer": ("Disclaimer", "Descargo de responsabilidad"),
    "disclaimer_desc": ("Warranty and liability disclaimer", "Descargo de garantía y responsabilidad"),
    "doc_not_available_message": ("This document could not be loaded.", "No se pudo cargar este documento."),
    "doc_not_available_title": ("Document unavailable", "Documento no disponible"),
    "documents": ("Documents", "Documentos"),
    "legal_readme": ("Legal overview", "Resumen legal"),
    "legal_readme_desc": (
        "A plain-language summary of the above",
        "Un resumen en lenguaje sencillo de lo anterior",
    ),
    "license": ("Licence", "Licencia"),
    "license_desc": (
        "The GNU General Public License, version 3",
        "La Licencia Pública General de GNU, versión 3",
    ),
    "read": ("Read", "Leer"),
    "subtitle": ("Licence and policy documents", "Documentos de licencia y política"),
    "title": ("Legal", "Legal"),
    "warning": (
        "These documents are provided in English only; translations carry no legal force.",
        "Estos documentos se proporcionan solo en inglés; las traducciones no tienen validez legal.",
    ),
}

HELP = {
    "faq": ("Frequently asked questions", "Preguntas frecuentes"),
    "faq_text": (
        "See the README for the current list of known limitations.",
        "Consulte el README para conocer la lista actual de limitaciones conocidas.",
    ),
    "mcp": ("Connecting an MCP client", "Conectar un cliente MCP"),
    "mcp_text": (
        "Use the Settings page to generate the configuration snippet your client needs.",
        "Use la página de Configuración para generar el fragmento de configuración que su cliente necesita.",
    ),
    "permission": ("Understanding permissions", "Cómo funcionan los permisos"),
    "permission_text": (
        ("A rule matches a schema pattern, an object type and a name pattern; "
        "the most specific match wins."),
        ("Una regla coincide con un patrón de esquema, un tipo de objeto y un "
        "patrón de nombre; la coincidencia más específica gana."),
    ),
    "started": ("Getting started", "Primeros pasos"),
    "started_text": (
        ("Create a connection, define permission rules, then point your MCP "
        "client at this server."),
        ("Cree una conexión, defina reglas de permisos y luego apunte su "
        "cliente MCP a este servidor."),
    ),
    "subtitle": ("Getting started with SAPÉ d-MCP", "Primeros pasos con SAPÉ d-MCP"),
    "title": ("Help", "Ayuda"),
}

ABOUT = {
    "author": ("Created by SAPÉ smart bud", "Creado por SAPÉ smart bud"),
    "benefit_auditability": ("Auditability", "Auditabilidad"),
    "benefit_auditability_desc": (
        "Full transparency over which tool calls touched which objects",
        "Transparencia total sobre qué llamadas de herramienta tocaron qué objetos",
    ),
    "benefit_performance": ("Performance", "Rendimiento"),
    "benefit_performance_desc": (
        "Connection pooling and lightweight introspection",
        "Agrupación de conexiones e introspección ligera",
    ),
    "benefit_security": ("Security", "Seguridad"),
    "benefit_security_desc": (
        "Default-deny permission rules, per object and per action",
        "Reglas de permisos por defecto denegadas, por objeto y por acción",
    ),
    "copyright": ("© 2026 Luciano Arrezze", "© 2026 Luciano Arrezze"),
    "mission_desc": (
        ("Modern AI systems need structured database access. SAPÉ enforces "
        "permissions, prevents unauthorised access and logs every operation "
        "for compliance and debugging."),
        ("Los sistemas de IA modernos necesitan acceso estructurado a bases "
        "de datos. SAPÉ aplica los permisos, evita el acceso no autorizado "
        "y registra cada operación para cumplimiento y depuración."),
    ),
    "mission_title": ("Mission", "Misión"),
    "sapebud_link": ("sapebud.com", "sapebud.com"),
    "sapebud_link_tooltip": (
        "Visit the SAPÉ smart bud website",
        "Visite el sitio web de SAPÉ smart bud",
    ),
    "tagline": (
        "Controlled database access with granular permissions for LLMs",
        "Acceso controlado a bases de datos con permisos granulares para LLMs",
    ),
    "tech_design": ("Custom SAPÉ design system", "Sistema de diseño SAPÉ personalizado"),
    "tech_mcp": ("Model Context Protocol", "Protocolo de contexto de modelo"),
    "tech_pyqt": ("PyQt6 — Modern cross-platform GUI", "PyQt6 — GUI moderna multiplataforma"),
    "tech_python": ("Python 3.10+", "Python 3.10+"),
    "tech_sqlite": (
        "SQLite — Permissions, connections and audit storage",
        "SQLite — Almacenamiento de permisos, conexiones y auditoría",
    ),
    "tech_title": ("Built with", "Construido con"),
    "title": ("About SAPÉ d-MCP", "Acerca de SAPÉ d-MCP"),
    "why_desc": (
        ("An LLM with unrestricted database access is a liability; SAPÉ "
        "makes the access explicit, auditable and revocable."),
        ("Un LLM con acceso irrestricto a la base de datos es un riesgo; "
        "SAPÉ hace que el acceso sea explícito, auditable y revocable."),
    ),
    "why_title": ("Why it matters", "Por qué importa"),
}

NAMESPACES: dict[str, dict[str, tuple[str, str]]] = {
    "common": COMMON,
    "header": HEADER_NS,
    "sidebar": SIDEBAR,
    "window": WINDOW,
    "status_bar": STATUS_BAR,
    "connections": CONNECTIONS,
    "discovery": DISCOVERY,
    "permissions": PERMISSIONS,
    "confirmation": CONFIRMATION,
    "logs": LOGS,
    "settings": SETTINGS,
    "mcp_config": MCP_CONFIG,
    "legal": LEGAL,
    "help": HELP,
    "about": ABOUT,
}


def build_translations() -> dict[str, dict[str, str]]:
    """Flatten the namespaced (english, spanish) pairs into the generated shape."""
    table: dict[str, dict[str, str]] = {}
    for namespace, entries in NAMESPACES.items():
        for name, (en, es) in entries.items():
            table[f"{namespace}.{name}"] = _entry(en, es)
    return table


def render(table: dict[str, dict[str, str]]) -> str:
    """Render the generated module source.

    One key per block and one locale per line — greppable, unlike f-MCP's
    single 154 KB line, and a diff on this file shows exactly which key and
    which locale changed.
    """
    lines = [HEADER, "TRANSLATIONS: dict[str, dict[str, str]] = {"]
    for key in sorted(table):
        lines.append(f"    {key!r}: {{")
        for code in LOCALE_CODES:
            lines.append(f"        {code!r}: {table[key][code]!r},")
        lines.append("    },")
    lines.append("}")
    lines.append(FOOTER)
    return "\n".join(lines)


def main() -> None:
    table = build_translations()
    OUTPUT_PATH.write_text(render(table), encoding="utf-8")
    print(f"Wrote {len(table)} keys x {len(LOCALE_CODES)} locales to {OUTPUT_PATH}")


if __name__ == "__main__":
    main()
