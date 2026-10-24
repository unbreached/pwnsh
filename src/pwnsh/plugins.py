"""A small hot-reloadable plugin API.

Drop a ``.py`` file under ``~/.pwnsh/plugins/`` that subclasses :class:`Plugin`
and overrides any of the hooks. ``/reload`` re-reads the directory at runtime,
so you can iterate on a plugin without restarting pwnsh. Every hook runs inside
try/except: a broken plugin is logged and skipped, never fatal.

Example plugin::

    from pwnsh.plugins import Plugin

    class AutoId(Plugin):
        name = "auto-id"

        def on_connect(self, session):
            # runs when a new session lands
            ...

        def commands(self):
            return {"hi": lambda app, args: app.notify("hi " + " ".join(args))}
"""
from __future__ import annotations

import importlib.util
import inspect
import itertools
import logging
from collections.abc import Callable
from pathlib import Path

from .config import DATA_DIR

log = logging.getLogger(__name__)

PLUGINS_DIR = DATA_DIR / "plugins"
_counter = itertools.count()


class Plugin:
    """Base class for pwnsh plugins. All hooks are optional."""

    name: str = ""

    def on_load(self, app) -> None:
        """Called once when the plugin is loaded/reloaded."""

    def on_connect(self, session) -> None:
        """Called when a new session connects."""

    def on_data(self, session, data: bytes) -> None:
        """Called with every chunk of bytes a session receives."""

    def commands(self) -> dict[str, Callable]:
        """Return ``{name: handler(app, args)}`` for extra ``/name`` commands."""
        return {}


class PluginManager:
    """Loads plugins from a directory and fans hooks out to them."""

    def __init__(self, app=None, plugins_dir: Path | None = None) -> None:
        self.app = app
        self.dir = plugins_dir or PLUGINS_DIR
        self.plugins: list[Plugin] = []
        self._commands: dict[str, Callable] = {}

    def load(self) -> list[str]:
        """(Re)load every ``*.py`` in the plugins dir. Returns the plugin names.
        Each file is executed as a fresh module, so calling this again picks up
        on-disk edits - that's the hot reload."""
        self.plugins = []
        self._commands = {}
        if not self.dir.exists():
            return []
        for path in sorted(self.dir.glob("*.py")):
            if path.name.startswith("_"):
                continue
            try:
                self._load_file(path)
            except Exception:
                log.exception("plugin load failed: %s", path)
        return self.names()

    def reload(self) -> list[str]:
        return self.load()

    def _load_file(self, path: Path) -> None:
        # Unique module name each load so Python never serves a cached version.
        mod_name = f"pwnsh_plugin_{path.stem}_{next(_counter)}"
        spec = importlib.util.spec_from_file_location(mod_name, path)
        if spec is None or spec.loader is None:
            return
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        for obj in vars(module).values():
            if (
                inspect.isclass(obj)
                and issubclass(obj, Plugin)
                and obj is not Plugin
                and obj.__module__ == module.__name__
            ):
                inst = obj()
                if not inst.name:
                    inst.name = obj.__name__
                try:
                    inst.on_load(self.app)
                except Exception:
                    log.exception("plugin on_load failed: %s", inst.name)
                self.plugins.append(inst)
                try:
                    for cmd, handler in (inst.commands() or {}).items():
                        self._commands[cmd.lower()] = handler
                except Exception:
                    log.exception("plugin commands() failed: %s", inst.name)

    def names(self) -> list[str]:
        return [p.name for p in self.plugins]

    def dispatch_connect(self, session) -> None:
        for p in self.plugins:
            try:
                p.on_connect(session)
            except Exception:
                log.debug("plugin on_connect failed: %s", p.name, exc_info=True)

    def dispatch_data(self, session, data: bytes) -> None:
        for p in self.plugins:
            try:
                p.on_data(session, data)
            except Exception:
                log.debug("plugin on_data failed: %s", p.name, exc_info=True)

    def command(self, name: str) -> Callable | None:
        return self._commands.get(name.lower())

    def command_names(self) -> list[str]:
        return sorted(self._commands)
