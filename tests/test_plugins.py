from __future__ import annotations

from pwnsh.plugins import PluginManager

RECORDING_PLUGIN = """
from pwnsh.plugins import Plugin

class Demo(Plugin):
    name = "demo"

    def on_load(self, app):
        self.events = []

    def on_connect(self, session):
        self.events.append(("connect", session))

    def on_data(self, session, data):
        self.events.append(("data", data))

    def commands(self):
        return {"demo": lambda app, args: self.events.append(("cmd", tuple(args)))}
"""


def test_load_dispatch_and_command(tmp_path):
    d = tmp_path / "plugins"
    d.mkdir()
    (d / "demo.py").write_text(RECORDING_PLUGIN)

    mgr = PluginManager(app=None, plugins_dir=d)
    assert mgr.load() == ["demo"]
    assert mgr.command("demo") is not None

    inst = mgr.plugins[0]
    mgr.dispatch_connect("SESSION")
    mgr.dispatch_data("SESSION", b"abc")
    mgr.command("demo")(None, ["x", "y"])

    assert ("connect", "SESSION") in inst.events
    assert ("data", b"abc") in inst.events
    assert ("cmd", ("x", "y")) in inst.events


def test_reload_picks_up_edits(tmp_path):
    d = tmp_path / "plugins"
    d.mkdir()
    p = d / "x.py"
    p.write_text("from pwnsh.plugins import Plugin\nclass A(Plugin):\n    name = 'alpha'\n")
    mgr = PluginManager(plugins_dir=d)
    assert mgr.load() == ["alpha"]

    p.write_text("from pwnsh.plugins import Plugin\nclass A(Plugin):\n    name = 'beta'\n")
    assert mgr.reload() == ["beta"]


def test_broken_plugin_is_isolated(tmp_path):
    d = tmp_path / "plugins"
    d.mkdir()
    (d / "bad.py").write_text("raise RuntimeError('boom')\n")
    (d / "good.py").write_text(
        "from pwnsh.plugins import Plugin\nclass G(Plugin):\n    name = 'good'\n"
    )
    mgr = PluginManager(plugins_dir=d)
    assert mgr.load() == ["good"]


def test_no_dir_is_empty(tmp_path):
    mgr = PluginManager(plugins_dir=tmp_path / "does-not-exist")
    assert mgr.load() == []
