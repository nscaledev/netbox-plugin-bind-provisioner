from __future__ import annotations

import importlib.util
import socket
import sys
import types
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch


ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"


def _install_stub_modules() -> dict[str, types.ModuleType]:
    """Install lightweight stubs so plugin modules can be unit-tested without a full NetBox stack."""
    saved: dict[str, types.ModuleType] = {}

    django_mod = types.ModuleType("django")
    django_conf = types.ModuleType("django.conf")
    django_conf.settings = MagicMock()
    django_core = types.ModuleType("django.core")
    django_core_mgmt = types.ModuleType("django.core.management")
    django_core_mgmt_base = types.ModuleType("django.core.management.base")

    class FakeBaseCommand:
        pass

    django_core_mgmt_base.BaseCommand = FakeBaseCommand

    django_db = types.ModuleType("django.db")
    django_db.close_old_connections = MagicMock(name="close_old_connections")
    django_db.connection = MagicMock(name="connection")

    netbox_dns = types.ModuleType("netbox_dns")
    netbox_dns_models = types.ModuleType("netbox_dns.models")
    netbox_dns_models.Zone = MagicMock()
    netbox_dns_models.Record = MagicMock()
    netbox_dns_models.View = MagicMock()
    netbox_dns_choices = types.ModuleType("netbox_dns.choices")
    netbox_dns_choices.ZoneStatusChoices = MagicMock(STATUS_ACTIVE="active")
    netbox_dns_choices.RecordStatusChoices = MagicMock(STATUS_ACTIVE="active")

    plugin_pkg = types.ModuleType("netbox_plugin_bind_provisioner")
    plugin_pkg.__path__ = [str(SRC / "netbox_plugin_bind_provisioner")]
    plugin_models = types.ModuleType("netbox_plugin_bind_provisioner.models")
    plugin_models.IntegerKeyValueSetting = MagicMock()
    plugin_models.CatalogZoneMemberIdentifier = MagicMock()

    dns_mod = MagicMock(name="dns")
    dns_mod.rdatatype.SOA = 6
    dns_mod.rdatatype.AXFR = 252
    dns_mod.rdatatype.to_text.return_value = "SOA"

    modules = {
        "dns": dns_mod,
        "dns.query": dns_mod.query,
        "dns.message": dns_mod.message,
        "dns.tsigkeyring": dns_mod.tsigkeyring,
        "dns.name": dns_mod.name,
        "dns.zone": dns_mod.zone,
        "dns.rdatatype": dns_mod.rdatatype,
        "dns.rdataclass": dns_mod.rdataclass,
        "dns.rdtypes": dns_mod.rdtypes,
        "dns.exception": dns_mod.exception,
        "dns.renderer": dns_mod.renderer,
        "django": django_mod,
        "django.conf": django_conf,
        "django.core": django_core,
        "django.core.management": django_core_mgmt,
        "django.core.management.base": django_core_mgmt_base,
        "django.db": django_db,
        "netbox_dns": netbox_dns,
        "netbox_dns.models": netbox_dns_models,
        "netbox_dns.choices": netbox_dns_choices,
        "netbox_plugin_bind_provisioner": plugin_pkg,
        "netbox_plugin_bind_provisioner.models": plugin_models,
    }
    for name, mod in modules.items():
        saved[name] = sys.modules.get(name)
        sys.modules[name] = mod

    if str(SRC) not in sys.path:
        sys.path.insert(0, str(SRC))

    return saved


class ConnectionLifecycleTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls._saved_modules = _install_stub_modules()
        from netbox_plugin_bind_provisioner.service.endpoint import request_handler

        cls.request_handler = request_handler
        cmd_path = (
            SRC
            / "netbox_plugin_bind_provisioner"
            / "management"
            / "commands"
            / "dns-transfer-endpoint.py"
        )
        spec = importlib.util.spec_from_file_location(
            "netbox_plugin_bind_provisioner.management.commands.dns_transfer_endpoint",
            cmd_path,
        )
        assert spec and spec.loader
        cmd_mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(cmd_mod)
        cls.cmd_mod = cmd_mod

    def setUp(self) -> None:
        self.request_handler.close_old_connections.reset_mock()
        self.request_handler.connection.reset_mock()

    def _build_valid_query_handler(self) -> object:
        handler = object.__new__(self.request_handler.DNSBaseRequestHandler)
        handler.client_address = ("127.0.0.1", 53000)
        handler.server = MagicMock()
        nb_view = MagicMock()
        nb_view.name = "Nscale Prod"
        handler.server.tsig_view_map = {"key.": nb_view}

        fake_question = MagicMock()
        fake_question.name.to_text.return_value = "example.com."
        fake_question.rdtype = self.request_handler.dns.rdatatype.SOA

        fake_query = MagicMock()
        fake_query.question = [fake_question]
        fake_query.had_tsig = True
        fake_query.keyname.canonicalize.return_value.to_text.return_value = "key."
        self.request_handler.dns.message.from_wire.return_value = fake_query
        return handler

    def test_handle_dns_query_calls_close_old_connections_before_db_lookup(self) -> None:
        events: list[str] = []
        self.request_handler.close_old_connections.side_effect = (
            lambda: events.append("close_old_connections")
        )
        handler = self._build_valid_query_handler()
        handler._getZoneFromNB = MagicMock(
            side_effect=lambda dname, view_name: (events.append("db_lookup"), None)[1]
        )
        handler._deny_request = MagicMock()

        handler._handle_dns_query(b"wire")

        self.assertEqual(
            events,
            ["close_old_connections", "db_lookup"],
        )

    def test_tcp_handler_closes_connection_on_disconnect_and_timeout(self) -> None:
        fake_sock = MagicMock()
        fake_sock.recv.side_effect = socket.timeout("timed out")

        handler = object.__new__(self.request_handler.TCPRequestHandler)
        handler.request = fake_sock
        handler.client_address = ("127.0.0.1", 53001)

        handler.handle()

        self.request_handler.connection.close.assert_called_once_with()

    def test_management_command_closes_startup_db_connection(self) -> None:
        cmd = self.cmd_mod.Command()
        cmd.load_settings = MagicMock()
        cmd.load_tsig_key_settings = MagicMock()
        cmd.keyring = {"k": "v"}
        cmd.tsig_view_map = {"k": "view"}

        with (
            patch.object(self.cmd_mod.catzm, "init"),
            patch.object(self.cmd_mod, "UDPDNSServer"),
            patch.object(self.cmd_mod, "TCPDNSServer") as mock_tcp_cls,
            patch.object(self.cmd_mod.threading, "Thread"),
        ):
            cmd.handle(port=5353, address="0.0.0.0")

        self.cmd_mod.connection.close.assert_called_once_with()
        mock_tcp_cls.return_value.serve_forever.assert_called_once_with()


if __name__ == "__main__":
    unittest.main()
