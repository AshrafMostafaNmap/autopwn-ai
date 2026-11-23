"""System detection and package-manager installs (the step that may use sudo)."""
from __future__ import annotations

import pytest

from autopwn import system
from autopwn.cli import main as cli_main
from autopwn.recon import installer
from autopwn.system import SystemInfo, detect_manager, install_command


def test_os_release_parsing(tmp_path):
    f = tmp_path / "os-release"
    f.write_text('NAME="Ubuntu"\nPRETTY_NAME="Ubuntu 24.04 LTS"\nID=ubuntu\n')
    info = system.detect(os_release=f)
    if info.os == "linux":
        assert info.distro == "Ubuntu 24.04 LTS" and info.distro_id == "ubuntu"
    assert info.summary()


@pytest.mark.parametrize("present,expected", [
    ({"apt-get"}, "apt"), ({"dnf"}, "dnf"), ({"pacman"}, "pacman"), ({"zypper"}, "zypper"),
    ({"apk"}, "apk"), ({"yum"}, "yum"), ({"dnf", "yum"}, "dnf"), (set(), ""),
])
def test_package_manager_detection(present, expected):
    assert detect_manager("linux", which=lambda b: b if b in present else None) == expected


def test_install_commands_per_manager():
    tools = ["nmap", "dig", "openssl"]
    assert install_command(tools, SystemInfo("linux", manager="pacman", sudo=True)) == \
        ["sudo", "pacman", "-S", "--needed", "--noconfirm", "bind", "nmap", "openssl"]
    assert install_command(tools, SystemInfo("linux", manager="apt", root=True)) == \
        ["apt-get", "install", "-y", "dnsutils", "nmap", "openssl"]
    assert install_command(["dig"], SystemInfo("linux", manager="apk", sudo=True))[-1] == "bind-tools"
    assert install_command(["nmap"], SystemInfo("darwin", manager="brew")) == ["brew", "install", "nmap"]
    assert install_command(["nmap"], SystemInfo("linux")) is None
    assert not SystemInfo("linux", manager="apt").can_install_packages        # no root, no sudo
    assert SystemInfo("darwin", manager="brew").can_install_packages


@pytest.fixture
def no_downloads_needed(monkeypatch):
    monkeypatch.setattr(installer, "resolve", lambda n: None if n == "nmap" else f"/usr/bin/{n}")
    info = SystemInfo("linux", distro="Test OS", arch="x86_64", manager="pacman", sudo=True)
    monkeypatch.setattr(system, "detect", lambda *a, **k: info)
    ran: list = []
    monkeypatch.setattr(system, "install_packages", lambda tools, info=None, **k: ran.append(tools) or 0)
    return ran


def _tools(*args):
    try:
        cli_main(["tools", *args])
    except SystemExit as e:
        return e.code
    return 0


def test_tools_install_asks_nothing_without_a_terminal(no_downloads_needed, capsys, monkeypatch):
    monkeypatch.setattr("sys.stdin.isatty", lambda: False)
    assert _tools("install", "nmap") == 0
    out = capsys.readouterr().out
    assert "sudo pacman -S --needed --noconfirm nmap" in out and no_downloads_needed == []
    assert "Test OS" in out


def test_tools_install_yes_runs_the_package_manager(no_downloads_needed, capsys):
    assert _tools("install", "nmap", "--yes") == 0
    assert no_downloads_needed == [["nmap"]] and "nmap installed" in capsys.readouterr().out


def test_tools_install_no_system_never_runs_it(no_downloads_needed, capsys):
    assert _tools("install", "nmap", "--yes", "--no-system") == 0
    assert no_downloads_needed == [] and "skipped" in capsys.readouterr().out


def test_tools_install_rejects_unknown(no_downloads_needed, capsys):
    assert _tools("install", "metasploit") == 2
