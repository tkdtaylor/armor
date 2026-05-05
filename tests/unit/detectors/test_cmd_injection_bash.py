"""Unit tests for the cmd_injection.bash detector."""

import pytest

from armor.detectors.cmd_injection_bash import CmdInjectionBash
from armor.types import Payload, SessionContext


@pytest.fixture
def detector() -> CmdInjectionBash:
    """Create a detector instance for testing."""
    return CmdInjectionBash()


@pytest.fixture
def session_ctx() -> SessionContext:
    """Create a session context for testing."""
    return SessionContext(session_id="test-session")


class TestCmdInjectionBashNonBashTools:
    """Test that non-Bash tools always return pass."""

    def test_non_bash_tool_returns_pass(self, detector: CmdInjectionBash, session_ctx: SessionContext) -> None:
        """TC-012-001: Non-Bash tool should return pass."""
        payload = Payload(tool="Edit", params={"text": "arbitrary content"})
        verdict = detector.check(payload, session_ctx)
        assert verdict.passed
        assert verdict.signal_id is None

    def test_empty_tool_returns_pass(self, detector: CmdInjectionBash, session_ctx: SessionContext) -> None:
        """TC-012-002: Empty tool should return pass."""
        payload = Payload(tool="", params={"command": "rm -rf /"})
        verdict = detector.check(payload, session_ctx)
        assert verdict.passed

    def test_none_tool_returns_pass(self, detector: CmdInjectionBash, session_ctx: SessionContext) -> None:
        """TC-012-003: None tool should return pass."""
        payload = Payload(tool=None, params={"command": "rm -rf /"})
        verdict = detector.check(payload, session_ctx)
        assert verdict.passed


class TestCmdInjectionBashEmptyCommands:
    """Test handling of empty or missing commands."""

    def test_empty_command_returns_pass(self, detector: CmdInjectionBash, session_ctx: SessionContext) -> None:
        """TC-012-004: Empty command should return pass."""
        payload = Payload(tool="Bash", params={"command": ""})
        verdict = detector.check(payload, session_ctx)
        assert verdict.passed
        assert verdict.signal_id is None

    def test_missing_command_key_returns_pass(self, detector: CmdInjectionBash, session_ctx: SessionContext) -> None:
        """TC-012-005: Missing command key should return pass."""
        payload = Payload(tool="Bash", params={"other_key": "value"})
        verdict = detector.check(payload, session_ctx)
        assert verdict.passed

    def test_none_params_returns_pass(self, detector: CmdInjectionBash, session_ctx: SessionContext) -> None:
        """TC-012-006: None params should return pass."""
        payload = Payload(tool="Bash", params=None)
        verdict = detector.check(payload, session_ctx)
        assert verdict.passed

    def test_empty_params_returns_pass(self, detector: CmdInjectionBash, session_ctx: SessionContext) -> None:
        """TC-012-007: Empty params dict should return pass."""
        payload = Payload(tool="Bash", params={})
        verdict = detector.check(payload, session_ctx)
        assert verdict.passed


class TestFilesystemDestructionFamily:
    """Test filesystem destruction patterns."""

    def test_rm_rf_root_blocks(self, detector: CmdInjectionBash, session_ctx: SessionContext) -> None:
        """TC-012-FS-001: rm -rf / should block."""
        payload = Payload(tool="Bash", params={"command": "rm -rf /"})
        verdict = detector.check(payload, session_ctx)
        assert verdict.blocked
        assert verdict.severity == "critical"
        assert verdict.signal_id == "cmd_injection.bash:fs-rm-rf-root"
        assert verdict.details["family"] == "filesystem_destruction"

    def test_rm_rf_home_blocks(self, detector: CmdInjectionBash, session_ctx: SessionContext) -> None:
        """TC-012-FS-002: rm -rf ~ should block."""
        payload = Payload(tool="Bash", params={"command": "rm -rf ~"})
        verdict = detector.check(payload, session_ctx)
        assert verdict.blocked
        assert verdict.signal_id == "cmd_injection.bash:fs-rm-rf-home"

    def test_rm_rf_home_var_blocks(self, detector: CmdInjectionBash, session_ctx: SessionContext) -> None:
        """TC-012-FS-003: rm -rf $HOME should block."""
        payload = Payload(tool="Bash", params={"command": "rm -rf $HOME"})
        verdict = detector.check(payload, session_ctx)
        assert verdict.blocked
        assert verdict.signal_id == "cmd_injection.bash:fs-rm-rf-home-var"

    def test_fork_bomb_blocks(self, detector: CmdInjectionBash, session_ctx: SessionContext) -> None:
        """TC-012-FS-004: Fork bomb should block."""
        payload = Payload(tool="Bash", params={"command": ":(){ :|:& };:"})
        verdict = detector.check(payload, session_ctx)
        assert verdict.blocked
        assert verdict.signal_id == "cmd_injection.bash:fs-fork-bomb"

    def test_dd_zero_dev_blocks(self, detector: CmdInjectionBash, session_ctx: SessionContext) -> None:
        """TC-012-FS-005: dd if=/dev/zero of=/dev/sda should block."""
        payload = Payload(tool="Bash", params={"command": "dd if=/dev/zero of=/dev/sda"})
        verdict = detector.check(payload, session_ctx)
        assert verdict.blocked
        assert verdict.signal_id == "cmd_injection.bash:fs-dd-zero-dev"

    def test_mkfs_blocks(self, detector: CmdInjectionBash, session_ctx: SessionContext) -> None:
        """TC-012-FS-006: mkfs.ext4 /dev/sda1 should block."""
        payload = Payload(tool="Bash", params={"command": "mkfs.ext4 /dev/sda1"})
        verdict = detector.check(payload, session_ctx)
        assert verdict.blocked
        assert verdict.signal_id == "cmd_injection.bash:fs-mkfs"

    def test_rm_rf_node_modules_passes(self, detector: CmdInjectionBash, session_ctx: SessionContext) -> None:
        """TC-012-FS-007: rm -rf node_modules should pass (relative path, legitimate dev)."""
        payload = Payload(tool="Bash", params={"command": "rm -rf node_modules"})
        verdict = detector.check(payload, session_ctx)
        assert verdict.passed
        assert verdict.signal_id is None


class TestCredentialReadFamily:
    """Test credential read patterns."""

    def test_cat_shadow_blocks(self, detector: CmdInjectionBash, session_ctx: SessionContext) -> None:
        """TC-012-CR-001: cat /etc/shadow should block."""
        payload = Payload(tool="Bash", params={"command": "cat /etc/shadow"})
        verdict = detector.check(payload, session_ctx)
        assert verdict.blocked
        assert verdict.signal_id == "cmd_injection.bash:cr-shadow-read"
        assert verdict.details["family"] == "credential_read"

    def test_cat_id_rsa_blocks(self, detector: CmdInjectionBash, session_ctx: SessionContext) -> None:
        """TC-012-CR-002: cat ~/.ssh/id_rsa should block."""
        payload = Payload(tool="Bash", params={"command": "cat ~/.ssh/id_rsa"})
        verdict = detector.check(payload, session_ctx)
        assert verdict.blocked
        assert verdict.signal_id == "cmd_injection.bash:cr-ssh-id-rsa"

    def test_grep_sudoers_blocks(self, detector: CmdInjectionBash, session_ctx: SessionContext) -> None:
        """TC-012-CR-003: grep /etc/sudoers should block."""
        payload = Payload(tool="Bash", params={"command": "grep . /etc/sudoers"})
        verdict = detector.check(payload, session_ctx)
        assert verdict.blocked
        assert verdict.signal_id == "cmd_injection.bash:cr-sudoers-read"

    def test_cat_aws_credentials_blocks(self, detector: CmdInjectionBash, session_ctx: SessionContext) -> None:
        """TC-012-CR-004: cat ~/.aws/credentials should block."""
        payload = Payload(tool="Bash", params={"command": "cat ~/.aws/credentials"})
        verdict = detector.check(payload, session_ctx)
        assert verdict.blocked
        assert verdict.signal_id == "cmd_injection.bash:cr-aws-credentials"

    def test_cat_known_hosts_passes(self, detector: CmdInjectionBash, session_ctx: SessionContext) -> None:
        """TC-012-CR-005: cat ~/.ssh/known_hosts should pass (not a key file)."""
        payload = Payload(tool="Bash", params={"command": "cat ~/.ssh/known_hosts"})
        verdict = detector.check(payload, session_ctx)
        assert verdict.passed


class TestContainerEscapeFamily:
    """Test container escape patterns."""

    def test_mount_cgroup_blocks(self, detector: CmdInjectionBash, session_ctx: SessionContext) -> None:
        """TC-012-CE-001: mount -t cgroup should block."""
        payload = Payload(tool="Bash", params={"command": "mount -t cgroup none /tmp"})
        verdict = detector.check(payload, session_ctx)
        assert verdict.blocked
        assert verdict.signal_id == "cmd_injection.bash:ce-mount-cgroup"
        assert verdict.details["family"] == "container_escape"

    def test_nsenter_blocks(self, detector: CmdInjectionBash, session_ctx: SessionContext) -> None:
        """TC-012-CE-002: nsenter -t 1 -m should block."""
        payload = Payload(tool="Bash", params={"command": "nsenter -t 1 -m bash"})
        verdict = detector.check(payload, session_ctx)
        assert verdict.blocked
        assert verdict.signal_id == "cmd_injection.bash:ce-nsenter"

    def test_unshare_blocks(self, detector: CmdInjectionBash, session_ctx: SessionContext) -> None:
        """TC-012-CE-003: unshare -m should block."""
        payload = Payload(tool="Bash", params={"command": "unshare -m bash"})
        verdict = detector.check(payload, session_ctx)
        assert verdict.blocked
        assert verdict.signal_id == "cmd_injection.bash:ce-unshare"


class TestPrivilegeEscalationFamily:
    """Test privilege escalation patterns."""

    def test_sudo_i_stdin_blocks(self, detector: CmdInjectionBash, session_ctx: SessionContext) -> None:
        """TC-012-PE-001: sudo -i with stdin redirect should block."""
        payload = Payload(tool="Bash", params={"command": "sudo -i <<< 'password'"})
        verdict = detector.check(payload, session_ctx)
        assert verdict.blocked
        assert verdict.signal_id == "cmd_injection.bash:pe-sudo-i-stdin"
        assert verdict.details["family"] == "privilege_escalation"

    def test_chmod_suid_blocks(self, detector: CmdInjectionBash, session_ctx: SessionContext) -> None:
        """TC-012-PE-002: chmod u+s /bin/bash should block."""
        payload = Payload(tool="Bash", params={"command": "chmod u+s /bin/bash"})
        verdict = detector.check(payload, session_ctx)
        assert verdict.blocked
        assert verdict.signal_id == "cmd_injection.bash:pe-chmod-suid"

    def test_setcap_admin_blocks(self, detector: CmdInjectionBash, session_ctx: SessionContext) -> None:
        """TC-012-PE-003: setcap cap_sys_admin should block."""
        payload = Payload(tool="Bash", params={"command": "setcap cap_sys_admin+ep /bin/bash"})
        verdict = detector.check(payload, session_ctx)
        assert verdict.blocked
        assert verdict.signal_id == "cmd_injection.bash:pe-setcap-admin"

    def test_sudo_apt_install_passes(self, detector: CmdInjectionBash, session_ctx: SessionContext) -> None:
        """TC-012-PE-004: sudo apt install should pass (legitimate package install)."""
        payload = Payload(tool="Bash", params={"command": "sudo apt install python3"})
        verdict = detector.check(payload, session_ctx)
        assert verdict.passed

    def test_sudo_e_pytest_passes(self, detector: CmdInjectionBash, session_ctx: SessionContext) -> None:
        """TC-012-PE-005: sudo -E pytest should pass (legitimate tool invocation)."""
        payload = Payload(tool="Bash", params={"command": "sudo -E pytest tests/"})
        verdict = detector.check(payload, session_ctx)
        assert verdict.passed

    def test_chmod_x_passes(self, detector: CmdInjectionBash, session_ctx: SessionContext) -> None:
        """TC-012-PE-006: chmod +x should pass (legitimate executable bit)."""
        payload = Payload(tool="Bash", params={"command": "chmod +x script.sh"})
        verdict = detector.check(payload, session_ctx)
        assert verdict.passed


class TestAdditionalLegitimateCommands:
    """Test additional legitimate commands that must not be blocked."""

    def test_dd_image_write_passes(self, detector: CmdInjectionBash, session_ctx: SessionContext) -> None:
        """TC-012-LEGIT-001: dd if=image.iso of=usb.img should pass (legitimate image write)."""
        payload = Payload(tool="Bash", params={"command": "dd if=image.iso of=usb.img"})
        verdict = detector.check(payload, session_ctx)
        assert verdict.passed

    def test_normal_commands_pass(self, detector: CmdInjectionBash, session_ctx: SessionContext) -> None:
        """TC-012-LEGIT-002: Normal commands should pass."""
        test_cases = [
            "ls -la /tmp",
            "mkdir -p /tmp/test",
            "echo hello",
            "grep pattern file.txt",
            "curl https://example.com",
        ]
        for cmd in test_cases:
            payload = Payload(tool="Bash", params={"command": cmd})
            verdict = detector.check(payload, session_ctx)
            assert verdict.passed, f"Command '{cmd}' should pass but got {verdict}"


class TestSignalIdStability:
    """Test that signal IDs are stable and deterministic."""

    def test_same_input_same_signal(self, detector: CmdInjectionBash, session_ctx: SessionContext) -> None:
        """TC-012-STABILITY-001: Same input should produce same signal ID."""
        payload = Payload(tool="Bash", params={"command": "rm -rf /"})
        verdict1 = detector.check(payload, session_ctx)
        verdict2 = detector.check(payload, session_ctx)
        assert verdict1.signal_id == verdict2.signal_id
        assert verdict1.blocked
        assert verdict2.blocked

    def test_signal_id_format(self, detector: CmdInjectionBash, session_ctx: SessionContext) -> None:
        """TC-012-STABILITY-002: Signal ID should follow cmd_injection.bash:<pattern_id> format."""
        payload = Payload(tool="Bash", params={"command": "rm -rf /"})
        verdict = detector.check(payload, session_ctx)
        assert verdict.signal_id is not None
        assert verdict.signal_id.startswith("cmd_injection.bash:")


class TestDetectorAttributes:
    """Test detector metadata."""

    def test_detector_id(self, detector: CmdInjectionBash) -> None:
        """TC-012-META-001: Detector should have correct id."""
        assert detector.id == "cmd_injection.bash"

    def test_detector_category(self, detector: CmdInjectionBash) -> None:
        """TC-012-META-002: Detector should have correct category."""
        assert detector.category == "tool_abuse"

    def test_detector_cost_tier(self, detector: CmdInjectionBash) -> None:
        """TC-012-META-003: Detector should have correct cost tier."""
        assert detector.cost_tier == "static"


class TestExceptionHandling:
    """Test exception handling in detector."""

    def test_non_string_command_returns_pass(self, detector: CmdInjectionBash, session_ctx: SessionContext) -> None:
        """TC-012-ERROR-001: Non-string command should return pass (no crash)."""
        payload = Payload(tool="Bash", params={"command": 12345})  # type: ignore
        verdict = detector.check(payload, session_ctx)
        assert verdict.passed or verdict.is_error  # Either pass or error, but not crash
