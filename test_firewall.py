import unittest
from unittest.mock import patch, MagicMock
import subprocess
from firewall import block_ip, get_ext, is_ip_blocked, manual_block, blocked_ips


class TestFirewall(unittest.TestCase):

    @patch("subprocess.run")
    def test_is_ip_blocked(self, mock_subprocess):
        mock_subprocess.return_value.stdout = "target_ip"
        result = is_ip_blocked("target_ip")
        self.assertTrue(result)

        mock_subprocess.return_value.stdout = ""
        result = is_ip_blocked("other_ip")
        self.assertFalse(result)

    def test_get_ext(self):
        url = "http://example.com/file.png"
        result = get_ext(url)
        self.assertEqual(result, ".png")

    @patch("subprocess.run")
    def test_block_ip(self, mock_subprocess):
        ip = "192.168.1.1"
        block_ip(ip)
        mock_subprocess.assert_called_with(["iptables", "-A", "INPUT", "-s", ip, "-j", "DROP"])
        self.assertIn(ip, blocked_ips)

    @patch("subprocess.run")
    @patch("firewall.ip_entry")
    @patch("tkinter.messagebox.showinfo")
    def test_manual_block(self, mock_messagebox, mock_ip_entry, mock_subprocess):
        mock_ip_entry.get.return_value = "192.168.1.1"
        manual_block()
        mock_messagebox.assert_called_with("Firewall", "Blocked IP: 192.168.1.1")
        self.assertIn("192.168.1.1", blocked_ips)


if __name__ == "__main__":
    unittest.main()

