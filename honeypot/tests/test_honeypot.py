import asyncio
import unittest
from datetime import datetime

import main


class CapturingHoneypot(main.HoneypotServer):
    def __init__(self):
        super().__init__()
        self.captured_events = []

    async def publish_event(self, event_type: str, payload: dict):
        event = self._build_event(event_type, payload)
        self.captured_events.append(event)


class HoneypotTests(unittest.IsolatedAsyncioTestCase):
    async def test_login_invalido_evento_normalizado(self):
        hp = CapturingHoneypot()

        await hp.register_login_attempt(
            source_ip="203.0.113.15",
            source_port=50221,
            username="root",
            password="wrong",
            success=False,
            connection_id="conn-1",
            attempt_number_connection=1,
        )

        self.assertEqual(len(hp.captured_events), 1)
        ev = hp.captured_events[0]
        self.assertEqual(ev["event_type"], "honeypot_login")
        self.assertEqual(ev["severity"], "high")
        self.assertFalse(ev["success"])
        self.assertEqual(ev["source_ip"], "203.0.113.15")
        self.assertEqual(ev["attempt_count_ip"], 1)
        self.assertIsNotNone(ev["@timestamp"])
        datetime.fromisoformat(ev["@timestamp"].replace("Z", "+00:00"))

    async def test_bruteforce_e_contador_por_ip(self):
        hp = CapturingHoneypot()

        # 4 falhas e 1 sucesso
        for idx in range(1, 5):
            await hp.register_login_attempt(
                source_ip="198.51.100.20",
                source_port=51000 + idx,
                username="admin",
                password=f"bad{idx}",
                success=False,
                connection_id="conn-2",
                attempt_number_connection=idx,
            )

        await hp.register_login_attempt(
            source_ip="198.51.100.20",
            source_port=51005,
            username="admin",
            password="admin123",
            success=True,
            connection_id="conn-2",
            attempt_number_connection=5,
        )

        self.assertEqual(hp.ip_counters["198.51.100.20"]["attempts"], 5)
        self.assertEqual(hp.ip_counters["198.51.100.20"]["failed_logins"], 4)
        self.assertEqual(hp.ip_counters["198.51.100.20"]["successful_logins"], 1)
        self.assertEqual(hp.captured_events[-1]["attempt_count_ip"], 5)

    async def test_execucao_comando_capturada_sem_execucao_real(self):
        hp = CapturingHoneypot()
        session = main.HoneypotSession("192.0.2.44", 44001, "root")
        session.password = "root"
        hp.active_sessions[session.session_id] = session

        response = await hp.handle_command(session.session_id, "touch /tmp/pwned")
        self.assertIn("command not found", response)
        self.assertEqual(len(session.commands_executed), 1)
        self.assertEqual(session.commands_executed[0]["command"], "touch /tmp/pwned")

        ev = hp.captured_events[-1]
        self.assertEqual(ev["event_type"], "honeypot_command")
        self.assertEqual(ev["severity"], "high")

    async def test_alta_carga_conexoes(self):
        hp = CapturingHoneypot()

        async def do_attempt(i: int):
            await hp.register_login_attempt(
                source_ip=f"203.0.113.{(i % 20) + 1}",
                source_port=52000 + i,
                username="root",
                password="nope",
                success=False,
                connection_id=f"conn-{i}",
                attempt_number_connection=1,
            )

        await asyncio.gather(*[do_attempt(i) for i in range(200)])

        self.assertEqual(len(hp.captured_events), 200)
        total_attempts = sum(v["attempts"] for v in hp.ip_counters.values())
        self.assertEqual(total_attempts, 200)

    async def test_limite_tentativas_por_conexao(self):
        hp = CapturingHoneypot()
        ssh_conn = main.HoneypotSSHServerSession(hp)
        ssh_conn.source_ip = "203.0.113.9"
        ssh_conn.source_port = 4444

        for _ in range(main.MAX_AUTH_ATTEMPTS_PER_CONNECTION):
            self.assertTrue(ssh_conn.password_auth_supported())
            ssh_conn.validate_password("root", "bad")

        self.assertFalse(ssh_conn.password_auth_supported())


if __name__ == "__main__":
    unittest.main()
