import asyncio
import tempfile
import unittest
from pathlib import Path

from collector import AgentConfig, EventPublisher


class FakeTransport:
    def __init__(self, fail_times: int = 0, fail_with: Exception | None = None):
        self.fail_times = fail_times
        self.fail_with = fail_with or ConnectionError("backend offline")
        self.sent: list[dict] = []

    async def send(self, event: dict) -> None:
        if self.fail_times > 0:
            self.fail_times -= 1
            raise self.fail_with
        self.sent.append(event)

    async def close(self) -> None:
        return


class PublisherResilienceTests(unittest.IsolatedAsyncioTestCase):
    def _config(self, buffer_dir: Path, retries: int = 2) -> AgentConfig:
        return AgentConfig(
            backend_transport="redis",
            backend_url="redis://localhost:6379",
            api_token=None,
            redis_stream="soc_events",
            request_timeout=0.01,
            max_retries=retries,
            backoff_base=0.001,
            backoff_max=0.01,
            resend_interval=3600,
            resend_batch_size=1000,
            buffer_dir=buffer_dir,
            buffer_max_files=10000,
            dedup_window_seconds=1,
            dedup_max_items=5000,
            log_files=[],
            check_interval=1,
            anonymize_logs=False,
            position_state_file=buffer_dir / "positions.json",
        )

    async def test_backend_offline_uses_local_queue_and_resend(self):
        with tempfile.TemporaryDirectory() as tmp:
            config = self._config(Path(tmp), retries=1)
            publisher = EventPublisher(config)
            fake = FakeTransport(fail_times=1)
            publisher.transport = fake
            await publisher.initialize()

            delivered = await publisher.publish(
                {
                    "event_type": "auth_failure",
                    "source_ip": "10.10.10.10",
                    "severity": "medium",
                }
            )
            self.assertFalse(delivered)
            self.assertEqual(publisher.buffer.size(), 1)

            fake.fail_times = 0
            flushed = await publisher.flush_buffer()
            self.assertEqual(flushed, 1)
            self.assertEqual(publisher.buffer.size(), 0)
            self.assertEqual(len(fake.sent), 1)

            await publisher.close()

    async def test_timeout_is_retried_and_buffered(self):
        with tempfile.TemporaryDirectory() as tmp:
            config = self._config(Path(tmp), retries=2)
            publisher = EventPublisher(config)
            timeout_transport = FakeTransport(fail_times=10, fail_with=TimeoutError("timeout"))
            publisher.transport = timeout_transport
            await publisher.initialize()

            delivered = await publisher.publish(
                {
                    "event_type": "suspicious_connection",
                    "source_ip": "192.168.1.10",
                    "severity": "critical",
                }
            )
            self.assertFalse(delivered)
            self.assertEqual(publisher.buffer.size(), 1)

            await publisher.close()

    async def test_invalid_event_is_normalized_to_schema(self):
        with tempfile.TemporaryDirectory() as tmp:
            config = self._config(Path(tmp), retries=1)
            publisher = EventPublisher(config)
            fake = FakeTransport()
            publisher.transport = fake
            await publisher.initialize()

            delivered = await publisher.publish({"event_type": "", "source_ip": "invalid-ip", "severity": "BAD"})
            self.assertTrue(delivered)
            self.assertEqual(len(fake.sent), 1)

            event = fake.sent[0]
            self.assertEqual(event["event_type"], "unknown")
            self.assertEqual(event["severity"], "low")
            self.assertEqual(event["source_ip"], "0.0.0.0")
            self.assertIn("timestamp", event)

            await publisher.close()

    async def test_high_volume_events(self):
        with tempfile.TemporaryDirectory() as tmp:
            config = self._config(Path(tmp), retries=1)
            publisher = EventPublisher(config)
            fake = FakeTransport()
            publisher.transport = fake
            await publisher.initialize()

            total = 1200
            for i in range(total):
                delivered = await publisher.publish(
                    {
                        "event_type": "system_log",
                        "source_ip": "127.0.0.1",
                        "severity": "low",
                        "raw_log": f"line-{i}",
                    }
                )
                self.assertTrue(delivered)

            self.assertEqual(len(fake.sent), total)
            self.assertEqual(publisher.buffer.size(), 0)

            await publisher.close()


if __name__ == "__main__":
    unittest.main()
