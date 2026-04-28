import unittest

from main import EventProcessor


class FakeRedis:
    def __init__(self):
        self.streams = {}
        self.counters = {}
        self.expirations = {}
        self.keys = {}
        self.acked = []

    async def xgroup_create(self, *_args, **_kwargs):
        return True

    async def ping(self):
        return True

    async def aclose(self):
        return True

    async def xadd(self, stream, fields, **_kwargs):
        self.streams.setdefault(stream, []).append(fields)
        return f"{len(self.streams[stream])}-0"

    async def xack(self, stream, group, *ids):
        self.acked.append((stream, group, list(ids)))
        return len(ids)

    async def xreadgroup(self, *_args, **_kwargs):
        return []

    async def incr(self, key):
        self.counters[key] = self.counters.get(key, 0) + 1
        return self.counters[key]

    async def expire(self, key, ttl):
        self.expirations[key] = ttl
        return True

    async def exists(self, key):
        return 1 if key in self.keys else 0

    async def setex(self, key, ttl, value):
        self.keys[key] = value
        self.expirations[key] = ttl
        return True


class FakeIndices:
    async def exists(self, index):
        return True

    async def create(self, index, body):
        return {"acknowledged": True, "index": index, "body": body}


class FakeElasticsearch:
    def __init__(self, fail_bulk=False):
        self.fail_bulk = fail_bulk
        self.indices = FakeIndices()

    async def close(self):
        return True

    async def bulk(self, **kwargs):
        if self.fail_bulk:
            raise RuntimeError("elasticsearch down")

        operations = kwargs.get("operations") or kwargs.get("body") or []
        items = []
        for idx in range(0, len(operations), 2):
            meta = operations[idx].get("index", {})
            _id = meta.get("_id")
            if str(_id).startswith("fail-es"):
                items.append({"index": {"status": 500}})
            else:
                items.append({"index": {"status": 201}})

        return {"errors": any(item["index"]["status"] >= 400 for item in items), "items": items}


class FakeAcquire:
    def __init__(self, conn):
        self.conn = conn

    async def __aenter__(self):
        return self.conn

    async def __aexit__(self, exc_type, exc, tb):
        return False


class FakePgConn:
    def __init__(self, fail=False):
        self.fail = fail
        self.rows = []

    async def executemany(self, query, rows):
        if self.fail:
            raise RuntimeError("db unavailable")
        self.rows.extend(rows)
        return None


class FakePgPool:
    def __init__(self, fail=False):
        self.conn = FakePgConn(fail=fail)

    def acquire(self):
        return FakeAcquire(self.conn)

    async def close(self):
        return True


class ProcessorTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.redis = FakeRedis()
        self.es = FakeElasticsearch()
        self.pg = FakePgPool()
        self.processor = EventProcessor(
            redis_client=self.redis,
            elasticsearch_client=self.es,
            postgres_pool=self.pg,
        )

    async def test_invalid_event_goes_to_dlq(self):
        messages = [("1-0", {"source": "sensor-a", "timestamp": "2026-01-01T00:00:00Z"})]
        ack_ids = await self.processor._process_batch(messages)

        self.assertEqual(ack_ids, ["1-0"])
        self.assertTrue(self.redis.streams.get("soc_events_dlq"))
        self.assertEqual(self.redis.streams["soc_events_dlq"][0]["failed_stage"], "validation")

    async def test_high_volume_batch_processing(self):
        messages = []
        for i in range(300):
            messages.append(
                (
                    f"{i}-0",
                    {
                        "event_type": "auth_failure",
                        "source": "sensor-a",
                        "source_ip": "203.0.113.10",
                        "timestamp": "2026-01-01T00:00:00Z",
                        "severity": "medium",
                    },
                )
            )

        ack_ids = await self.processor._process_batch(messages)

        self.assertEqual(len(ack_ids), 300)
        self.assertFalse(self.redis.streams.get("soc_events_dlq"))

    async def test_elasticsearch_failure_sends_all_to_dlq(self):
        processor = EventProcessor(
            redis_client=self.redis,
            elasticsearch_client=FakeElasticsearch(fail_bulk=True),
            postgres_pool=self.pg,
        )
        messages = [
            (
                "2-0",
                {
                    "event_type": "suspicious_connection",
                    "source": "sensor-a",
                    "source_ip": "198.51.100.11",
                    "timestamp": "2026-01-01T00:00:00Z",
                },
            )
        ]

        ack_ids = await processor._process_batch(messages)

        self.assertEqual(ack_ids, ["2-0"])
        self.assertEqual(self.redis.streams["soc_events_dlq"][0]["failed_stage"], "elasticsearch")

    async def test_postgres_failure_sends_critical_event_to_dlq(self):
        processor = EventProcessor(
            redis_client=self.redis,
            elasticsearch_client=self.es,
            postgres_pool=FakePgPool(fail=True),
        )
        messages = [
            (
                "3-0",
                {
                    "event_type": "suspicious_connection",
                    "source": "sensor-a",
                    "source_ip": "198.51.100.5",
                    "timestamp": "2026-01-01T00:00:00Z",
                },
            )
        ]

        ack_ids = await processor._process_batch(messages)

        self.assertEqual(ack_ids, ["3-0"])
        self.assertEqual(self.redis.streams["soc_events_dlq"][0]["failed_stage"], "postgresql")

    async def test_bruteforce_correlation_generates_alert(self):
        for i in range(5):
            event = {
                "id": f"id-{i}",
                "event_type": "auth_failure",
                "source": "sensor-a",
                "source_ip": "203.0.113.20",
                "timestamp": "2026-01-01T00:00:00Z",
                "severity": "medium",
                "status": "new",
                "timestamp_dt": None,
            }
            await self.processor._correlate_bruteforce(event)

        stream = self.redis.streams.get("soc_events", [])
        self.assertEqual(len(stream), 1)
        self.assertEqual(stream[0]["event_type"], "ssh_bruteforce_detected")


if __name__ == "__main__":
    unittest.main()
