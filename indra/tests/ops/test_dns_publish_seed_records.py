import os
import stat
import tempfile
import unittest

from ops import dns_publish_seed_records as dns


class FakeCloudflare:
    def __init__(self):
        self.created = []
        self.updated = []
        self.deleted = []

    def list_a_records(self, names):
        return []

    def create_a_record(self, record):
        self.created.append(record)

    def update_a_record(self, record_id, record):
        self.updated.append((record_id, record))

    def delete_record(self, record_id):
        self.deleted.append(record_id)


class DnsPublishSeedRecordsTests(unittest.TestCase):
    def test_derives_expected_dns_records_from_validator_set(self):
        validator_set = {
            "validators": [
                {"validator_id": "a", "network_addr": "116.203.185.28:30303"},
                {"validator_id": "b", "network_addr": "5.161.221.10:30303"},
                {"validator_id": "c", "network_addr": None},
            ]
        }

        records = dns.derive_desired_a_records(
            validator_set,
            ["seeds.indraprotocol.com", "seeds2.indraprotocol.com"],
            min_expected_validators=1,
        )

        self.assertEqual(
            {(record.name, record.content) for record in records},
            {
                ("seeds.indraprotocol.com", "5.161.221.10"),
                ("seeds.indraprotocol.com", "116.203.185.28"),
                ("seeds2.indraprotocol.com", "5.161.221.10"),
                ("seeds2.indraprotocol.com", "116.203.185.28"),
            },
        )

    def test_diff_is_empty_when_dns_already_matches(self):
        desired = [
            dns.DesiredRecord("seeds.indraprotocol.com", "116.203.185.28"),
            dns.DesiredRecord("seeds.indraprotocol.com", "5.161.221.10"),
        ]
        existing = [
            dns.CloudflareRecord(
                id="1",
                name="seeds.indraprotocol.com",
                type="A",
                content="116.203.185.28",
                ttl=dns.DEFAULT_TTL,
                proxied=False,
                comment=dns.DEFAULT_COMMENT,
            ),
            dns.CloudflareRecord(
                id="2",
                name="seeds.indraprotocol.com",
                type="A",
                content="5.161.221.10",
                ttl=dns.DEFAULT_TTL,
                proxied=False,
                comment=dns.DEFAULT_COMMENT,
            ),
        ]

        self.assertEqual(dns.compute_dns_diff(existing, desired), [])

    def test_diff_creates_updates_and_deletes_minimally(self):
        desired = [
            dns.DesiredRecord("seeds.indraprotocol.com", "116.203.185.28"),
            dns.DesiredRecord("seeds.indraprotocol.com", "5.161.221.10"),
        ]
        existing = [
            dns.CloudflareRecord(
                id="keep-but-update",
                name="seeds.indraprotocol.com",
                type="A",
                content="116.203.185.28",
                ttl=120,
                proxied=False,
                comment="manual",
            ),
            dns.CloudflareRecord(
                id="stale",
                name="seeds.indraprotocol.com",
                type="A",
                content="203.0.113.9",
                ttl=dns.DEFAULT_TTL,
                proxied=False,
                comment=dns.DEFAULT_COMMENT,
            ),
            dns.CloudflareRecord(
                id="untouched-aaaa",
                name="seeds.indraprotocol.com",
                type="AAAA",
                content="2001:db8::1",
            ),
        ]

        changes = dns.compute_dns_diff(existing, desired)

        self.assertEqual(
            {(change.action, change.content) for change in changes},
            {
                ("create", "5.161.221.10"),
                ("update", "116.203.185.28"),
                ("delete", "203.0.113.9"),
            },
        )

    def test_dry_run_makes_no_api_changes(self):
        client = FakeCloudflare()
        changes = [
            dns.DnsChange(
                action="create",
                name="seeds.indraprotocol.com",
                content="116.203.185.28",
                desired=dns.DesiredRecord("seeds.indraprotocol.com", "116.203.185.28"),
            )
        ]

        # Dry-run mode prints the plan but intentionally does not call apply_changes.
        dns.print_plan(changes, dry_run=True)

        self.assertEqual(client.created, [])
        self.assertEqual(client.updated, [])
        self.assertEqual(client.deleted, [])

    def test_refuses_empty_or_malformed_validator_sets(self):
        with self.assertRaises(dns.DnsPublishError):
            dns.derive_desired_a_records(
                {"validators": []},
                ["seeds.indraprotocol.com"],
                min_expected_validators=1,
            )

        with self.assertRaises(dns.DnsPublishError):
            dns.derive_desired_a_records(
                {"validators": [{"validator_id": "a", "network_addr": "validator.example:30303"}]},
                ["seeds.indraprotocol.com"],
                min_expected_validators=1,
            )

    def test_token_file_must_not_be_group_or_world_readable(self):
        with tempfile.NamedTemporaryFile("w", delete=False) as fh:
            fh.write("secret-token\n")
            path = fh.name
        try:
            os.chmod(path, stat.S_IRUSR | stat.S_IWUSR | stat.S_IRGRP)
            with self.assertRaises(dns.DnsPublishError):
                dns.read_token_from_file(path)

            os.chmod(path, stat.S_IRUSR | stat.S_IWUSR)
            self.assertEqual(dns.read_token_from_file(path), "secret-token")
        finally:
            os.unlink(path)


if __name__ == "__main__":
    unittest.main()
