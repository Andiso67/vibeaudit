"""Tests del escaneo de nube (solo lectura) sin red real ni credenciales."""

import pytest

from vibeaudit.models import Severity
from vibeaudit.scanners.cloud import CloudScanner


class FakeS3:
    """Cliente S3 fake: un bucket público y otro privado."""

    def __init__(self):
        self.list_buckets_called = False
        self.acl_calls = []

    def list_buckets(self):
        self.list_buckets_called = True
        return {"Buckets": [{"Name": "public-bucket"}, {"Name": "private-bucket"}]}

    def get_bucket_acl(self, Bucket):
        self.acl_calls.append(Bucket)
        if Bucket == "public-bucket":
            return {
                "Grants": [
                    {
                        "Grantee": {"URI": "http://acs.amazonaws.com/groups/global/AllUsers"},
                        "Permission": "READ",
                    }
                ]
            }
        return {"Grants": []}


class FakeEC2:
    """Cliente EC2 fake: un security group abierto y otro cerrado."""

    def __init__(self):
        self.called = False

    def describe_security_groups(self):
        self.called = True
        return {
            "SecurityGroups": [
                {
                    "GroupId": "sg-open",
                    "GroupName": "open-to-world",
                    "IpPermissions": [
                        {
                            "FromPort": 22,
                            "ToPort": 22,
                            "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
                        }
                    ],
                },
                {
                    "GroupId": "sg-safe",
                    "GroupName": "restricted",
                    "IpPermissions": [
                        {
                            "FromPort": 22,
                            "ToPort": 22,
                            "IpRanges": [{"CidrIp": "10.0.0.0/8"}],
                        }
                    ],
                },
            ]
        }


class TestCloudScannerAws:
    def test_scan_detecta_bucket_publico_y_sg_abierto(self):
        fake_s3 = FakeS3()
        fake_ec2 = FakeEC2()
        scanner = CloudScanner(providers=["aws"], clients={"s3": fake_s3, "ec2": fake_ec2})
        issues = scanner.scan()

        assert fake_s3.list_buckets_called is True
        assert fake_ec2.called is True

        rules = {issue.rule: issue for issue in issues}
        assert set(rules) == {"aws-s3-bucket-public", "aws-ec2-security-group-open"}

        s3_issue = rules["aws-s3-bucket-public"]
        assert s3_issue.resource == "s3://public-bucket"
        assert s3_issue.provider == "aws"
        assert s3_issue.severity == Severity.HIGH
        assert "AllUsers" in s3_issue.description

        sg_issue = rules["aws-ec2-security-group-open"]
        assert sg_issue.resource == "sg-open"
        assert "22" in sg_issue.description
        assert sg_issue.severity == Severity.HIGH

    def test_scan_reusa_clientes_privados_sin_issue_s3(self):
        fake_s3 = FakeS3()
        fake_ec2 = FakeEC2()
        # el bucket "private-bucket" no genera issue; el público sí
        scanner = CloudScanner(providers=["aws"], clients={"s3": fake_s3, "ec2": fake_ec2})
        issues = scanner.scan()
        s3_issues = [i for i in issues if i.rule == "aws-s3-bucket-public"]
        assert [i.resource for i in s3_issues] == ["s3://public-bucket"]

    def test_public_acl_permissions_filtra_grantees_anonimos(self):
        acl = {
            "Grants": [
                {"Grantee": {"URI": "http://acs.amazonaws.com/groups/global/AllUsers"}, "Permission": "WRITE"},
                {"Grantee": {"Type": "CanonicalUser", "ID": "x"}, "Permission": "READ"},
                {"Grantee": {"URI": "http://acs.amazonaws.com/groups/global/AuthenticatedUsers"}, "Permission": "READ"},
            ]
        }
        perms = CloudScanner._public_acl_permissions(acl)
        assert perms == ["AllUsers:WRITE", "AuthenticatedUsers:READ"]

    def test_open_ingress_ports_ignora_sg_cerrado(self):
        permissions = [
            {"FromPort": 22, "ToPort": 22, "IpRanges": [{"CidrIp": "203.0.113.0/24"}]},
            {"FromPort": 80, "ToPort": 80, "IpRanges": [{"CidrIp": "0.0.0.0/0"}]},
            {"FromPort": -1, "IpRanges": [{"CidrIp": "0.0.0.0/0"}]},
        ]
        ports = CloudScanner._open_ingress_ports(permissions)
        assert ports == ["80", "all"]

    def test_scan_azure_y_gcp_placeholder_advierten_sin_crash(self, monkeypatch):
        monkeypatch.setenv("AZURE_CLIENT_ID", "fake")
        monkeypatch.setenv("GCLOUD_PROJECT", "fake")
        scanner = CloudScanner(
            providers=["azure", "gcp"], clients={"s3": FakeS3()}
        )
        issues = scanner.scan()
        assert issues == []


class TestCloudScannerCredenciales:
    def test_sin_credenciales_lanza_error_limpio(self, monkeypatch):
        for var in (
            "AWS_ACCESS_KEY_ID",
            "AWS_SECRET_ACCESS_KEY",
            "AWS_PROFILE",
            "AWS_SESSION_TOKEN",
            "AZURE_CLIENT_ID",
            "AZURE_CLIENT_SECRET",
            "AZURE_TENANT_ID",
            "AZURE_SUBSCRIPTION_ID",
            "GOOGLE_APPLICATION_CREDENTIALS",
            "GCLOUD_PROJECT",
            "GOOGLE_PROJECT",
        ):
            monkeypatch.delenv(var, raising=False)
        scanner = CloudScanner()
        assert scanner.configured_providers() == []
        with pytest.raises(RuntimeError, match="No hay credenciales de nube"):
            scanner.scan()

    def test_aws_configurado_por_env(self, monkeypatch):
        monkeypatch.setenv("AWS_ACCESS_KEY_ID", "AKIAFAKE")
        scanner = CloudScanner(providers=["aws"])
        assert scanner.configured_providers() == ["aws"]

    def test_azure_configurado_por_env(self, monkeypatch):
        monkeypatch.setenv("AZURE_TENANT_ID", "fake-tenant")
        scanner = CloudScanner(providers=["azure"])
        assert scanner.configured_providers() == ["azure"]