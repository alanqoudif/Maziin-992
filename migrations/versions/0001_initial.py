"""Initial schema for vulnerability prioritization dashboard.

Revision ID: 0001_initial
Revises:
Create Date: 2026-04-03
"""

from alembic import op
import sqlalchemy as sa

revision = "0001_initial"
down_revision = None
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        "user",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("username", sa.String(length=64), nullable=False, unique=True),
        sa.Column("email", sa.String(length=255), nullable=False, unique=True),
        sa.Column("password_hash", sa.String(length=255), nullable=False),
        sa.Column("role", sa.String(length=32), nullable=False),
        sa.Column("mfa_enabled", sa.Boolean(), nullable=True),
        sa.Column("created_at", sa.DateTime(), nullable=True),
        sa.Column("last_login", sa.DateTime(), nullable=True),
    )
    op.create_table(
        "device",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("hostname", sa.String(length=120), nullable=False, unique=True),
        sa.Column("ip_address", sa.String(length=45), nullable=False, unique=True),
        sa.Column("mac_address", sa.String(length=32), nullable=False),
        sa.Column("device_type", sa.String(length=50), nullable=False),
        sa.Column("os", sa.String(length=120), nullable=False),
        sa.Column("os_version", sa.String(length=120), nullable=True),
        sa.Column("department", sa.String(length=120), nullable=False),
        sa.Column("vlan", sa.String(length=20), nullable=False),
        sa.Column("subnet", sa.String(length=32), nullable=False),
        sa.Column("role", sa.String(length=120), nullable=False),
        sa.Column("criticality", sa.String(length=20), nullable=False),
        sa.Column("status", sa.String(length=20), nullable=False),
        sa.Column("last_scan", sa.DateTime(), nullable=True),
        sa.Column("created_at", sa.DateTime(), nullable=True),
    )
    op.create_table(
        "vulnerability",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("cve_id", sa.String(length=40), nullable=False),
        sa.Column("title", sa.String(length=255), nullable=False),
        sa.Column("description", sa.Text(), nullable=False),
        sa.Column("cvss_base_score", sa.Float(), nullable=False),
        sa.Column("cvss_vector", sa.String(length=255), nullable=True),
        sa.Column("severity", sa.String(length=20), nullable=False),
        sa.Column("exploitability_score", sa.Float(), nullable=False),
        sa.Column("impact_score", sa.Float(), nullable=False),
        sa.Column("status", sa.String(length=30), nullable=False),
        sa.Column("discovered_at", sa.DateTime(), nullable=True),
        sa.Column("patched_at", sa.DateTime(), nullable=True),
        sa.Column("ai_risk_score", sa.Float(), nullable=True),
        sa.Column("ai_priority_rank", sa.Integer(), nullable=True),
        sa.Column("asset_criticality_factor", sa.Float(), nullable=True),
        sa.Column("network_exposure_factor", sa.Float(), nullable=True),
        sa.Column("exploit_availability", sa.Boolean(), nullable=True),
    )
    op.create_index("ix_vulnerability_cve_id", "vulnerability", ["cve_id"], unique=False)
    op.create_table(
        "vulnerability_device",
        sa.Column("vulnerability_id", sa.Integer(), sa.ForeignKey("vulnerability.id"), primary_key=True),
        sa.Column("device_id", sa.Integer(), sa.ForeignKey("device.id"), primary_key=True),
    )
    op.create_table(
        "scan_result",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("scan_type", sa.String(length=30), nullable=False),
        sa.Column("scan_date", sa.DateTime(), nullable=True),
        sa.Column("device_id", sa.Integer(), sa.ForeignKey("device.id"), nullable=False),
        sa.Column("raw_output", sa.Text(), nullable=True),
        sa.Column("parsed_results", sa.JSON(), nullable=True),
        sa.Column("findings_count", sa.Integer(), nullable=True),
    )
    op.create_table(
        "patch",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("vulnerability_id", sa.Integer(), sa.ForeignKey("vulnerability.id"), nullable=False),
        sa.Column("patch_name", sa.String(length=255), nullable=False),
        sa.Column("vendor", sa.String(length=120), nullable=False),
        sa.Column("release_date", sa.DateTime(), nullable=True),
        sa.Column("urgency", sa.String(length=20), nullable=False),
        sa.Column("recommendation", sa.Text(), nullable=False),
        sa.Column("status", sa.String(length=20), nullable=False),
        sa.Column("applied_date", sa.DateTime(), nullable=True),
    )
    op.create_table(
        "alert",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("alert_type", sa.String(length=50), nullable=False),
        sa.Column("severity", sa.String(length=20), nullable=False),
        sa.Column("message", sa.Text(), nullable=False),
        sa.Column("device_id", sa.Integer(), sa.ForeignKey("device.id"), nullable=True),
        sa.Column("vulnerability_id", sa.Integer(), sa.ForeignKey("vulnerability.id"), nullable=True),
        sa.Column("is_read", sa.Boolean(), nullable=True),
        sa.Column("created_at", sa.DateTime(), nullable=True),
    )


def downgrade():
    op.drop_table("alert")
    op.drop_table("patch")
    op.drop_table("scan_result")
    op.drop_table("vulnerability_device")
    op.drop_index("ix_vulnerability_cve_id", table_name="vulnerability")
    op.drop_table("vulnerability")
    op.drop_table("device")
    op.drop_table("user")
