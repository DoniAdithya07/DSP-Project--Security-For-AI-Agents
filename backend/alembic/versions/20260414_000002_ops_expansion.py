"""ops and governance expansion

Revision ID: 20260414_000002
Revises: 20260414_000001
Create Date: 2026-04-14 04:30:00
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = "20260414_000002"
down_revision: Union[str, None] = "20260414_000001"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "dashboard_users",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("username", sa.String(), nullable=True),
        sa.Column("password_hash", sa.String(), nullable=True),
        sa.Column("role", sa.String(), nullable=True),
        sa.Column("team", sa.String(), nullable=True),
        sa.Column("is_active", sa.Boolean(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=True),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_dashboard_users_id", "dashboard_users", ["id"], unique=False)
    op.create_index("ix_dashboard_users_username", "dashboard_users", ["username"], unique=True)

    op.create_table(
        "user_session_tokens",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("username", sa.String(), nullable=True),
        sa.Column("token_hash", sa.String(), nullable=True),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=True),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_user_session_tokens_id", "user_session_tokens", ["id"], unique=False)
    op.create_index("ix_user_session_tokens_username", "user_session_tokens", ["username"], unique=False)
    op.create_index("ix_user_session_tokens_token_hash", "user_session_tokens", ["token_hash"], unique=True)
    op.create_index("ix_user_session_tokens_expires_at", "user_session_tokens", ["expires_at"], unique=False)

    op.create_table(
        "policy_versions",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("version", sa.Integer(), nullable=True),
        sa.Column("policy", sa.JSON(), nullable=True),
        sa.Column("changed_by", sa.String(), nullable=True),
        sa.Column("change_note", sa.String(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=True),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_policy_versions_id", "policy_versions", ["id"], unique=False)
    op.create_index("ix_policy_versions_version", "policy_versions", ["version"], unique=False)
    op.create_index("ix_policy_versions_changed_by", "policy_versions", ["changed_by"], unique=False)

    op.create_table(
        "policy_change_audit",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("policy_version", sa.Integer(), nullable=True),
        sa.Column("changed_by", sa.String(), nullable=True),
        sa.Column("summary", sa.String(), nullable=True),
        sa.Column("details", sa.JSON(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=True),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_policy_change_audit_id", "policy_change_audit", ["id"], unique=False)
    op.create_index("ix_policy_change_audit_policy_version", "policy_change_audit", ["policy_version"], unique=False)
    op.create_index("ix_policy_change_audit_changed_by", "policy_change_audit", ["changed_by"], unique=False)

    op.create_table(
        "threat_intel_patterns",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("rule_id", sa.String(), nullable=True),
        sa.Column("pattern", sa.String(), nullable=True),
        sa.Column("reason", sa.String(), nullable=True),
        sa.Column("weight", sa.Float(), nullable=True),
        sa.Column("source", sa.String(), nullable=True),
        sa.Column("enabled", sa.Boolean(), nullable=True),
        sa.Column("created_by", sa.String(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=True),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_threat_intel_patterns_id", "threat_intel_patterns", ["id"], unique=False)
    op.create_index("ix_threat_intel_patterns_rule_id", "threat_intel_patterns", ["rule_id"], unique=False)

    op.create_table(
        "tool_risk_profiles",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("tool_name", sa.String(), nullable=True),
        sa.Column("max_risk_score", sa.Float(), nullable=True),
        sa.Column("require_approval_above", sa.Float(), nullable=True),
        sa.Column("updated_by", sa.String(), nullable=True),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=True),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_tool_risk_profiles_id", "tool_risk_profiles", ["id"], unique=False)
    op.create_index("ix_tool_risk_profiles_tool_name", "tool_risk_profiles", ["tool_name"], unique=True)

    op.create_table(
        "approval_requests",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("session_id", sa.String(), nullable=True),
        sa.Column("agent_id", sa.String(), nullable=True),
        sa.Column("role", sa.String(), nullable=True),
        sa.Column("tool_name", sa.String(), nullable=True),
        sa.Column("risk_score", sa.Float(), nullable=True),
        sa.Column("prompt", sa.Text(), nullable=True),
        sa.Column("status", sa.String(), nullable=True),
        sa.Column("payload", sa.JSON(), nullable=True),
        sa.Column("created_by", sa.String(), nullable=True),
        sa.Column("approved_by", sa.String(), nullable=True),
        sa.Column("approved_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=True),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_approval_requests_id", "approval_requests", ["id"], unique=False)
    op.create_index("ix_approval_requests_session_id", "approval_requests", ["session_id"], unique=False)
    op.create_index("ix_approval_requests_agent_id", "approval_requests", ["agent_id"], unique=False)
    op.create_index("ix_approval_requests_created_by", "approval_requests", ["created_by"], unique=False)

    op.create_table(
        "rotating_api_keys",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("key_hash", sa.String(), nullable=True),
        sa.Column("label", sa.String(), nullable=True),
        sa.Column("active", sa.Boolean(), nullable=True),
        sa.Column("created_by", sa.String(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=True),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_rotating_api_keys_id", "rotating_api_keys", ["id"], unique=False)
    op.create_index("ix_rotating_api_keys_key_hash", "rotating_api_keys", ["key_hash"], unique=True)

    op.create_table(
        "risk_calibration_feedback",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("session_id", sa.String(), nullable=True),
        sa.Column("expected_decision", sa.String(), nullable=True),
        sa.Column("actual_decision", sa.String(), nullable=True),
        sa.Column("risk_score", sa.Float(), nullable=True),
        sa.Column("notes", sa.Text(), nullable=True),
        sa.Column("recorded_by", sa.String(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=True),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_risk_calibration_feedback_id", "risk_calibration_feedback", ["id"], unique=False)
    op.create_index("ix_risk_calibration_feedback_session_id", "risk_calibration_feedback", ["session_id"], unique=False)
    op.create_index("ix_risk_calibration_feedback_expected_decision", "risk_calibration_feedback", ["expected_decision"], unique=False)
    op.create_index("ix_risk_calibration_feedback_actual_decision", "risk_calibration_feedback", ["actual_decision"], unique=False)
    op.create_index("ix_risk_calibration_feedback_recorded_by", "risk_calibration_feedback", ["recorded_by"], unique=False)


def downgrade() -> None:
    op.drop_index("ix_risk_calibration_feedback_recorded_by", table_name="risk_calibration_feedback")
    op.drop_index("ix_risk_calibration_feedback_actual_decision", table_name="risk_calibration_feedback")
    op.drop_index("ix_risk_calibration_feedback_expected_decision", table_name="risk_calibration_feedback")
    op.drop_index("ix_risk_calibration_feedback_session_id", table_name="risk_calibration_feedback")
    op.drop_index("ix_risk_calibration_feedback_id", table_name="risk_calibration_feedback")
    op.drop_table("risk_calibration_feedback")

    op.drop_index("ix_rotating_api_keys_key_hash", table_name="rotating_api_keys")
    op.drop_index("ix_rotating_api_keys_id", table_name="rotating_api_keys")
    op.drop_table("rotating_api_keys")

    op.drop_index("ix_approval_requests_created_by", table_name="approval_requests")
    op.drop_index("ix_approval_requests_agent_id", table_name="approval_requests")
    op.drop_index("ix_approval_requests_session_id", table_name="approval_requests")
    op.drop_index("ix_approval_requests_id", table_name="approval_requests")
    op.drop_table("approval_requests")

    op.drop_index("ix_tool_risk_profiles_tool_name", table_name="tool_risk_profiles")
    op.drop_index("ix_tool_risk_profiles_id", table_name="tool_risk_profiles")
    op.drop_table("tool_risk_profiles")

    op.drop_index("ix_threat_intel_patterns_rule_id", table_name="threat_intel_patterns")
    op.drop_index("ix_threat_intel_patterns_id", table_name="threat_intel_patterns")
    op.drop_table("threat_intel_patterns")

    op.drop_index("ix_policy_change_audit_changed_by", table_name="policy_change_audit")
    op.drop_index("ix_policy_change_audit_policy_version", table_name="policy_change_audit")
    op.drop_index("ix_policy_change_audit_id", table_name="policy_change_audit")
    op.drop_table("policy_change_audit")

    op.drop_index("ix_policy_versions_changed_by", table_name="policy_versions")
    op.drop_index("ix_policy_versions_version", table_name="policy_versions")
    op.drop_index("ix_policy_versions_id", table_name="policy_versions")
    op.drop_table("policy_versions")

    op.drop_index("ix_user_session_tokens_expires_at", table_name="user_session_tokens")
    op.drop_index("ix_user_session_tokens_token_hash", table_name="user_session_tokens")
    op.drop_index("ix_user_session_tokens_username", table_name="user_session_tokens")
    op.drop_index("ix_user_session_tokens_id", table_name="user_session_tokens")
    op.drop_table("user_session_tokens")

    op.drop_index("ix_dashboard_users_username", table_name="dashboard_users")
    op.drop_index("ix_dashboard_users_id", table_name="dashboard_users")
    op.drop_table("dashboard_users")
