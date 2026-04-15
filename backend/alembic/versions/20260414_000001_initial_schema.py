"""initial schema

Revision ID: 20260414_000001
Revises:
Create Date: 2026-04-14 00:00:01
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = "20260414_000001"
down_revision: Union[str, None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "agent_identities",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("agent_id", sa.String(), nullable=True),
        sa.Column("role", sa.String(), nullable=True),
        sa.Column("api_key_hash", sa.String(), nullable=True),
        sa.Column("is_active", sa.Boolean(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=True),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_agent_identities_id", "agent_identities", ["id"], unique=False)
    op.create_index("ix_agent_identities_agent_id", "agent_identities", ["agent_id"], unique=True)

    op.create_table(
        "security_events",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("session_id", sa.String(), nullable=True),
        sa.Column("event_type", sa.String(), nullable=True),
        sa.Column("risk_score", sa.Float(), nullable=True),
        sa.Column("details", sa.JSON(), nullable=True),
        sa.Column("timestamp", sa.DateTime(timezone=True), nullable=True),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_security_events_id", "security_events", ["id"], unique=False)
    op.create_index("ix_security_events_session_id", "security_events", ["session_id"], unique=False)

    op.create_table(
        "audit_logs",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("session_id", sa.String(), nullable=True),
        sa.Column("agent_id", sa.String(), nullable=True),
        sa.Column("action", sa.String(), nullable=True),
        sa.Column("status", sa.String(), nullable=True),
        sa.Column("input_text", sa.Text(), nullable=True),
        sa.Column("output_text", sa.Text(), nullable=True),
        sa.Column("timestamp", sa.DateTime(timezone=True), nullable=True),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_audit_logs_id", "audit_logs", ["id"], unique=False)
    op.create_index("ix_audit_logs_session_id", "audit_logs", ["session_id"], unique=False)
    op.create_index("ix_audit_logs_status", "audit_logs", ["status"], unique=False)


def downgrade() -> None:
    op.drop_index("ix_audit_logs_status", table_name="audit_logs")
    op.drop_index("ix_audit_logs_session_id", table_name="audit_logs")
    op.drop_index("ix_audit_logs_id", table_name="audit_logs")
    op.drop_table("audit_logs")

    op.drop_index("ix_security_events_session_id", table_name="security_events")
    op.drop_index("ix_security_events_id", table_name="security_events")
    op.drop_table("security_events")

    op.drop_index("ix_agent_identities_agent_id", table_name="agent_identities")
    op.drop_index("ix_agent_identities_id", table_name="agent_identities")
    op.drop_table("agent_identities")
