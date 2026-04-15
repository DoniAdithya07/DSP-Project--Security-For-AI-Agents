"""add indexes for large-scale log query paths

Revision ID: 20260414_000003
Revises: 20260414_000002
Create Date: 2026-04-14 15:45:00
"""
from typing import Sequence, Union

from alembic import op


revision: str = "20260414_000003"
down_revision: Union[str, None] = "20260414_000002"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_index("ix_security_events_event_type", "security_events", ["event_type"], unique=False)
    op.create_index("ix_security_events_risk_score", "security_events", ["risk_score"], unique=False)
    op.create_index("ix_security_events_timestamp", "security_events", ["timestamp"], unique=False)
    op.create_index("ix_audit_logs_timestamp", "audit_logs", ["timestamp"], unique=False)
    op.create_index("ix_approval_requests_status", "approval_requests", ["status"], unique=False)


def downgrade() -> None:
    op.drop_index("ix_approval_requests_status", table_name="approval_requests")
    op.drop_index("ix_audit_logs_timestamp", table_name="audit_logs")
    op.drop_index("ix_security_events_timestamp", table_name="security_events")
    op.drop_index("ix_security_events_risk_score", table_name="security_events")
    op.drop_index("ix_security_events_event_type", table_name="security_events")
