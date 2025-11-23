"""add_group_aes_key

Revision ID: 1187b109a19e
Revises: 001
Create Date: 2025-11-23 06:12:42.346650

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '1187b109a19e'
down_revision = '001'
branch_labels = None
depends_on = None

def upgrade() -> None:
    # Add aes_key_b64 column to groups table
    op.add_column('groups', sa.Column('aes_key_b64', sa.Text(), nullable=True))


def downgrade() -> None:
    # Remove aes_key_b64 column
    op.drop_column('groups', 'aes_key_b64')

