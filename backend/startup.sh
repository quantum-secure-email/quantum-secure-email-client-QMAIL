#!/bin/bash
set -e

echo "🚀 Starting QMail Backend Deployment..."

# Wait for database to be ready
echo "⏳ Waiting for database connection..."
python -c "
import time
import sys
from sqlalchemy import create_engine
from sqlalchemy.exc import OperationalError
import os

db_url = os.getenv('DATABASE_URL')
if not db_url:
    print('❌ DATABASE_URL not set')
    sys.exit(1)

max_retries = 30
for i in range(max_retries):
    try:
        engine = create_engine(db_url)
        conn = engine.connect()
        conn.close()
        print('✅ Database connection successful')
        break
    except OperationalError:
        if i == max_retries - 1:
            print('❌ Could not connect to database after 30 attempts')
            sys.exit(1)
        print(f'Attempt {i+1}/{max_retries} failed, retrying...')
        time.sleep(2)
"

# Run Alembic migrations
echo "📊 Running database migrations..."
alembic upgrade head
if [ $? -eq 0 ]; then
    echo "✅ Migrations completed successfully"
else
    echo "❌ Migration failed"
    exit 1
fi

# Initialize OTP keys (if not already present)
echo "🔐 Initializing OTP keys..."
python init_otp_keys.py
if [ $? -eq 0 ]; then
    echo "✅ OTP keys initialization completed"
else
    echo "❌ OTP keys initialization failed"
    exit 1
fi

# Start the application
echo "🎉 Starting FastAPI server..."
PORT=${PORT:-8000}
exec uvicorn main:app --host 0.0.0.0 --port $PORT