#!/usr/bin/env python3
"""Initialize DeepVuln Web database."""
import asyncio
from src.web.models.database import init_db

async def main():
    # Default database URL for DeepVuln
    database_url = "postgresql+asyncpg://deepvuln:deepvuln@localhost:5432/deepvuln"
    print(f"Initializing database: {database_url}")
    await init_db(database_url)
    print("Database initialized successfully!")

    # Verify connection
    from sqlalchemy import text
    from src.web.models.database import AsyncSessionLocal

    async with AsyncSessionLocal() as db:
        result = await db.execute(text('SELECT COUNT(*) FROM projects'))
        projects = result.scalar()
        result = await db.execute(text('SELECT COUNT(*) FROM scans'))
        scans = result.scalar()
        print(f"\nDatabase status:")
        print(f"  Projects: {projects}")
        print(f"  Scans: {scans}")

if __name__ == '__main__':
    asyncio.run(main())
