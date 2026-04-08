#!/usr/bin/env python3
"""Check database status."""
import asyncio
from src.web.models.database import get_session_local
from sqlalchemy import text

async def main():
    async with get_session_local() as db:
        result = await db.execute(text('SELECT COUNT(*) FROM projects'))
        print(f'Projects: {result.scalar()}')
        result = await db.execute(text('SELECT COUNT(*) FROM scans'))
        print(f'Scans: {result.scalar()}')

if __name__ == '__main__':
    asyncio.run(main())
