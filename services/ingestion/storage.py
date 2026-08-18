# SPDX-FileCopyrightText: 2026 Virantis
# SPDX-License-Identifier: LicenseRef-Vooda-Community-1.0

import os
import aiofiles
from apps.api.app.core.config import settings


async def save_upload(file, repo_id: str) -> str:
    base = os.path.join(settings.STORAGE_PATH, "uploads", repo_id)
    os.makedirs(base, exist_ok=True)
    path = os.path.join(base, file.filename or "upload")
    async with aiofiles.open(path, "wb") as f:
        content = await file.read()
        await f.write(content)
    return path


async def save_artifact(content: bytes, scan_job_id: str, filename: str) -> str:
    base = os.path.join(settings.STORAGE_PATH, "artifacts", scan_job_id)
    os.makedirs(base, exist_ok=True)
    path = os.path.join(base, filename)
    async with aiofiles.open(path, "wb") as f:
        await f.write(content)
    return path
