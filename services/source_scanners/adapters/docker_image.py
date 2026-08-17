# SPDX-FileCopyrightText: 2026 Virantis
# SPDX-License-Identifier: LicenseRef-Vooda-Community-1.0

"""Docker image source adapter — scans image layers, ENV vars, and embedded files."""

import asyncio
import json
import os
import shutil
import tarfile
import tempfile
from typing import AsyncIterator

from services.integration_errors.classifiers import classify_sdk_error
from services.source_scanners.base import SourceAdapter, ScanableContent

TEXT_EXTENSIONS = {".json", ".yaml", ".yml", ".env", ".conf", ".ini", ".toml", ".xml", ".properties",
                   ".txt", ".sh", ".bash", ".py", ".js", ".ts", ".rb", ".go", ".java", ".tf", ".hcl",
                   ".dockerfile", ".cfg", ".key", ".pem", ".crt"}


class DockerImageSourceAdapter(SourceAdapter):
    source_type = "docker_image"

    def __init__(self, image: str, registry_url: str = "", username: str = "", password: str = "", max_layer_size_mb: int = 500):
        self.image = image
        self.registry_url = registry_url
        self.username = username
        self.password = password
        self.max_layer_size = max_layer_size_mb * 1_000_000
        self._updated_sync_state: dict = {}

    async def test_connection(self) -> dict:
        """Probe via ``docker manifest inspect`` — confirms registry
        reachability AND that the image ref exists, without pulling
        layers.

        Two failure modes:
          - Docker CLI missing on the host → distinct fix step ("install Docker")
          - manifest inspect non-zero exit → registry-side problem;
            stderr text drives the SDK classifier
        """
        ctx = {"adapter": "docker_image", "image": self.image}
        try:
            proc = await asyncio.create_subprocess_exec(
                "docker", "manifest", "inspect", self.image,
                stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
            )
            _, stderr = await proc.communicate()
            if proc.returncode == 0:
                return {"status": "success", "message": f"Image {self.image} is accessible"}
            err = classify_sdk_error(
                RuntimeError(stderr.decode()[:500] or "docker manifest inspect failed"),
                provider="docker_image", context=ctx,
            )
            return err.to_user_dict()
        except FileNotFoundError:
            err = classify_sdk_error(
                RuntimeError("Docker CLI not found on this system"),
                provider="docker_image", context=ctx,
            )
            # Patch the title / fix steps for the host-tooling case.
            err.title = "Docker CLI not installed"
            err.summary = "Vooda's worker host doesn't have the `docker` CLI on PATH."
            err.fix_steps = [
                "Install Docker on the worker host (apt-get install docker.io / brew install docker / etc.)",
                "Confirm `docker version` succeeds for the user the worker runs as",
            ]
            return err.to_user_dict()
        except Exception as exc:
            err = classify_sdk_error(exc, provider="docker_image", context=ctx)
            return err.to_user_dict()

    async def extract_content(self, sync_state: dict) -> AsyncIterator[ScanableContent]:
        self._updated_sync_state = dict(sync_state)
        tmpdir = tempfile.mkdtemp(prefix="vooda_docker_")

        try:
            # Save image to tar
            tar_path = os.path.join(tmpdir, "image.tar")
            proc = await asyncio.create_subprocess_exec(
                "docker", "save", "-o", tar_path, self.image,
                stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
            )
            _, stderr = await proc.communicate()
            if proc.returncode != 0:
                return

            # Extract and scan
            with tarfile.open(tar_path, "r") as tar:
                # Scan manifest/config for ENV vars
                for member in tar.getmembers():
                    if member.name.endswith(".json") and member.size < 1_000_000:
                        f = tar.extractfile(member)
                        if f:
                            content = f.read().decode("utf-8", errors="replace")
                            # Look for config with env vars
                            try:
                                config = json.loads(content)
                                env_vars = config.get("config", {}).get("Env", [])
                                if env_vars:
                                    env_text = "\n".join(env_vars)
                                    yield ScanableContent(
                                        source_locator=f"docker://{self.image}/config/env",
                                        content=env_text,
                                        content_type="env_var",
                                        deep_link_url="",
                                        metadata={"image": self.image, "env_count": len(env_vars)},
                                    )
                            except json.JSONDecodeError:
                                pass

                    # Scan layer tars
                    if member.name.endswith("/layer.tar") and member.size < self.max_layer_size:
                        f = tar.extractfile(member)
                        if not f:
                            continue
                        layer_name = member.name.split("/")[0][:12]
                        layer_dir = os.path.join(tmpdir, f"layer_{layer_name}")
                        os.makedirs(layer_dir, exist_ok=True)

                        try:
                            with tarfile.open(fileobj=f) as layer_tar:
                                for layer_member in layer_tar.getmembers():
                                    if not layer_member.isfile() or layer_member.size > 1_000_000:
                                        continue
                                    ext = os.path.splitext(layer_member.name)[1].lower()
                                    if ext not in TEXT_EXTENSIONS:
                                        continue
                                    lf = layer_tar.extractfile(layer_member)
                                    if lf:
                                        try:
                                            file_content = lf.read().decode("utf-8", errors="replace")[:500_000]
                                            if file_content.strip():
                                                yield ScanableContent(
                                                    source_locator=f"docker://{self.image}/{layer_name}/{layer_member.name}",
                                                    content=file_content,
                                                    content_type="file",
                                                    metadata={"image": self.image, "layer": layer_name, "path": layer_member.name},
                                                )
                                        except Exception:
                                            pass
                        except Exception:
                            pass

            # Track image digest
            proc = await asyncio.create_subprocess_exec(
                "docker", "inspect", "--format={{.Id}}", self.image,
                stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
            )
            stdout, _ = await proc.communicate()
            if proc.returncode == 0:
                self._updated_sync_state["last_digest"] = stdout.decode().strip()

        finally:
            shutil.rmtree(tmpdir, ignore_errors=True)

    def get_updated_sync_state(self) -> dict:
        return self._updated_sync_state
