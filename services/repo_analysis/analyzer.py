# SPDX-FileCopyrightText: 2026 Virantis
# SPDX-License-Identifier: LicenseRef-Vooda-Community-1.0

"""
Repository analysis service.
Detects languages, frameworks, config files, and builds a code inventory.
"""

import os
from pathlib import Path
from dataclasses import dataclass, field

LANGUAGE_EXTENSIONS = {
    ".py": "python", ".java": "java", ".js": "javascript", ".ts": "typescript",
    ".tsx": "typescript", ".jsx": "javascript", ".go": "go", ".cs": "csharp",
    ".kt": "kotlin", ".php": "php", ".rb": "ruby", ".tf": "terraform",
    ".yml": "yaml", ".yaml": "yaml", ".sh": "shell", ".bash": "shell",
    ".sql": "sql", ".rs": "rust", ".swift": "swift", ".c": "c", ".cpp": "cpp",
    ".h": "c", ".hpp": "cpp",
}

FRAMEWORK_INDICATORS = {
    "requirements.txt": {"lang": "python", "hints": {
        "django": "django", "flask": "flask", "fastapi": "fastapi",
    }},
    "package.json": {"lang": "javascript", "hints": {
        "express": "express", "next": "nextjs", "react": "react",
        "@nestjs/core": "nestjs", "vue": "vue", "angular": "angular",
    }},
    "pom.xml": {"lang": "java", "hints": {"spring-boot": "spring_boot"}},
    "build.gradle": {"lang": "java", "hints": {"spring-boot": "spring_boot"}},
    "go.mod": {"lang": "go", "hints": {"gin-gonic": "gin", "echo": "echo"}},
    "Gemfile": {"lang": "ruby", "hints": {"rails": "rails", "sinatra": "sinatra"}},
    "composer.json": {"lang": "php", "hints": {"laravel": "laravel"}},
    "Dockerfile": {"lang": "docker", "hints": {}},
    "terraform.tf": {"lang": "terraform", "hints": {}},
}


@dataclass
class RepoAnalysis:
    languages: dict[str, int] = field(default_factory=dict)  # lang -> file count
    frameworks: list[str] = field(default_factory=list)
    config_files: list[str] = field(default_factory=list)
    file_index: dict[str, dict] = field(default_factory=dict)  # path -> {lang, size}
    total_files: int = 0
    total_size: int = 0


def analyze_repository(repo_path: str) -> RepoAnalysis:
    """Analyze a repository directory and return structured inventory."""
    analysis = RepoAnalysis()
    root = Path(repo_path)

    if not root.exists():
        return analysis

    skip_dirs = {".git", "node_modules", "__pycache__", ".venv", "venv", "vendor", "dist", "build", ".next"}

    for path in root.rglob("*"):
        if path.is_dir():
            continue
        if any(skip in path.parts for skip in skip_dirs):
            continue

        # Skip broken/circular symlinks
        if path.is_symlink():
            try:
                path.resolve(strict=True)
            except (OSError, ValueError, RuntimeError):
                continue

        rel_path = str(path.relative_to(root))
        ext = path.suffix.lower()
        lang = LANGUAGE_EXTENSIONS.get(ext, "other")
        try:
            size = path.stat().st_size
        except OSError:
            continue

        analysis.file_index[rel_path] = {"lang": lang, "size": size}
        analysis.languages[lang] = analysis.languages.get(lang, 0) + 1
        analysis.total_files += 1
        analysis.total_size += size

        # Detect config files and frameworks
        if path.name in FRAMEWORK_INDICATORS:
            analysis.config_files.append(rel_path)
            indicator = FRAMEWORK_INDICATORS[path.name]
            try:
                content = path.read_text(errors="ignore").lower()
                for keyword, framework in indicator["hints"].items():
                    if keyword in content and framework not in analysis.frameworks:
                        analysis.frameworks.append(framework)
            except Exception:
                pass

    return analysis


def extract_code_context(repo_path: str, file_path: str, line_start: int, context_lines: int = 30) -> dict:
    """Extract code around a specific location for AI analysis."""
    full_path = os.path.join(repo_path, file_path)
    if not os.path.exists(full_path):
        return {"code_snippet": "", "file_context": "", "language": ""}

    try:
        with open(full_path, "r", errors="ignore") as f:
            lines = f.readlines()
    except Exception:
        return {"code_snippet": "", "file_context": "", "language": ""}

    ext = os.path.splitext(file_path)[1].lower()
    language = LANGUAGE_EXTENSIONS.get(ext, "")

    # Extract snippet around the finding
    start = max(0, (line_start or 1) - context_lines)
    end = min(len(lines), (line_start or 1) + context_lines)
    snippet_lines = lines[start:end]
    snippet = "".join(snippet_lines)

    # Full file context (truncated)
    file_context = "".join(lines[:500])  # first 500 lines

    return {
        "code_snippet": snippet,
        "file_context": file_context,
        "language": language,
        "total_lines": len(lines),
    }
