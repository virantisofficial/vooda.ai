#!/bin/bash
# Install Vooda AI pre-commit hook
#
# Usage:
#   cd your-repo
#   bash /path/to/vooda/cli/install-hook.sh
#
# Or with pre-commit framework:
#   Add to .pre-commit-config.yaml:
#     repos:
#       - repo: /path/to/vooda
#         rev: main
#         hooks:
#           - id: vooda-secret-scan

set -e

VOODA_DIR="$(cd "$(dirname "$0")/.." && pwd)"
HOOK_PATH=".git/hooks/pre-commit"

if [ ! -d ".git" ]; then
    echo "Error: Not a git repository. Run this from your project root."
    exit 1
fi

# Create pre-commit hook
cat > "$HOOK_PATH" << HOOK
#!/bin/bash
# Vooda AI Secret Scanner — Pre-commit Hook
# Blocks commits that contain hardcoded secrets

python3 "${VOODA_DIR}/cli/vooda_cli.py" scan --staged
exit_code=\$?

if [ \$exit_code -eq 1 ]; then
    echo ""
    echo "Commit blocked by Vooda AI. Remove secrets before committing."
    echo "To bypass (not recommended): git commit --no-verify"
    exit 1
fi

exit 0
HOOK

chmod +x "$HOOK_PATH"

echo "✅ Vooda AI pre-commit hook installed successfully."
echo "   Secrets will be scanned before every commit."
echo "   To bypass: git commit --no-verify"
