# SPDX-FileCopyrightText: 2026 Virantis
# SPDX-License-Identifier: LicenseRef-Vooda-Community-1.0

"""
Remediation template registry — pre-built fix patterns per vulnerability category.

Provides the AI remediation engine with proven fix patterns so it generates
correct, idiomatic patches for common vulnerability types.
"""

from typing import Optional


TEMPLATES: dict[str, dict[str, str]] = {
    # ═══ SQL Injection ════════════════════════════════════
    "sql_injection": {
        "python_raw": """# VULNERABLE:
cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")

# FIXED — use parameterized query:
cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))""",

        "python_sqlalchemy": """# VULNERABLE:
db.execute(f"SELECT * FROM users WHERE name = '{name}'")

# FIXED — use SQLAlchemy text() with bindparams:
from sqlalchemy import text
db.execute(text("SELECT * FROM users WHERE name = :name"), {"name": name})""",

        "python_django": """# VULNERABLE:
User.objects.raw(f"SELECT * FROM users WHERE name = '{name}'")

# FIXED — use ORM or parameterized raw:
User.objects.filter(name=name)
# OR if raw SQL needed:
User.objects.raw("SELECT * FROM users WHERE name = %s", [name])""",

        "javascript_mysql": """// VULNERABLE:
db.query(`SELECT * FROM users WHERE id = ${userId}`)

// FIXED — use parameterized query:
db.query("SELECT * FROM users WHERE id = ?", [userId])""",

        "java_jdbc": """// VULNERABLE:
stmt.execute("SELECT * FROM users WHERE id = " + userId);

// FIXED — use PreparedStatement:
PreparedStatement ps = conn.prepareStatement("SELECT * FROM users WHERE id = ?");
ps.setString(1, userId);
ResultSet rs = ps.executeQuery();""",

        "java_jpa": """// VULNERABLE:
em.createQuery("SELECT u FROM User u WHERE u.name = '" + name + "'");

// FIXED — use named parameters:
em.createQuery("SELECT u FROM User u WHERE u.name = :name")
  .setParameter("name", name);""",
    },

    # ═══ Cross-Site Scripting ═════════════════════════════
    "xss": {
        "python_flask": """# VULNERABLE:
return f"<h1>Hello {username}</h1>"

# FIXED — use template engine (auto-escapes):
from flask import render_template_string
return render_template_string("<h1>Hello {{ name }}</h1>", name=username)
# OR use markupsafe:
from markupsafe import escape
return f"<h1>Hello {escape(username)}</h1>"
""",

        "python_django": """# VULNERABLE:
return HttpResponse(f"<div>{user_input}</div>")

# FIXED — use Django templates (auto-escape):
from django.shortcuts import render
return render(request, "template.html", {"content": user_input})
# In template: {{ content }} — auto-escaped by default""",

        "javascript_dom": """// VULNERABLE:
element.innerHTML = userInput;

// FIXED — use textContent:
element.textContent = userInput;
// OR sanitize with DOMPurify:
element.innerHTML = DOMPurify.sanitize(userInput);""",

        "react": """// VULNERABLE:
<div dangerouslySetInnerHTML={{__html: userInput}} />

// FIXED — use JSX (auto-escaped):
<div>{userInput}</div>
// OR sanitize if HTML needed:
import DOMPurify from 'dompurify';
<div dangerouslySetInnerHTML={{__html: DOMPurify.sanitize(userInput)}} />""",
    },

    # ═══ Command Injection ════════════════════════════════
    "command_injection": {
        "python": """# VULNERABLE:
os.system(f"ping {host}")

# FIXED — use subprocess with argument list:
import subprocess
subprocess.run(["ping", "-c", "4", host], capture_output=True)
# NEVER pass user input through shell=True""",

        "javascript": """// VULNERABLE:
exec(`convert ${filename} output.pdf`);

// FIXED — use execFile with argument array:
const { execFile } = require('child_process');
execFile('convert', [filename, 'output.pdf'], callback);""",
    },

    # ═══ Path Traversal ══════════════════════════════════
    "path_traversal": {
        "python": """# VULNERABLE:
filepath = os.path.join(UPLOAD_DIR, request.args['filename'])
return send_file(filepath)

# FIXED — canonicalize and validate:
import os
filename = os.path.basename(request.args['filename'])  # strip directory components
filepath = os.path.realpath(os.path.join(UPLOAD_DIR, filename))
if not filepath.startswith(os.path.realpath(UPLOAD_DIR)):
    abort(403)
return send_file(filepath)""",

        "javascript": """// VULNERABLE:
const filepath = path.join(uploadDir, req.params.file);

// FIXED — validate resolved path is within base dir:
const resolved = path.resolve(uploadDir, req.params.file);
if (!resolved.startsWith(path.resolve(uploadDir))) {
    return res.status(403).send('Access denied');
}""",
    },

    # ═══ SSRF ════════════════════════════════════════════
    "ssrf": {
        "python": """# VULNERABLE:
response = requests.get(user_provided_url)

# FIXED — validate URL against allowlist:
from urllib.parse import urlparse

ALLOWED_HOSTS = {"api.example.com", "cdn.example.com"}
parsed = urlparse(user_provided_url)
if parsed.hostname not in ALLOWED_HOSTS:
    raise ValueError("URL not in allowlist")
if parsed.scheme not in ("http", "https"):
    raise ValueError("Invalid scheme")
response = requests.get(user_provided_url, allow_redirects=False)""",
    },

    # ═══ Hardcoded Secrets ═══════════════════════════════
    "hardcoded_secret": {
        "any": """# VULNERABLE:
API_KEY = "sk-live-abc123def456"

# FIXED — use environment variables:
import os
API_KEY = os.environ.get("API_KEY")
# OR use a secrets manager:
# from aws_secretsmanager import get_secret
# API_KEY = get_secret("my-api-key")""",
    },

    # ═══ Weak Cryptography ═══════════════════════════════
    "weak_crypto": {
        "python": """# VULNERABLE:
password_hash = hashlib.md5(password.encode()).hexdigest()

# FIXED — use bcrypt or scrypt:
import bcrypt
password_hash = bcrypt.hashpw(password.encode(), bcrypt.gensalt())
# Verify: bcrypt.checkpw(password.encode(), stored_hash)""",

        "java": """// VULNERABLE:
MessageDigest md = MessageDigest.getInstance("MD5");

// FIXED — use bcrypt via Spring Security:
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
BCryptPasswordEncoder encoder = new BCryptPasswordEncoder();
String hash = encoder.encode(password);""",
    },

    # ═══ Insecure Deserialization ════════════════════════
    "deserialization": {
        "python": """# VULNERABLE:
data = pickle.loads(user_data)
# OR:
data = yaml.load(user_input)

# FIXED — use safe alternatives:
import json
data = json.loads(user_data)  # JSON is safe
# OR for YAML:
data = yaml.safe_load(user_input)  # safe_load restricts to basic types""",
    },
}


def get_template(vulnerability_category: str, language: str, framework: str = "") -> Optional[str]:
    """
    Look up a remediation template for a vulnerability category + language combo.

    Returns the most specific template available:
    1. language_framework (e.g., "python_django")
    2. language (e.g., "python")
    3. "any" (generic template)
    """
    # Normalize category to template key
    cat_lower = vulnerability_category.lower()
    template_key = None

    category_map = {
        "sql injection": "sql_injection",
        "sqli": "sql_injection",
        "cross-site scripting": "xss",
        "xss": "xss",
        "command injection": "command_injection",
        "os command": "command_injection",
        "path traversal": "path_traversal",
        "directory traversal": "path_traversal",
        "ssrf": "ssrf",
        "server-side request": "ssrf",
        "hardcoded": "hardcoded_secret",
        "credential": "hardcoded_secret",
        "secret": "hardcoded_secret",
        "weak crypto": "weak_crypto",
        "md5": "weak_crypto",
        "sha1": "weak_crypto",
        "insecure hash": "weak_crypto",
        "deserialization": "deserialization",
        "pickle": "deserialization",
        "yaml.load": "deserialization",
    }

    for pattern, key in category_map.items():
        if pattern in cat_lower:
            template_key = key
            break

    if not template_key or template_key not in TEMPLATES:
        return None

    templates = TEMPLATES[template_key]
    lang = language.lower()
    fw = framework.lower().replace(" ", "_")

    # Try most specific first
    if fw:
        specific = f"{lang}_{fw}"
        if specific in templates:
            return templates[specific]
        # Try framework name alone (e.g., "react")
        if fw in templates:
            return templates[fw]

    if lang in templates:
        return templates[lang]

    if "any" in templates:
        return templates["any"]

    # Return first available
    return next(iter(templates.values()), None)
