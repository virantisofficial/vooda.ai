# SPDX-FileCopyrightText: 2026 Virantis
# SPDX-License-Identifier: LicenseRef-Vooda-Community-1.0

"""
Framework-specific security context for AI prompt augmentation.

Each framework entry contains:
- Common security protections (what the framework does automatically)
- Safe APIs (functions/patterns that indicate proper security)
- Unsafe patterns (anti-patterns specific to this framework)
- Common false positive causes (why scanners flag safe code)

Used by triage v2 and remediation prompts to give AI framework awareness.
"""

from typing import Optional


FRAMEWORK_SECURITY_CONTEXT: dict[str, dict] = {
    # ═══ Python Frameworks ═══════════════════════════════════
    "django": {
        "name": "Django",
        "protections": [
            "Django ORM auto-parameterizes all queries — raw SQL injection via ORM is not possible",
            "Django templates auto-escape HTML by default — XSS requires explicit |safe filter or mark_safe()",
            "CSRF middleware is enabled by default — POST/PUT/DELETE requests require CSRF token",
            "Django's password hashers use PBKDF2/Argon2/bcrypt by default — not MD5/SHA1",
            "Django's SECURE_BROWSER_XSS_FILTER, SECURE_CONTENT_TYPE_NOSNIFF are available as settings",
            "clickjacking protection via X-Frame-Options middleware is enabled by default",
        ],
        "safe_apis": [
            "Model.objects.filter() — parameterized",
            "Model.objects.get() — parameterized",
            "Model.objects.create() — parameterized",
            "connection.cursor().execute(sql, params) — with params tuple is safe",
            "render(request, template, context) — auto-escaped",
            "JsonResponse() — safe serialization",
            "@login_required — authentication enforcement",
            "@permission_required — authorization enforcement",
            "csrf_protect decorator",
        ],
        "unsafe_patterns": [
            "Model.objects.raw(f'SELECT...{user_input}') — raw SQL with f-string",
            "Model.objects.extra(where=[f'...{input}...']) — extra() with formatting",
            "cursor.execute(f'SELECT...{input}') — raw cursor without params",
            "mark_safe(user_input) — marking user data as safe HTML",
            "{{ variable|safe }} — disabling auto-escape in templates",
            "@csrf_exempt — disabling CSRF protection",
            "ALLOWED_HOSTS = ['*'] — accepting all hosts",
            "DEBUG = True in production",
        ],
        "fp_causes": [
            "ORM queries flagged as SQLi — ORM auto-parameterizes",
            "Template variables flagged as XSS — Django auto-escapes by default",
            "CSRF findings on GET endpoints — GET doesn't need CSRF",
            "Password hashing findings when using Django's built-in auth — uses PBKDF2 by default",
        ],
    },

    "flask": {
        "name": "Flask",
        "protections": [
            "Jinja2 templates auto-escape HTML in .html templates by default",
            "Flask-WTF provides CSRF protection (not enabled by default — must be configured)",
            "Flask-Login provides session management",
            "Flask-SQLAlchemy uses parameterized queries through SQLAlchemy ORM",
        ],
        "safe_apis": [
            "db.session.query().filter() — SQLAlchemy parameterized",
            "db.session.execute(text(sql), params) — with bindparams",
            "render_template() — auto-escaped Jinja2",
            "jsonify() — safe JSON response",
            "@login_required from Flask-Login",
            "url_for() — safe URL generation",
            "escape() from markupsafe — explicit HTML escaping",
        ],
        "unsafe_patterns": [
            "db.engine.execute(f'SELECT...{input}') — raw SQL with f-string",
            "render_template_string(user_input) — SSTI vulnerability",
            "Markup(user_input) — marking user data as safe",
            "send_file(user_input) — path traversal if unvalidated",
            "app.run(debug=True) in production",
            "SECRET_KEY hardcoded in source",
        ],
        "fp_causes": [
            "SQLAlchemy ORM queries flagged as SQLi — auto-parameterized",
            "Jinja2 template variables flagged as XSS — auto-escaped in .html files",
            "url_for() flagged as open redirect — generates internal URLs only",
        ],
    },

    "fastapi": {
        "name": "FastAPI",
        "protections": [
            "Pydantic models validate and coerce all input data automatically",
            "SQLAlchemy/SQLModel ORM auto-parameterizes queries",
            "Automatic OpenAPI schema validation rejects malformed input",
            "Response models strip undeclared fields from output",
            "Dependency injection system for auth/permissions",
        ],
        "safe_apis": [
            "Depends() — dependency injection for auth checks",
            "HTTPBearer/OAuth2PasswordBearer — token validation",
            "Pydantic BaseModel — input validation",
            "SQLModel/SQLAlchemy ORM queries — parameterized",
            "Response model filtering — prevents data leakage",
        ],
        "unsafe_patterns": [
            "Raw SQL via f-strings bypassing ORM",
            "Disabling Pydantic validation with Any type",
            "Returning dict instead of response_model — no output filtering",
        ],
        "fp_causes": [
            "Pydantic-validated inputs flagged as unsanitized — Pydantic validates types",
            "SQLModel queries flagged as SQLi — auto-parameterized",
        ],
    },

    # ═══ JavaScript Frameworks ═══════════════════════════════
    "express": {
        "name": "Express.js",
        "protections": [
            "helmet middleware adds security headers (CSP, HSTS, X-Frame-Options, etc.)",
            "express-rate-limit provides rate limiting",
            "cors middleware controls cross-origin access",
            "express-validator provides input validation",
        ],
        "safe_apis": [
            "res.json() — safe JSON serialization",
            "req.params / req.query with validation — parameterized routes",
            "parameterized queries with ? placeholders in mysql2/pg",
            "bcrypt.hash() / bcrypt.compare() — safe password hashing",
            "express-validator check() / validationResult()",
        ],
        "unsafe_patterns": [
            "res.send(userInput) — direct HTML injection",
            "eval(req.body.code) — code injection",
            "child_process.exec(userInput) — command injection",
            "fs.readFile(req.params.file) — path traversal",
            "SQL string concatenation with template literals",
        ],
        "fp_causes": [
            "helmet-protected apps flagged for missing headers — helmet adds them",
            "Parameterized SQL queries flagged as SQLi — ? placeholders are safe",
        ],
    },

    "react": {
        "name": "React",
        "protections": [
            "JSX auto-escapes all embedded expressions — prevents XSS by default",
            "React DOM escapes values before rendering",
            "React does NOT auto-escape dangerouslySetInnerHTML — this is intentionally unsafe",
        ],
        "safe_apis": [
            "JSX expressions {variable} — auto-escaped",
            "React.createElement() — auto-escaped",
            "textContent / innerText — safe text insertion",
        ],
        "unsafe_patterns": [
            "dangerouslySetInnerHTML={{__html: userInput}} — XSS",
            "eval() with user data",
            "document.write() with user data",
            "innerHTML = userInput",
        ],
        "fp_causes": [
            "JSX variables flagged as XSS — React auto-escapes expressions",
            "Static HTML in dangerouslySetInnerHTML flagged — safe if content is constant",
        ],
    },

    "nextjs": {
        "name": "Next.js",
        "protections": [
            "Inherits all React auto-escaping protections",
            "Server-side rendering doesn't expose client secrets",
            "API routes are server-only — no client-side exposure",
            "next/image component prevents image-based attacks",
            "Built-in CSRF protection in server actions (Next 14+)",
        ],
        "safe_apis": [
            "getServerSideProps — server-only data fetching",
            "API routes (pages/api/*) — server-side only",
            "next/headers — safe header access",
            "Server Components — no client-side JS exposure",
        ],
        "unsafe_patterns": [
            "Exposing secrets via NEXT_PUBLIC_ prefix — visible to client",
            "dangerouslySetInnerHTML in components",
            "eval() in API routes",
        ],
        "fp_causes": [
            "Server-side code flagged for client-side vulnerabilities — runs on server only",
        ],
    },

    # ═══ Java Frameworks ═════════════════════════════════════
    "spring_boot": {
        "name": "Spring Boot",
        "protections": [
            "Spring Security provides comprehensive auth/authz when configured",
            "CSRF protection enabled by default in Spring Security",
            "Thymeleaf templates auto-escape HTML by default",
            "Spring Data JPA uses parameterized queries",
            "Spring MVC input binding validates @RequestParam types",
            "Content-Type negotiation prevents type confusion",
        ],
        "safe_apis": [
            "JpaRepository methods — auto-parameterized",
            "@Query with :param named parameters — parameterized",
            "JdbcTemplate.query(sql, params) — parameterized",
            "Thymeleaf th:text — auto-escaped",
            "@PreAuthorize / @Secured — method-level auth",
            "@Valid / @Validated — input validation",
            "BCryptPasswordEncoder — safe password hashing",
        ],
        "unsafe_patterns": [
            "String concatenation in @Query (JPQL injection)",
            "EntityManager.createQuery(dynamicString) — HQL injection",
            "th:utext in Thymeleaf — unescaped HTML",
            "@CrossOrigin(origins='*') — open CORS",
            "Exposed Actuator endpoints without auth",
            "spring.datasource.password in application.properties (hardcoded)",
        ],
        "fp_causes": [
            "JPA named parameters flagged as SQLi — parameterized by framework",
            "Thymeleaf th:text flagged as XSS — auto-escaped",
            "CSRF findings on REST APIs with JWT — stateless APIs don't need CSRF",
        ],
    },

    # ═══ Go Frameworks ═══════════════════════════════════════
    "gin": {
        "name": "Gin",
        "protections": [
            "html/template auto-escapes HTML output",
            "Gin's binding and validation with struct tags",
        ],
        "safe_apis": [
            "c.JSON() — safe JSON response",
            "db.Query(sql, args...) — parameterized with database/sql",
            "c.ShouldBindJSON(&obj) — struct-based input validation",
            "template.HTML() should only be used with trusted content",
        ],
        "unsafe_patterns": [
            "fmt.Sprintf with SQL queries — SQL injection",
            "os.exec with user input — command injection",
            "template.HTML(userInput) — XSS",
            "ioutil.ReadFile(userInput) — path traversal",
        ],
        "fp_causes": [
            "database/sql parameterized queries flagged as SQLi — safe with ? placeholders",
            "html/template output flagged as XSS — auto-escaped",
        ],
    },

    # ═══ Ruby Frameworks ═════════════════════════════════════
    "rails": {
        "name": "Ruby on Rails",
        "protections": [
            "ActiveRecord auto-parameterizes all queries",
            "ERB templates auto-escape with <%= %> by default",
            "CSRF protection via protect_from_forgery",
            "Strong Parameters require explicit permit",
            "has_secure_password uses bcrypt",
        ],
        "safe_apis": [
            "Model.where(field: value) — parameterized",
            "Model.find_by(field: value) — parameterized",
            "<%= expression %> — auto-escaped ERB",
            "params.require(:model).permit(:fields) — strong params",
            "redirect_to with only_path: true — prevents open redirect",
        ],
        "unsafe_patterns": [
            "Model.where(\"field = '#{input}'\") — string interpolation in SQL",
            "<%== expression %> or raw() — unescaped output",
            "send(user_input) — arbitrary method invocation",
            "YAML.load(user_input) — insecure deserialization",
        ],
        "fp_causes": [
            "ActiveRecord queries flagged as SQLi — auto-parameterized",
            "ERB auto-escaped output flagged as XSS — safe by default",
        ],
    },

    # ═══ PHP Frameworks ══════════════════════════════════════
    "laravel": {
        "name": "Laravel",
        "protections": [
            "Eloquent ORM auto-parameterizes all queries",
            "Blade templates auto-escape with {{ }} by default",
            "CSRF middleware enabled by default on web routes",
            "Laravel's Hash facade uses bcrypt/Argon2",
            "Validation rules via FormRequest classes",
        ],
        "safe_apis": [
            "Model::where('field', $value) — parameterized",
            "DB::select('SELECT * WHERE id = ?', [$id]) — parameterized",
            "{{ $variable }} in Blade — auto-escaped",
            "Hash::make() / Hash::check() — safe password ops",
            "Storage::get() with path validation — safe file access",
        ],
        "unsafe_patterns": [
            "DB::raw(\"...{$input}...\") — raw SQL with interpolation",
            "{!! $variable !!} in Blade — unescaped output",
            "eval($userInput) — code injection",
            "file_get_contents($userUrl) — SSRF",
        ],
        "fp_causes": [
            "Eloquent queries flagged as SQLi — auto-parameterized",
            "Blade {{ }} output flagged as XSS — auto-escaped",
        ],
    },
}


def get_framework_context(frameworks: list[str]) -> str:
    """
    Build a framework context block for AI prompts based on detected frameworks.

    Returns a formatted string containing security protections, safe APIs,
    and common FP causes for all detected frameworks.
    """
    if not frameworks:
        return ""

    sections = []

    for fw_name in frameworks:
        fw_key = fw_name.lower().replace(" ", "_").replace(".", "")

        # Try exact match, then partial match
        ctx = FRAMEWORK_SECURITY_CONTEXT.get(fw_key)
        if not ctx:
            for key, val in FRAMEWORK_SECURITY_CONTEXT.items():
                if key in fw_key or fw_key in key or val["name"].lower() == fw_name.lower():
                    ctx = val
                    break

        if not ctx:
            continue

        block = f"\n### {ctx['name']} Security Context\n"
        block += "\n**Built-in Protections:**\n"
        for p in ctx["protections"]:
            block += f"- {p}\n"

        block += "\n**Safe APIs (NOT vulnerable):**\n"
        for api in ctx["safe_apis"][:8]:
            block += f"- {api}\n"

        block += "\n**Known False Positive Causes:**\n"
        for fp in ctx["fp_causes"]:
            block += f"- {fp}\n"

        sections.append(block)

    return "\n".join(sections) if sections else ""


def get_remediation_context(frameworks: list[str], vulnerability_category: str) -> str:
    """
    Get framework-specific remediation guidance for a vulnerability category.
    Used to augment AI remediation prompts.
    """
    if not frameworks:
        return ""

    sections = []
    category_lower = vulnerability_category.lower()

    for fw_name in frameworks:
        fw_key = fw_name.lower().replace(" ", "_").replace(".", "")
        ctx = FRAMEWORK_SECURITY_CONTEXT.get(fw_key)
        if not ctx:
            for key, val in FRAMEWORK_SECURITY_CONTEXT.items():
                if key in fw_key or fw_key in key:
                    ctx = val
                    break

        if not ctx:
            continue

        # Find relevant safe APIs based on vulnerability category
        relevant_safe = []
        for api in ctx["safe_apis"]:
            api_lower = api.lower()
            if "sql" in category_lower and ("parameterized" in api_lower or "sql" in api_lower or "query" in api_lower or "orm" in api_lower):
                relevant_safe.append(api)
            elif ("xss" in category_lower or "cross-site" in category_lower or "scripting" in category_lower) and ("escape" in api_lower or "template" in api_lower or "html" in api_lower or "json" in api_lower or "text" in api_lower):
                relevant_safe.append(api)
            elif "csrf" in category_lower and ("csrf" in api_lower or "token" in api_lower):
                relevant_safe.append(api)
            elif ("auth" in category_lower or "access" in category_lower) and ("auth" in api_lower or "login" in api_lower or "permission" in api_lower):
                relevant_safe.append(api)
            elif "password" in category_lower and ("hash" in api_lower or "password" in api_lower or "bcrypt" in api_lower):
                relevant_safe.append(api)

        if relevant_safe:
            block = f"\n**{ctx['name']} — Recommended Safe APIs for {vulnerability_category}:**\n"
            for api in relevant_safe:
                block += f"- {api}\n"
            sections.append(block)

    return "\n".join(sections) if sections else ""
