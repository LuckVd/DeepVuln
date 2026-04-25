"""
P6-05: JavaScript/TypeScript/Node.js Sink and Source Definitions

Integrated from code-audit/references/core/sinks_sources.md
Comprehensive definitions for JavaScript/TypeScript/Node.js including
Express, Koa, Fastify, NestJS, Next.js, and Hapi frameworks.
"""

from src.layers.l3_analysis.sinks_sources.models import (
    SinkCategory,
    SinkDefinition,
    SinkLibrary,
    SourceCategory,
    SourceDefinition,
    SourceLibrary,
)


def get_sink_library() -> SinkLibrary:
    """Get the JavaScript sink library."""
    return SinkLibrary(
        language="javascript",
        sinks=_get_javascript_sinks(),
    )


def get_source_library() -> SourceLibrary:
    """Get the JavaScript source library."""
    return SourceLibrary(
        language="javascript",
        sources=_get_javascript_sources(),
    )


def _get_javascript_sinks() -> list[SinkDefinition]:
    """Get all JavaScript sink definitions."""
    sinks = []

    # =========================================================================
    # RCE - Remote Code Execution (Critical)
    # =========================================================================
    sinks.extend([
        SinkDefinition(
            name="eval_function",
            category=SinkCategory.RCE,
            language="javascript",
            function_patterns=[
                r"\beval\s*\(",
                r"\bFunction\s*\(",
                r"new\s+Function\s*\(",
            ],
            cwe="CWE-95",
            owasp="A03:2021",
            description="Code injection via eval() or Function constructor",
            impact="Arbitrary JavaScript code execution in application context",
            effective_sanitizers=["Avoid eval entirely", "JSON.parse() for data"],
            safe_alternatives=["JSON.parse()", "Use a safe expression evaluator"],
        ),
        SinkDefinition(
            name="child_process_exec",
            category=SinkCategory.RCE,
            language="javascript",
            function_patterns=[
                r"child_process\.exec\s*\(",
                r"child_process\.execSync\s*\(",
                r"require\s*\(\s*['\"]child_process['\"]\s*\).*\.exec\s*\(",
                r"\bexec\s*\([^)]*\)",  # destructured from child_process
                r"\bexecSync\s*\([^)]*\)",
            ],
            cwe="CWE-78",
            owasp="A03:2021",
            description="OS command injection via child_process.exec/execSync",
            impact="Remote code execution with process privileges",
            effective_sanitizers=["Use execFile with argument arrays", "Input validation"],
            safe_alternatives=["child_process.execFile()", "child_process.spawn() without shell"],
        ),
        SinkDefinition(
            name="child_process_spawn_shell",
            category=SinkCategory.RCE,
            language="javascript",
            function_patterns=[
                r"child_process\.spawn\s*\([^)]*shell\s*:\s*true",
                r"child_process\.spawnSync\s*\([^)]*shell\s*:\s*true",
                r"child_process\.execFile\s*\([^)]*shell\s*:\s*true",
                r"\.spawn\s*\([^)]*shell\s*:\s*true",
            ],
            cwe="CWE-78",
            owasp="A03:2021",
            description="Command injection via spawn/execFile with shell:true",
            impact="Shell command injection with process privileges",
            effective_sanitizers=["Remove shell:true option", "Use argument arrays"],
            safe_alternatives=["spawn(cmd, [args]) without shell option"],
        ),
        SinkDefinition(
            name="vm_module",
            category=SinkCategory.RCE,
            language="javascript",
            function_patterns=[
                r"vm\.runInContext\s*\(",
                r"vm\.runInNewContext\s*\(",
                r"vm\.runInThisContext\s*\(",
                r"vm\.Script",
                r"new\s+vm\.Script\s*\(",
                r"vm\.compileFunction\s*\(",
            ],
            cwe="CWE-94",
            owasp="A03:2021",
            description="Code execution via Node.js vm module",
            impact="Arbitrary code execution (vm is not a security sandbox)",
            effective_sanitizers=["Use vm2 or isolated-vm for sandboxing"],
            safe_alternatives=["vm2 library", "isolated-vm", "Worker threads"],
        ),
        SinkDefinition(
            name="set_timeout_string",
            category=SinkCategory.RCE,
            language="javascript",
            function_patterns=[
                r"setTimeout\s*\(\s*['\"]",
                r"setInterval\s*\(\s*['\"]",
                r"setImmediate\s*\(\s*['\"]",
            ],
            cwe="CWE-95",
            owasp="A03:2021",
            description="Code injection via setTimeout/setInterval with string argument",
            impact="Arbitrary JavaScript code execution",
            effective_sanitizers=["Always pass functions, not strings"],
            safe_alternatives=["setTimeout(() => { ... }, delay)"],
        ),
    ])

    # =========================================================================
    # PROTOTYPE POLLUTION (Critical)
    # =========================================================================
    sinks.extend([
        SinkDefinition(
            name="prototype_pollution_merge",
            category=SinkCategory.RCE,
            language="javascript",
            function_patterns=[
                r"\bmerge\s*\(",
                r"\bdefaultsDeep\s*\(",
                r"\bextend\s*\(",
                r"lodash\.merge\s*\(",
                r"lodash\.defaultsDeep\s*\(",
                r"lodash\.set\s*\(",
                r"lodash\.setWith\s*\(",
                r"_.merge\s*\(",
                r"_.defaultsDeep\s*\(",
                r"_.set\s*\(",
            ],
            cwe="CWE-1321",
            owasp="A08:2021",
            description="Prototype pollution via merge/defaultsDeep/set with user-controlled path",
            impact="Denial of service, property injection, potential RCE",
            effective_sanitizers=["Validate keys don't contain __proto__, constructor, prototype"],
            safe_alternatives=["Use Object.create(null)", "Map instead of plain objects"],
        ),
        SinkDefinition(
            name="prototype_pollution_assign",
            category=SinkCategory.RCE,
            language="javascript",
            function_patterns=[
                r"Object\.assign\s*\([^)]*__proto__",
                r"\['__proto__'\]\s*=",
                r"\['__proto__'\]\s*\.",
                r"\.constructor\s*\[\s*['\"]prototype['\"]\s*\]",
                r"\.prototype\s*\[",
            ],
            cwe="CWE-1321",
            owasp="A08:2021",
            description="Direct prototype pollution via __proto__ or constructor.prototype",
            impact="Global object pollution, DoS, potential RCE",
            effective_sanitizers=["Block __proto__, constructor, prototype in user input keys"],
        ),
    ])

    # =========================================================================
    # PATH_TRAVERSAL - Path Traversal (High)
    # =========================================================================
    sinks.extend([
        SinkDefinition(
            name="fs_read",
            category=SinkCategory.PATH_TRAVERSAL,
            language="javascript",
            function_patterns=[
                r"fs\.readFile\s*\(",
                r"fs\.readFileSync\s*\(",
                r"fs\.readdir\s*\(",
                r"fs\.readdirSync\s*\(",
                r"fs\.createReadStream\s*\(",
                r"fs\.promises\.readFile\s*\(",
                r"fs\.promises\.readdir\s*\(",
            ],
            cwe="CWE-22",
            owasp="A01:2021",
            description="Path traversal via fs.readFile/readdir with user-controlled path",
            impact="Arbitrary file read on the server",
            effective_sanitizers=["path.resolve() + validate", "path.normalize() + startsWith check"],
            safe_alternatives=["path.resolve(baseDir, userPath).startsWith(baseDir)"],
        ),
        SinkDefinition(
            name="fs_write",
            category=SinkCategory.PATH_TRAVERSAL,
            language="javascript",
            function_patterns=[
                r"fs\.writeFile\s*\(",
                r"fs\.writeFileSync\s*\(",
                r"fs\.appendFile\s*\(",
                r"fs\.appendFileSync\s*\(",
                r"fs\.createWriteStream\s*\(",
                r"fs\.promises\.writeFile\s*\(",
                r"fs\.promises\.appendFile\s*\(",
            ],
            cwe="CWE-22",
            owasp="A01:2021",
            description="Path traversal via fs.writeFile/appendFile with user-controlled path",
            impact="Arbitrary file write, potential code planting",
            effective_sanitizers=["path.resolve() + validate"],
            safe_alternatives=["path.resolve(baseDir, userPath).startsWith(baseDir)"],
        ),
        SinkDefinition(
            name="fs_delete",
            category=SinkCategory.PATH_TRAVERSAL,
            language="javascript",
            function_patterns=[
                r"fs\.unlink\s*\(",
                r"fs\.unlinkSync\s*\(",
                r"fs\.rmdir\s*\(",
                r"fs\.rmdirSync\s*\(",
                r"fs\.rm\s*\(",
                r"fs\.rmSync\s*\(",
                r"fs\.promises\.unlink\s*\(",
                r"fs\.promises\.rm\s*\(",
            ],
            cwe="CWE-22",
            owasp="A01:2021",
            description="Path traversal via fs.unlink/rmdir with user-controlled path",
            impact="Arbitrary file deletion on the server",
            effective_sanitizers=["path.resolve() + validate against allowed directories"],
        ),
    ])

    # =========================================================================
    # SQLI - SQL Injection (Critical)
    # =========================================================================
    sinks.extend([
        SinkDefinition(
            name="mysql_query",
            category=SinkCategory.SQLI,
            language="javascript",
            function_patterns=[
                r"mysql\.query\s*\(",
                r"mysql2\.query\s*\(",
                r"connection\.query\s*\(",
                r"pool\.query\s*\(",
                r"\.query\s*\(\s*['\"][^'\"]*\+\s*",
                r"\.query\s*\(\s*`[^`]*\$\{",
            ],
            cwe="CWE-89",
            owasp="A03:2021",
            description="SQL injection via mysql/mysql2 query with string concatenation",
            impact="Database compromise, data exfiltration",
            effective_sanitizers=["Parameterized queries with ? placeholders"],
            safe_alternatives=["connection.query('SELECT * FROM users WHERE id = ?', [id])"],
        ),
        SinkDefinition(
            name="pg_query",
            category=SinkCategory.SQLI,
            language="javascript",
            function_patterns=[
                r"pg\.query\s*\(",
                r"client\.query\s*\(",
                r"pool\.query\s*\(",
            ],
            cwe="CWE-89",
            owasp="A03:2021",
            description="SQL injection via PostgreSQL pg query",
            impact="Database compromise",
            effective_sanitizers=["Parameterized queries with $1, $2 placeholders"],
            safe_alternatives=["client.query('SELECT * FROM users WHERE id = $1', [id])"],
        ),
        SinkDefinition(
            name="sequelize_query",
            category=SinkCategory.SQLI,
            language="javascript",
            function_patterns=[
                r"sequelize\.query\s*\(",
                r"\.query\s*\(\s*['\"][^'\"]*\+",
                r"Sequelize\.query\s*\(",
            ],
            cwe="CWE-89",
            owasp="A03:2021",
            description="SQL injection via Sequelize raw query",
            impact="Database compromise",
            effective_sanitizers=["Use Sequelize ORM methods", "replacements option"],
            safe_alternatives=["sequelize.query(sql, { replacements: [id] })"],
        ),
        SinkDefinition(
            name="knex_raw",
            category=SinkCategory.SQLI,
            language="javascript",
            function_patterns=[
                r"knex\.raw\s*\(",
                r"\.raw\s*\(",
                r"\.whereRaw\s*\(",
                r"\.joinRaw\s*\(",
                r"\.havingRaw\s*\(",
            ],
            cwe="CWE-89",
            owasp="A03:2021",
            description="SQL injection via Knex.js raw query",
            impact="Database compromise",
            effective_sanitizers=["Use bindings: knex.raw('?', [userInput])"],
            safe_alternatives=["knex('users').where('id', id) with bindings"],
        ),
        SinkDefinition(
            name="typeorm_query",
            category=SinkCategory.SQLI,
            language="javascript",
            function_patterns=[
                r"\.query\s*\(\s*['\"][^'\"]*\+",
                r"createQueryBuilder.*\.getQuery\s*\(",
                r"repository\.query\s*\(",
            ],
            cwe="CWE-89",
            owasp="A03:2021",
            description="SQL injection via TypeORM raw query",
            impact="Database compromise",
            effective_sanitizers=["Use TypeORM QueryBuilder with parameters"],
            safe_alternatives=["createQueryBuilder().where('user.id = :id', { id })"],
        ),
    ])

    # =========================================================================
    # SSRF - Server-Side Request Forgery (High)
    # =========================================================================
    sinks.extend([
        SinkDefinition(
            name="fetch_api",
            category=SinkCategory.SSRF,
            language="javascript",
            function_patterns=[
                r"\bfetch\s*\(",
                r"node-fetch\s*\(",
                r"isomorphic-fetch\s*\(",
                r"cross-fetch\s*\(",
                r"undici\.fetch\s*\(",
            ],
            cwe="CWE-918",
            owasp="A10:2021",
            description="SSRF via fetch() with user-controlled URL",
            impact="Internal network access, cloud metadata exposure",
            effective_sanitizers=["URL whitelist", "Validate URL scheme and host"],
            safe_alternatives=["Allowlist of permitted domains"],
        ),
        SinkDefinition(
            name="axios",
            category=SinkCategory.SSRF,
            language="javascript",
            function_patterns=[
                r"axios\.get\s*\(",
                r"axios\.post\s*\(",
                r"axios\.put\s*\(",
                r"axios\.delete\s*\(",
                r"axios\.request\s*\(",
                r"axios\(\s*\{",
            ],
            cwe="CWE-918",
            owasp="A10:2021",
            description="SSRF via axios with user-controlled URL",
            impact="Internal network access, SSRF to cloud metadata",
            effective_sanitizers=["URL validation", "Block private IPs"],
        ),
        SinkDefinition(
            name="http_native",
            category=SinkCategory.SSRF,
            language="javascript",
            function_patterns=[
                r"http\.get\s*\(",
                r"http\.request\s*\(",
                r"https\.get\s*\(",
                r"https\.request\s*\(",
            ],
            cwe="CWE-918",
            owasp="A10:2021",
            description="SSRF via Node.js native http/https module",
            impact="Internal network access",
            effective_sanitizers=["URL validation against private IP ranges"],
        ),
        SinkDefinition(
            name="request_lib",
            category=SinkCategory.SSRF,
            language="javascript",
            function_patterns=[
                r"request\s*\(\s*\{[^}]*url\s*:",
                r"request\.get\s*\(",
                r"request\.post\s*\(",
                r"needle\s*\(\s*",
                r"needle\.get\s*\(",
                r"needle\.post\s*\(",
                r"got\s*\(\s*",
                r"superagent\s*\.\s*get\s*\(",
                r"superagent\s*\.\s*post\s*\(",
            ],
            cwe="CWE-918",
            owasp="A10:2021",
            description="SSRF via request/needle/got/superagent with user-controlled URL",
            impact="Internal resource access, cloud metadata exposure",
            effective_sanitizers=["URL whitelist", "DNS resolution validation"],
        ),
    ])

    # =========================================================================
    # XSS - Cross-Site Scripting (Medium)
    # =========================================================================
    sinks.extend([
        SinkDefinition(
            name="express_response_send",
            category=SinkCategory.XSS,
            language="javascript",
            function_patterns=[
                r"res\.send\s*\(",
                r"res\.write\s*\(",
                r"res\.end\s*\(",
                r"res\.json\s*\(.*res\.send",  # chain pattern
            ],
            cwe="CWE-79",
            owasp="A03:2021",
            description="XSS via Express res.send() with unescaped user input",
            impact="Cross-site scripting, session hijacking",
            effective_sanitizers=["HTML escaping", "DOMPurify on server"],
            safe_alternatives=["Template engine with auto-escaping (EJS, Pug)"],
        ),
        SinkDefinition(
            name="template_render_unsafe",
            category=SinkCategory.XSS,
            language="javascript",
            function_patterns=[
                r"res\.render\s*\(",
                r"res\.type\s*\(\s*['\"]html['\"]\s*\)",
            ],
            cwe="CWE-79",
            owasp="A03:2021",
            description="XSS via template rendering without auto-escaping",
            impact="Cross-site scripting",
            effective_sanitizers=["Enable auto-escaping in template engines"],
        ),
        SinkDefinition(
            name="dom_xss",
            category=SinkCategory.XSS,
            language="javascript",
            function_patterns=[
                r"\.innerHTML\s*=",
                r"\.outerHTML\s*=",
                r"document\.write\s*\(",
                r"document\.writeln\s*\(",
                r"\.insertAdjacentHTML\s*\(",
            ],
            cwe="CWE-79",
            owasp="A03:2021",
            description="DOM-based XSS via innerHTML/document.write",
            impact="Cross-site scripting in browser context",
            effective_sanitizers=["DOMPurify.sanitize()", "textContent instead of innerHTML"],
            safe_alternatives=["element.textContent = userInput", "DOMPurify.sanitize(html)"],
        ),
    ])

    # =========================================================================
    # XXE - XML External Entity (High)
    # =========================================================================
    sinks.extend([
        SinkDefinition(
            name="xml_parser",
            category=SinkCategory.XXE,
            language="javascript",
            function_patterns=[
                r"xml2js\.parseString\s*\(",
                r"parseString\s*\(",
                r"xml2js\.Parser\s*\(",
                r"libxmljs\.parseXml\s*\(",
                r"libxmljs2\.parseXml\s*\(",
                r"fast-xml-parser.*parse\s*\(",
                r"XMLParser\s*\(",
                r"sax\.parser\s*\(",
                r"expat\.parser\s*\(",
            ],
            cwe="CWE-611",
            owasp="A05:2021",
            description="XXE via XML parser with entity expansion enabled",
            impact="File disclosure, SSRF, DoS via entity expansion",
            effective_sanitizers=["Disable external entities", "Disable DTD processing"],
            safe_alternatives=["fast-xml-parser with disableEntityResolution", "Configure SAX parser safely"],
        ),
    ])

    # =========================================================================
    # UNSERIALIZE - Deserialization (Critical)
    # =========================================================================
    sinks.extend([
        SinkDefinition(
            name="node_serialize",
            category=SinkCategory.UNSERIALIZE,
            language="javascript",
            function_patterns=[
                r"node-serialize\.unserialize\s*\(",
                r"serialize\.unserialize\s*\(",
                r"serialize-and-deserialize",
                r"\.unserialize\s*\(",
            ],
            cwe="CWE-502",
            owasp="A08:2021",
            description="Insecure deserialization via node-serialize",
            impact="Remote code execution via IIFE in serialized data",
            effective_sanitizers=["Never unserialize untrusted data"],
            safe_alternatives=["JSON.parse()", "Use JSON serialization only"],
        ),
        SinkDefinition(
            name="js_deserialize",
            category=SinkCategory.UNSERIALIZE,
            language="javascript",
            function_patterns=[
                r"deserialize\s*\(",
                r"js-object-serialize",
                r"\.decode\s*\(\s*Buffer\s*\(",
            ],
            cwe="CWE-502",
            owasp="A08:2021",
            description="Insecure JavaScript deserialization",
            impact="Code execution via crafted serialized payload",
            effective_sanitizers=["HMAC signature verification", "Input validation"],
            safe_alternatives=["JSON.parse()", "Protocol Buffers"],
        ),
    ])

    # =========================================================================
    # SSTI - Server-Side Template Injection (High)
    # =========================================================================
    sinks.extend([
        SinkDefinition(
            name="ejs_render",
            category=SinkCategory.SSTI,
            language="javascript",
            function_patterns=[
                r"ejs\.render\s*\(",
                r"ejs\.renderString\s*\(",
                r"res\.render\s*\([^)]*\.\s*render\s*\(",
            ],
            cwe="CWE-94",
            owasp="A03:2021",
            description="Server-side template injection via EJS render",
            impact="Arbitrary code execution via template directives",
            effective_sanitizers=["Avoid rendering user-controlled templates"],
            safe_alternatives=["Pass user data as template variables, not template strings"],
        ),
        SinkDefinition(
            name="pug_render",
            category=SinkCategory.SSTI,
            language="javascript",
            function_patterns=[
                r"pug\.render\s*\(",
                r"pug\.renderFile\s*\(",
                r"pug\.compile\s*\(",
            ],
            cwe="CWE-94",
            owasp="A03:2021",
            description="Server-side template injection via Pug render",
            impact="Arbitrary code execution",
            effective_sanitizers=["Never pass user input as template source"],
        ),
        SinkDefinition(
            name="handlebars_compile",
            category=SinkCategory.SSTI,
            language="javascript",
            function_patterns=[
                r"Handlebars\.compile\s*\(",
                r"Handlebars\.precompile\s*\(",
                r"handlebars\.compile\s*\(",
            ],
            cwe="CWE-94",
            owasp="A03:2021",
            description="Server-side template injection via Handlebars compile",
            impact="Code execution via prototype pollution in Handlebars",
            effective_sanitizers=["Use strict mode", "Sandboxed compilation"],
        ),
        SinkDefinition(
            name="mustache_nunjucks_render",
            category=SinkCategory.SSTI,
            language="javascript",
            function_patterns=[
                r"mustache\.render\s*\(",
                r"Mustache\.render\s*\(",
                r"nunjucks\.renderString\s*\(",
                r"nunjucks\.render\s*\(",
                r"nunjucks\.compile\s*\(",
                r"nunjucks\.Environment.*\.renderString\s*\(",
            ],
            cwe="CWE-94",
            owasp="A03:2021",
            description="Server-side template injection via Mustache or Nunjucks",
            impact="Potential code execution via template directives",
            effective_sanitizers=["Avoid rendering user-controlled template source"],
            safe_alternatives=["Use templates for layout only, pass data as variables"],
        ),
    ])

    # =========================================================================
    # LDAP - LDAP Injection (High)
    # =========================================================================
    sinks.extend([
        SinkDefinition(
            name="ldap_search",
            category=SinkCategory.LDAP,
            language="javascript",
            function_patterns=[
                r"ldapjs.*\.search\s*\(",
                r"ldap\.search\s*\(",
                r"client\.search\s*\(",
                r"ldapts.*\.search\s*\(",
            ],
            cwe="CWE-90",
            owasp="A03:2021",
            description="LDAP injection via ldapjs search with user input",
            impact="Authentication bypass, directory data disclosure",
            effective_sanitizers=["LDAP escape special characters", "Parameterized LDAP filters"],
            safe_alternatives=["Escape ( ) * \\ and NUL characters in user input"],
        ),
    ])

    # =========================================================================
    # REDIRECT - Open Redirect (Medium)
    # =========================================================================
    sinks.extend([
        SinkDefinition(
            name="express_redirect",
            category=SinkCategory.REDIRECT,
            language="javascript",
            function_patterns=[
                r"res\.redirect\s*\(",
                r"response\.redirect\s*\(",
                r"ctx\.redirect\s*\(",
                r"reply\.redirect\s*\(",
            ],
            cwe="CWE-601",
            owasp="A01:2021",
            description="Open redirect via res.redirect with user-controlled URL",
            impact="Phishing attacks, authentication bypass",
            effective_sanitizers=["Validate URL is relative or on allowlist"],
            safe_alternatives=["Allow only relative URLs or whitelisted domains"],
        ),
        SinkDefinition(
            name="header_redirect",
            category=SinkCategory.REDIRECT,
            language="javascript",
            function_patterns=[
                r"res\.writeHead\s*\(\s*\d{3}[^)]*Location",
                r"res\.setHeader\s*\(\s*['\"]Location['\"]",
                r"response\.setHeader\s*\(\s*['\"]Location['\"]",
            ],
            cwe="CWE-601",
            owasp="A01:2021",
            description="Open redirect via Location header manipulation",
            impact="Phishing attacks via crafted redirect URL",
            effective_sanitizers=["Validate redirect target"],
        ),
    ])

    # =========================================================================
    # Weak Crypto (Medium)
    # =========================================================================
    sinks.extend([
        SinkDefinition(
            name="weak_hash",
            category=SinkCategory.RCE,
            language="javascript",
            function_patterns=[
                r"crypto\.createHash\s*\(\s*['\"]md5['\"]\s*\)",
                r"crypto\.createHash\s*\(\s*['\"]sha1['\"]\s*\)",
                r"crypto\.createHash\s*\(\s*['\"]sha['\"]\s*\)",
                r"md5\s*\(",
                r"sha1\s*\(",
            ],
            cwe="CWE-328",
            owasp="A02:2021",
            description="Weak cryptographic hash algorithm (MD5/SHA1)",
            impact="Hash collision attacks, password cracking",
            effective_sanitizers=["Use SHA-256 or stronger"],
            safe_alternatives=["crypto.createHash('sha256')", "bcrypt for passwords", "argon2"],
        ),
        SinkDefinition(
            name="weak_cipher",
            category=SinkCategory.RCE,
            language="javascript",
            function_patterns=[
                r"crypto\.createCipher\s*\(\s*['\"]des['\"]\s*\)",
                r"crypto\.createCipher\s*\(\s*['\"]rc4['\"]\s*\)",
                r"crypto\.createCipheriv\s*\(\s*['\"]des['\"]\s*\)",
                r"crypto\.createCipheriv\s*\(\s*['\"]aes-128-ecb['\"]\s*\)",
                r"crypto\.createCipheriv\s*\(\s*['\"]rc4['\"]\s*\)",
                r"crypto\.createCipher\s*\(",  # deprecated in Node.js
            ],
            cwe="CWE-327",
            owasp="A02:2021",
            description="Weak or deprecated encryption algorithm",
            impact="Data confidentiality compromise",
            effective_sanitizers=["Use AES-256-GCM or ChaCha20-Poly1305"],
            safe_alternatives=["crypto.createCipheriv('aes-256-gcm', key, iv)"],
        ),
    ])

    # =========================================================================
    # ReDoS - Regular Expression Denial of Service (Medium)
    # =========================================================================
    sinks.extend([
        SinkDefinition(
            name="regex_dos",
            category=SinkCategory.RCE,
            language="javascript",
            function_patterns=[
                r"new\s+RegExp\s*\(",
                r"RegExp\s*\(",
            ],
            cwe="CWE-1333",
            owasp="A05:2021",
            description="ReDoS via RegExp with user-controlled pattern or input",
            impact="Denial of service via catastrophic backtracking",
            effective_sanitizers=["Use safe-regex to validate patterns", "Limit input length"],
            safe_alternatives=["Pre-compiled regex", "re2 module (Google RE2 engine)"],
        ),
    ])

    return sinks


def _get_javascript_sources() -> list[SourceDefinition]:
    """Get all JavaScript source definitions."""
    sources = []

    # =========================================================================
    # Express Sources
    # =========================================================================
    sources.extend([
        SourceDefinition(
            name="express_params",
            category=SourceCategory.HTTP_PARAM,
            language="javascript",
            function_patterns=[
                r"req\.params",
                r"req\.params\s*\[",
                r"request\.params",
                r"request\.params\s*\[",
            ],
            risk_level="high",
            controllability="full",
            description="Express URL path parameters",
            example='app.get("/user/:id", (req, res) => { const id = req.params.id; })',
        ),
        SourceDefinition(
            name="express_query",
            category=SourceCategory.HTTP_PARAM,
            language="javascript",
            function_patterns=[
                r"req\.query",
                r"req\.query\s*\.",
                r"req\.query\s*\[",
                r"request\.query",
                r"request\.query\s*\[",
            ],
            risk_level="high",
            controllability="full",
            description="Express query string parameters",
            example='const name = req.query.name;',
        ),
        SourceDefinition(
            name="express_body",
            category=SourceCategory.HTTP_PARAM,
            language="javascript",
            function_patterns=[
                r"req\.body",
                r"req\.body\s*\.",
                r"req\.body\s*\[",
                r"request\.body",
                r"request\.body\s*\[",
            ],
            risk_level="high",
            controllability="full",
            description="Express request body (parsed by body-parser)",
            example='const email = req.body.email;',
        ),
        SourceDefinition(
            name="express_headers",
            category=SourceCategory.HTTP_HEADER,
            language="javascript",
            function_patterns=[
                r"req\.headers",
                r"req\.headers\s*\[",
                r"req\.get\s*\(",
                r"req\.header\s*\(",
                r"request\.headers",
                r"request\.get\s*\(",
            ],
            risk_level="high",
            controllability="full",
            description="Express request headers",
            example='const token = req.get("Authorization");',
        ),
        SourceDefinition(
            name="express_cookies",
            category=SourceCategory.COOKIE,
            language="javascript",
            function_patterns=[
                r"req\.cookies",
                r"req\.cookies\s*\[",
                r"req\.cookies\s*\.",
                r"req\.signedCookies",
                r"request\.cookies",
            ],
            risk_level="high",
            controllability="full",
            description="Express cookies (via cookie-parser middleware)",
            example='const session = req.cookies.session_id;',
        ),
        SourceDefinition(
            name="express_param_deprecated",
            category=SourceCategory.HTTP_PARAM,
            language="javascript",
            function_patterns=[
                r"req\.param\s*\(",
                r"request\.param\s*\(",
            ],
            risk_level="high",
            controllability="full",
            description="Express req.param() (deprecated, checks params/query/body)",
            example='const id = req.param("id");',
        ),
    ])

    # =========================================================================
    # Koa Sources
    # =========================================================================
    sources.extend([
        SourceDefinition(
            name="koa_params",
            category=SourceCategory.HTTP_PARAM,
            language="javascript",
            function_patterns=[
                r"ctx\.params",
                r"ctx\.params\s*\[",
                r"ctx\.params\s*\.",
            ],
            risk_level="high",
            controllability="full",
            description="Koa URL path parameters (via koa-router)",
            example='router.get("/user/:id", (ctx) => { const id = ctx.params.id; })',
        ),
        SourceDefinition(
            name="koa_query",
            category=SourceCategory.HTTP_PARAM,
            language="javascript",
            function_patterns=[
                r"ctx\.query",
                r"ctx\.query\s*\.",
                r"ctx\.query\s*\[",
                r"ctx\.request\.query",
                r"ctx\.request\.querystring",
            ],
            risk_level="high",
            controllability="full",
            description="Koa query string parameters",
            example='const page = ctx.query.page;',
        ),
        SourceDefinition(
            name="koa_body",
            category=SourceCategory.HTTP_PARAM,
            language="javascript",
            function_patterns=[
                r"ctx\.request\.body",
                r"ctx\.request\.body\s*\.",
                r"ctx\.request\.body\s*\[",
                r"ctx\.request\.type",
            ],
            risk_level="high",
            controllability="full",
            description="Koa request body (via koa-bodyparser)",
            example='const data = ctx.request.body;',
        ),
        SourceDefinition(
            name="koa_headers",
            category=SourceCategory.HTTP_HEADER,
            language="javascript",
            function_patterns=[
                r"ctx\.headers",
                r"ctx\.header",
                r"ctx\.headers\s*\[",
                r"ctx\.get\s*\(",
                r"ctx\.request\.headers",
            ],
            risk_level="high",
            controllability="full",
            description="Koa request headers",
            example='const auth = ctx.get("Authorization");',
        ),
    ])

    # =========================================================================
    # Fastify Sources
    # =========================================================================
    sources.extend([
        SourceDefinition(
            name="fastify_params",
            category=SourceCategory.HTTP_PARAM,
            language="javascript",
            function_patterns=[
                r"request\.params",
                r"req\.params",
                r"request\.params\s*\[",
            ],
            risk_level="high",
            controllability="full",
            description="Fastify URL path parameters",
            example='fastify.get("/user/:id", (request, reply) => { const id = request.params.id; })',
        ),
        SourceDefinition(
            name="fastify_query",
            category=SourceCategory.HTTP_PARAM,
            language="javascript",
            function_patterns=[
                r"request\.query",
                r"req\.query",
                r"request\.query\s*\.",
                r"request\.query\s*\[",
            ],
            risk_level="high",
            controllability="full",
            description="Fastify query string parameters",
            example='const search = request.query.search;',
        ),
        SourceDefinition(
            name="fastify_body",
            category=SourceCategory.HTTP_PARAM,
            language="javascript",
            function_patterns=[
                r"request\.body",
                r"req\.body",
                r"request\.body\s*\.",
                r"request\.body\s*\[",
            ],
            risk_level="high",
            controllability="full",
            description="Fastify request body",
            example='const data = request.body;',
        ),
    ])

    # =========================================================================
    # NestJS Sources (Decorators)
    # =========================================================================
    sources.extend([
        SourceDefinition(
            name="nestjs_request",
            category=SourceCategory.HTTP_PARAM,
            language="javascript",
            annotation_patterns=[
                r"@Req\s*\(",
                r"@Request\s*\(",
            ],
            risk_level="high",
            controllability="full",
            description="NestJS @Req()/@Request() decorator for full request object",
            example='constructor(@Req() req: Request) { const body = req.body; }',
        ),
        SourceDefinition(
            name="nestjs_param",
            category=SourceCategory.HTTP_PARAM,
            language="javascript",
            annotation_patterns=[
                r"@Param\s*\(",
                r"@Params\s*\(",
            ],
            risk_level="high",
            controllability="full",
            description="NestJS @Param() decorator for route parameters",
            example='getUser(@Param("id") id: string)',
        ),
        SourceDefinition(
            name="nestjs_query",
            category=SourceCategory.HTTP_PARAM,
            language="javascript",
            annotation_patterns=[
                r"@Query\s*\(",
            ],
            risk_level="high",
            controllability="full",
            description="NestJS @Query() decorator for query parameters",
            example='search(@Query("q") query: string)',
        ),
        SourceDefinition(
            name="nestjs_body",
            category=SourceCategory.HTTP_PARAM,
            language="javascript",
            annotation_patterns=[
                r"@Body\s*\(",
            ],
            risk_level="high",
            controllability="full",
            description="NestJS @Body() decorator for request body",
            example='create(@Body() createDto: CreateDto)',
        ),
        SourceDefinition(
            name="nestjs_headers",
            category=SourceCategory.HTTP_HEADER,
            language="javascript",
            annotation_patterns=[
                r"@Headers\s*\(",
                r"@Header\s*\(",
            ],
            risk_level="high",
            controllability="full",
            description="NestJS @Headers() decorator for HTTP headers",
            example='handler(@Headers("authorization") auth: string)',
        ),
        SourceDefinition(
            name="nestjs_ip",
            category=SourceCategory.HTTP_HEADER,
            language="javascript",
            annotation_patterns=[
                r"@Ip\s*\(",
                r"@ClientIp\s*\(",
            ],
            risk_level="medium",
            controllability="partial",
            description="NestJS @Ip() decorator for client IP address (X-Forwarded-For spoofable)",
            example='handler(@Ip() ip: string)',
        ),
    ])

    # =========================================================================
    # Next.js Sources
    # =========================================================================
    sources.extend([
        SourceDefinition(
            name="nextjs_query",
            category=SourceCategory.HTTP_PARAM,
            language="javascript",
            function_patterns=[
                r"req\.query",
                r"router\.query",
                r"useRouter\s*\(\s*\).*\.query",
                r"searchParams\.get\s*\(",
                r"URLSearchParams\s*\(",
            ],
            risk_level="high",
            controllability="full",
            description="Next.js query parameters (pages router and app router)",
            example='const { id } = req.query;',
        ),
        SourceDefinition(
            name="nextjs_body",
            category=SourceCategory.HTTP_PARAM,
            language="javascript",
            function_patterns=[
                r"req\.body",
                r"await\s+request\.json\s*\(\s*\)",
                r"await\s+req\.json\s*\(\s*\)",
                r"await\s+request\.text\s*\(\s*\)",
                r"await\s+request\.formData\s*\(\s*\)",
            ],
            risk_level="high",
            controllability="full",
            description="Next.js request body (API routes and server actions)",
            example='const body = await request.json();',
        ),
    ])

    # =========================================================================
    # Hapi Sources
    # =========================================================================
    sources.extend([
        SourceDefinition(
            name="hapi_params",
            category=SourceCategory.HTTP_PARAM,
            language="javascript",
            function_patterns=[
                r"request\.params",
                r"request\.params\s*\[",
                r"request\.params\s*\.",
            ],
            risk_level="high",
            controllability="full",
            description="Hapi URL path parameters",
            example='handler: (request) => { const id = request.params.id; }',
        ),
        SourceDefinition(
            name="hapi_query",
            category=SourceCategory.HTTP_PARAM,
            language="javascript",
            function_patterns=[
                r"request\.query",
                r"request\.query\s*\.",
                r"request\.query\s*\[",
                r"request\.url\.searchParams\.get\s*\(",
            ],
            risk_level="high",
            controllability="full",
            description="Hapi query string parameters",
            example='const page = request.query.page;',
        ),
        SourceDefinition(
            name="hapi_payload",
            category=SourceCategory.HTTP_PARAM,
            language="javascript",
            function_patterns=[
                r"request\.payload",
                r"request\.payload\s*\.",
                r"request\.payload\s*\[",
            ],
            risk_level="high",
            controllability="full",
            description="Hapi request payload (body)",
            example='const data = request.payload;',
        ),
    ])

    # =========================================================================
    # File Upload Sources
    # =========================================================================
    sources.extend([
        SourceDefinition(
            name="multer_upload",
            category=SourceCategory.FILE_UPLOAD,
            language="javascript",
            function_patterns=[
                r"req\.file",
                r"req\.files",
                r"req\.file\s*\.",
                r"req\.files\s*\[",
                r"multer\s*\(",
                r"upload\.single\s*\(",
                r"upload\.array\s*\(",
                r"upload\.fields\s*\(",
            ],
            risk_level="critical",
            controllability="full",
            description="File upload via multer middleware",
            example="const file = req.file; // multer populated",
        ),
        SourceDefinition(
            name="formidable_upload",
            category=SourceCategory.FILE_UPLOAD,
            language="javascript",
            function_patterns=[
                r"formidable\s*\(",
                r"form\.parse\s*\(",
                r"form\.on\s*\(\s*['\"]file['\"]",
                r"IncomingForm\s*\(",
            ],
            risk_level="critical",
            controllability="full",
            description="File upload via formidable",
            example="form.parse(req, (err, fields, files) => { ... })",
        ),
        SourceDefinition(
            name="busboy_upload",
            category=SourceCategory.FILE_UPLOAD,
            language="javascript",
            function_patterns=[
                r"busboy\s*\(",
                r"Busboy\s*\(",
                r"new\s+Busboy\s*\(",
                r"\.on\s*\(\s*['\"]file['\"]",
            ],
            risk_level="critical",
            controllability="full",
            description="File upload via busboy",
            example="const busboy = new Busboy({ headers: req.headers })",
        ),
    ])

    # =========================================================================
    # WebSocket Sources
    # =========================================================================
    sources.extend([
        SourceDefinition(
            name="ws_message",
            category=SourceCategory.WEBSOCKET,
            language="javascript",
            function_patterns=[
                r"ws\.on\s*\(\s*['\"]message['\"]",
                r"\.on\s*\(\s*['\"]message['\"]\s*,\s*\([^)]*\)\s*=>",
                r"WebSocket.*\.onmessage",
                r"ws\.onmessage",
                r"event\.data",
            ],
            risk_level="high",
            controllability="full",
            description="WebSocket message data (ws library)",
            example="ws.on('message', (data) => { const msg = data.toString(); })",
        ),
        SourceDefinition(
            name="socketio_data",
            category=SourceCategory.WEBSOCKET,
            language="javascript",
            function_patterns=[
                r"socket\.on\s*\(",
                r"io\.on\s*\(\s*['\"]connection['\"]",
                r"socket\.emit\s*\(",
                r"io\.emit\s*\(",
                r"socket\.broadcast\.emit\s*\(",
            ],
            risk_level="high",
            controllability="full",
            description="Socket.IO event data",
            example='socket.on("chat", (data) => { ... })',
        ),
    ])

    # =========================================================================
    # Process Sources
    # =========================================================================
    sources.extend([
        SourceDefinition(
            name="process_argv",
            category=SourceCategory.COMMAND_LINE,
            language="javascript",
            variable_patterns=[
                r"process\.argv",
                r"process\.argv\s*\[",
                r"process\.argv\.slice\s*\(",
                r"minimist\s*\(\s*process\.argv",
                r"yargs\.argv",
            ],
            risk_level="medium",
            controllability="full",
            description="Command line arguments via process.argv",
            example='const args = process.argv.slice(2);',
        ),
        SourceDefinition(
            name="process_env",
            category=SourceCategory.ENVIRONMENT,
            language="javascript",
            variable_patterns=[
                r"process\.env",
                r"process\.env\s*\[",
                r"process\.env\.\w+",
            ],
            risk_level="low",
            controllability="none",
            description="Environment variables via process.env",
            example='const dbUrl = process.env.DATABASE_URL;',
        ),
    ])

    return sources


__all__ = [
    "get_sink_library",
    "get_source_library",
]
