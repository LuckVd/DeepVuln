"""
P6-05: PHP Sink and Source Definitions

Integrated from code-audit/references/core/sinks_sources.md
Comprehensive definitions for PHP/Laravel/Symfony/CodeIgniter/WordPress/Slim/CakePHP.
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
    """Get the PHP sink library."""
    return SinkLibrary(
        language="php",
        sinks=_get_php_sinks(),
    )


def get_source_library() -> SourceLibrary:
    """Get the PHP source library."""
    return SourceLibrary(
        language="php",
        sources=_get_php_sources(),
    )


def _get_php_sinks() -> list[SinkDefinition]:
    """Get all PHP sink definitions."""
    sinks = []

    # =========================================================================
    # RCE - Remote Code Execution (Critical)
    # =========================================================================
    sinks.extend([
        SinkDefinition(
            name="system_exec",
            category=SinkCategory.RCE,
            language="php",
            function_patterns=[
                r"\bsystem\s*\(",
                r"\bexec\s*\(",
                r"\bpassthru\s*\(",
                r"\bshell_exec\s*\(",
                r"\bpopen\s*\(",
                r"\bproc_open\s*\(",
                r"\bpcntl_exec\s*\(",
            ],
            cwe="CWE-78",
            owasp="A03:2021",
            description="Command injection via PHP command execution functions",
            impact="Remote code execution with web server privileges",
            effective_sanitizers=["escapeshellarg()", "escapeshellcmd()"],
            safe_alternatives=["pcntl_exec() with escaped arguments", "proc_open() with array arguments"],
        ),
        SinkDefinition(
            name="backtick_operator",
            category=SinkCategory.RCE,
            language="php",
            function_patterns=[
                r"`[^`]*\\\$_(GET|POST|REQUEST|COOKIE|SERVER)`",
                r"`[^`]*\\\$\\{",
            ],
            cwe="CWE-78",
            owasp="A03:2021",
            description="Command injection via backtick operator with user input",
            impact="Remote code execution",
            effective_sanitizers=["Avoid backtick operators entirely"],
            safe_alternatives=["proc_open() with array arguments"],
        ),
    ])

    # =========================================================================
    # Code Injection (Critical)
    # =========================================================================
    sinks.extend([
        SinkDefinition(
            name="eval_assert",
            category=SinkCategory.RCE,
            language="php",
            function_patterns=[
                r"\beval\s*\(",
                r"\bassert\s*\(",
            ],
            cwe="CWE-95",
            owasp="A03:2021",
            description="Code injection via eval() or assert() with user input",
            impact="Arbitrary PHP code execution",
            effective_sanitizers=["Avoid eval() entirely", "Whitelist allowed values"],
            safe_alternatives=["Use switch/case or lookup tables", "preg_match_callback()"],
        ),
        SinkDefinition(
            name="preg_replace_e",
            category=SinkCategory.RCE,
            language="php",
            function_patterns=[
                r"\bpreg_replace\s*\([^)]*['\"]/[^/]*e[^/]*['\"]",
                r"\bpreg_replace\s*\([^)]*\\e[^/]*[\"']",
            ],
            cwe="CWE-95",
            owasp="A03:2021",
            description="Code injection via preg_replace() with /e modifier (deprecated in PHP 5.5, removed in 7.0)",
            impact="Arbitrary PHP code execution",
            effective_sanitizers=["Remove /e modifier"],
            safe_alternatives=["preg_replace_callback()"],
        ),
        SinkDefinition(
            name="create_function",
            category=SinkCategory.RCE,
            language="php",
            function_patterns=[
                r"\bcreate_function\s*\(",
            ],
            cwe="CWE-95",
            owasp="A03:2021",
            description="Code injection via create_function() (deprecated in PHP 7.2)",
            impact="Arbitrary PHP code execution",
            effective_sanitizers=["Avoid create_function()"],
            safe_alternatives=["Anonymous functions (closures)", "fn() =>"],
        ),
        SinkDefinition(
            name="call_user_func",
            category=SinkCategory.RCE,
            language="php",
            function_patterns=[
                r"\bcall_user_func\s*\(",
                r"\bcall_user_func_array\s*\(",
            ],
            cwe="CWE-94",
            owasp="A03:2021",
            description="Dynamic function call with user-controlled function name or arguments",
            impact="Arbitrary function invocation leading to code execution",
            effective_sanitizers=["Whitelist allowed function names"],
            safe_alternatives=["Use explicit function calls", "match/case with known functions"],
        ),
    ])

    # =========================================================================
    # SQLI - SQL Injection (Critical)
    # =========================================================================
    sinks.extend([
        SinkDefinition(
            name="mysql_legacy",
            category=SinkCategory.SQLI,
            language="php",
            function_patterns=[
                r"\bmysql_query\s*\(",
                r"\bmysql_db_query\s*\(",
                r"\bmysql_unbuffered_query\s*\(",
            ],
            cwe="CWE-89",
            owasp="A03:2021",
            description="SQL injection via legacy mysql_* functions (removed in PHP 7.0)",
            impact="Database compromise, data exfiltration",
            effective_sanitizers=["mysql_real_escape_string() (insufficient)"],
            safe_alternatives=["PDO with prepared statements", "mysqli with prepared statements"],
        ),
        SinkDefinition(
            name="mysqli_query",
            category=SinkCategory.SQLI,
            language="php",
            function_patterns=[
                r"\bmysqli_query\s*\(",
                r"\bmysqli_real_query\s*\(",
                r"\bmysqli_multi_query\s*\(",
                r"->query\s*\(",
                r"->real_query\s*\(",
                r"->multi_query\s*\(",
            ],
            cwe="CWE-89",
            owasp="A03:2021",
            description="SQL injection via mysqli query functions with string concatenation",
            impact="Database compromise, data exfiltration",
            effective_sanitizers=["mysqli_prepare() + bind_param()"],
            safe_alternatives=["Prepared statements with parameterized queries"],
        ),
        SinkDefinition(
            name="pdo_query",
            category=SinkCategory.SQLI,
            language="php",
            function_patterns=[
                r"->query\s*\([^)]*\.",
                r"->exec\s*\([^)]*\.",
                r"PDO::query\s*\(",
                r"PDO::exec\s*\(",
            ],
            cwe="CWE-89",
            owasp="A03:2021",
            description="SQL injection via PDO query/exec with string concatenation",
            impact="Database compromise",
            effective_sanitizers=["PDO::prepare() with bindParam()/bindValue()"],
            safe_alternatives=["Prepared statements", "Query builder with parameter binding"],
        ),
        SinkDefinition(
            name="wordpress_db",
            category=SinkCategory.SQLI,
            language="php",
            function_patterns=[
                r"\$wpdb->query\s*\(",
                r"\$wpdb->get_results\s*\([^)]*\.",
                r"\$wpdb->get_var\s*\([^)]*\.",
                r"\$wpdb->get_row\s*\([^)]*\.",
                r"\$wpdb->get_col\s*\([^)]*\.",
                r"\$wpdb->prepare\s*\([^)]*%",
            ],
            cwe="CWE-89",
            owasp="A03:2021",
            description="SQL injection via WordPress $wpdb with string concatenation",
            impact="Database compromise, WordPress site takeover",
            effective_sanitizers=["$wpdb->prepare() with proper placeholders"],
            safe_alternatives=["$wpdb->prepare() with %s/%d/%f placeholders"],
        ),
    ])

    # =========================================================================
    # PATH_TRAVERSAL - Path Traversal / LFI (High)
    # =========================================================================
    sinks.extend([
        SinkDefinition(
            name="include_require",
            category=SinkCategory.PATH_TRAVERSAL,
            language="php",
            function_patterns=[
                r"\binclude\s*\(\s*\$",
                r"\binclude_once\s*\(\s*\$",
                r"\brequire\s*\(\s*\$",
                r"\brequire_once\s*\(\s*\$",
                r"\binclude\s+\$",
                r"\binclude_once\s+\$",
                r"\brequire\s+\$",
                r"\brequire_once\s+\$",
            ],
            cwe="CWE-22",
            owasp="A01:2021",
            description="Local File Inclusion via include/require with user-controlled path",
            impact="Arbitrary file disclosure, code execution via log poisoning or PHP wrappers",
            effective_sanitizers=["basename()", "Whitelist allowed file paths"],
            safe_alternatives=["Map allowed page names to file paths", "Use autoloader"],
        ),
        SinkDefinition(
            name="file_operations",
            category=SinkCategory.PATH_TRAVERSAL,
            language="php",
            function_patterns=[
                r"\bfopen\s*\(",
                r"\bfile\s*\(",
                r"\bfile_get_contents\s*\(",
                r"\bfile_put_contents\s*\(",
                r"\breadfile\s*\(",
                r"\bfilemtime\s*\(",
                r"\bfileatime\s*\(",
            ],
            cwe="CWE-22",
            owasp="A01:2021",
            description="Path traversal via file read/write functions",
            impact="Arbitrary file read/write, sensitive data disclosure",
            effective_sanitizers=["realpath() validation", "Check for directory traversal sequences"],
            safe_alternatives=["Validate against whitelist of allowed directories"],
        ),
        SinkDefinition(
            name="file_delete_rename",
            category=SinkCategory.PATH_TRAVERSAL,
            language="php",
            function_patterns=[
                r"\bunlink\s*\(",
                r"\brename\s*\(",
                r"\bcopy\s*\(",
                r"\bglob\s*\(",
            ],
            cwe="CWE-22",
            owasp="A01:2021",
            description="Path traversal via file manipulation functions",
            impact="Arbitrary file deletion, rename, or copy",
            effective_sanitizers=["realpath() validation", "basename()"],
            safe_alternatives=["Restrict to safe directories with chroot or open_basedir"],
        ),
        SinkDefinition(
            name="move_uploaded_file",
            category=SinkCategory.PATH_TRAVERSAL,
            language="php",
            function_patterns=[
                r"\bmove_uploaded_file\s*\(",
            ],
            cwe="CWE-22",
            owasp="A01:2021",
            description="Path traversal via move_uploaded_file() with user-controlled destination",
            impact="Arbitrary file write, overwrite critical files",
            effective_sanitizers=["Validate destination path", "Use hardcoded or whitelisted paths"],
            safe_alternatives=["Generate random filenames", "Restrict to upload directory"],
        ),
    ])

    # =========================================================================
    # SSRF - Server-Side Request Forgery (High)
    # =========================================================================
    sinks.extend([
        SinkDefinition(
            name="file_get_contents_url",
            category=SinkCategory.SSRF,
            language="php",
            function_patterns=[
                r"\bfile_get_contents\s*\(\s*\$",
            ],
            cwe="CWE-918",
            owasp="A10:2021",
            description="SSRF via file_get_contents() with user-controlled URL",
            impact="Internal network access, cloud metadata exposure (169.254.169.254)",
            effective_sanitizers=["URL validation with whitelist", "Disable allow_url_fopen"],
            safe_alternatives=["cURL with explicit options and URL validation"],
        ),
        SinkDefinition(
            name="curl_exec",
            category=SinkCategory.SSRF,
            language="php",
            function_patterns=[
                r"\bcurl_exec\s*\(",
                r"\bcurl_multi_exec\s*\(",
            ],
            cwe="CWE-918",
            owasp="A10:2021",
            description="SSRF via curl_exec() with user-controlled URL",
            impact="Internal network scanning, cloud metadata exposure, data exfiltration",
            effective_sanitizers=["curl_setopt() to restrict protocols", "URL whitelist validation"],
            safe_alternatives=["Validate URL against allowed hosts", "Use CURLOPT_PROTOCOLS"],
        ),
        SinkDefinition(
            name="fopen_url_wrapper",
            category=SinkCategory.SSRF,
            language="php",
            function_patterns=[
                r"\bfopen\s*\(\s*['\"]https?://",
                r"\bfsockopen\s*\(",
                r"\bstream_socket_client\s*\(",
            ],
            cwe="CWE-918",
            owasp="A10:2021",
            description="SSRF via fopen() URL wrapper or fsockopen()",
            impact="Internal resource access",
            effective_sanitizers=["Disable allow_url_fopen in php.ini", "URL validation"],
            safe_alternatives=["Use cURL with restricted options"],
        ),
    ])

    # =========================================================================
    # UNSERIALIZE - Deserialization (Critical)
    # =========================================================================
    sinks.extend([
        SinkDefinition(
            name="unserialize",
            category=SinkCategory.UNSERIALIZE,
            language="php",
            function_patterns=[
                r"\bunserialize\s*\(",
            ],
            cwe="CWE-502",
            owasp="A08:2021",
            description="Insecure deserialization via unserialize() with user-controlled data",
            impact="Remote code execution via POP gadget chains, authentication bypass",
            effective_sanitizers=["json_decode() for JSON data", "Whitelist allowed classes"],
            safe_alternatives=["json_decode()", "unserialize($data, ['allowed_classes' => false])"],
        ),
        SinkDefinition(
            name="magic_methods_pop",
            category=SinkCategory.UNSERIALIZE,
            language="php",
            function_patterns=[
                r"function\s+__wakeup\s*\(",
                r"function\s+__destruct\s*\(",
                r"function\s+__toString\s*\(",
                r"function\s+__call\s*\(",
            ],
            cwe="CWE-502",
            owasp="A08:2021",
            description="PHP magic methods exploitable in POP gadget chains",
            impact="Code execution when class contains dangerous operations in magic methods",
            effective_sanitizers=["Review magic method implementations for dangerous operations"],
            safe_alternatives=["Avoid dangerous operations in magic methods"],
            requires_dataflow=True,
        ),
    ])

    # =========================================================================
    # XSS - Cross-Site Scripting (Medium)
    # =========================================================================
    sinks.extend([
        SinkDefinition(
            name="echo_print",
            category=SinkCategory.XSS,
            language="php",
            function_patterns=[
                r"\becho\s+\$",
                r"\bprint\s+\$",
                r"\bprintf\s*\(\s*\$",
                r"\bsprintf\s*\([^)]*\)\s*;\s*echo",
                r"<\?=\s*\$",
                r"<\?php\s+echo\s+\$",
            ],
            cwe="CWE-79",
            owasp="A03:2021",
            description="XSS via direct output of unescaped user input",
            impact="Session hijacking, credential theft, malware distribution",
            effective_sanitizers=["htmlspecialchars()", "htmlentities()", "strip_tags()"],
            safe_alternatives=["Template engine with auto-escaping (Twig, Blade)"],
        ),
        SinkDefinition(
            name="debug_output",
            category=SinkCategory.XSS,
            language="php",
            function_patterns=[
                r"\bprint_r\s*\(\s*\$",
                r"\bvar_dump\s*\(",
                r"\bvar_export\s*\(",
                r"\bdebug_zval_dump\s*\(",
            ],
            cwe="CWE-79",
            owasp="A03:2021",
            description="XSS via debug output functions with user-controlled data",
            impact="Information disclosure, potential XSS",
            effective_sanitizers=["Wrap in htmlspecialchars()", "Log to file instead"],
            safe_alternatives=["error_log()", "Monolog logger", "Remove in production"],
        ),
        SinkDefinition(
            name="header_injection",
            category=SinkCategory.XSS,
            language="php",
            function_patterns=[
                r"\bheader\s*\(\s*['\"]\s*Location\s*:",
                r"\bheader\s*\(\s*\$",
            ],
            cwe="CWE-79",
            owasp="A03:2021",
            description="HTTP response header injection or open redirect via header() with user input",
            impact="HTTP response splitting, open redirect, XSS via header injection",
            effective_sanitizers=["Validate URL format", "Remove newlines from header value"],
            safe_alternatives=["Use framework redirect methods"],
        ),
    ])

    # =========================================================================
    # XXE - XML External Entity (High)
    # =========================================================================
    sinks.extend([
        SinkDefinition(
            name="simplexml",
            category=SinkCategory.XXE,
            language="php",
            function_patterns=[
                r"\bsimplexml_load_string\s*\(",
                r"\bsimplexml_load_file\s*\(",
            ],
            cwe="CWE-611",
            owasp="A05:2021",
            description="XXE via SimpleXML with default settings (external entities enabled)",
            impact="Server-side file disclosure, SSRF, denial of service",
            effective_sanitizers=["libxml_disable_entity_loader(true) (PHP < 8.0)", "LIBXML_NOENT flag"],
            safe_alternatives=["Use LIBXML_NONET flag", "DOMDocument with secure configuration"],
        ),
        SinkDefinition(
            name="domdocument",
            category=SinkCategory.XXE,
            language="php",
            function_patterns=[
                r"DOMDocument.*->loadXML\s*\(",
                r"DOMDocument.*->load\s*\(",
                r"DOMDocument.*->loadHTML\s*\(",
                r"DOMDocument.*->loadHTMLFile\s*\(",
            ],
            cwe="CWE-611",
            owasp="A05:2021",
            description="XXE via DOMDocument XML parsing",
            impact="Server-side file disclosure, SSRF",
            effective_sanitizers=["libxml_disable_entity_loader(true)", "Set LIBXML_NOENT | LIBXML_NONET"],
            safe_alternatives=["JSON instead of XML", "Configure libxml with secure defaults"],
        ),
        SinkDefinition(
            name="xmlreader",
            category=SinkCategory.XXE,
            language="php",
            function_patterns=[
                r"XMLReader.*->XML\s*\(",
                r"XMLReader.*->open\s*\(",
            ],
            cwe="CWE-611",
            owasp="A05:2021",
            description="XXE via XMLReader",
            impact="File disclosure, SSRF",
            effective_sanitizers=["Disable external entities"],
            safe_alternatives=["Use LIBXML_NOENT | LIBXML_NONET flags"],
        ),
    ])

    # =========================================================================
    # SSTI - Server-Side Template Injection (High)
    # =========================================================================
    sinks.extend([
        SinkDefinition(
            name="twig_render",
            category=SinkCategory.SSTI,
            language="php",
            function_patterns=[
                r"\$twig->render\s*\(",
                r"\$twig->display\s*\(",
                r"\$this->render\s*\(",
                r"Twig_Environment.*->render\s*\(",
                r"Twig\ Environment.*->render\s*\(",
            ],
            cwe="CWE-94",
            owasp="A03:2021",
            description="Server-side template injection via Twig render/display",
            impact="Remote code execution via Twig sandbox escape",
            effective_sanitizers=["Enable Twig sandbox", "Use sandboxed Twig environment"],
            safe_alternatives=["Twig sandboxed environment with allowed tags/filters"],
        ),
        SinkDefinition(
            name="smarty_render",
            category=SinkCategory.SSTI,
            language="php",
            function_patterns=[
                r"\$smarty->display\s*\(",
                r"\$smarty->fetch\s*\(",
                r"Smarty.*->display\s*\(",
            ],
            cwe="CWE-94",
            owasp="A03:2021",
            description="Server-side template injection via Smarty",
            impact="Remote code execution via {php} tags or Smarty exploits",
            effective_sanitizers=["Disable {php} tags", "Use secure Smarty configuration"],
            safe_alternatives=["Use Smarty security policy"],
        ),
        SinkDefinition(
            name="blade_compile",
            category=SinkCategory.SSTI,
            language="php",
            function_patterns=[
                r"Blade.*compile\s*\(",
                r"BladeCompiler.*compileString\s*\(",
                r"\$__env->make\s*\(",
            ],
            cwe="CWE-94",
            owasp="A03:2021",
            description="Server-side template injection via Blade template engine",
            impact="Code execution via Blade directive injection",
            effective_sanitizers=["Escape all user input in templates"],
            safe_alternatives=["Use {{ }} (escaped) instead of {!! !!} (unescaped)"],
        ),
    ])

    # =========================================================================
    # LDAP - LDAP Injection (High)
    # =========================================================================
    sinks.extend([
        SinkDefinition(
            name="ldap_functions",
            category=SinkCategory.LDAP,
            language="php",
            function_patterns=[
                r"\bldap_search\s*\(",
                r"\bldap_read\s*\(",
                r"\bldap_list\s*\(",
                r"\bldap_get_entries\s*\(",
            ],
            cwe="CWE-90",
            owasp="A03:2021",
            description="LDAP injection via LDAP search functions with user-controlled filter",
            impact="Authentication bypass, unauthorized data access, information disclosure",
            effective_sanitizers=["ldap_escape()", "Input validation"],
            safe_alternatives=["ldap_escape() with LDAP_ESCAPE_FILTER flag", "Parameterized LDAP queries"],
        ),
    ])

    # =========================================================================
    # REDIRECT - Open Redirect (Medium)
    # =========================================================================
    sinks.extend([
        SinkDefinition(
            name="header_redirect",
            category=SinkCategory.REDIRECT,
            language="php",
            function_patterns=[
                r"\bheader\s*\(\s*['\"]\s*Location\s*:\s*\$",
                r"\bheader\s*\(\s*['\"]\s*Location\s*:\s*['\"].*\.\s*\$",
            ],
            cwe="CWE-601",
            owasp="A01:2021",
            description="Open redirect via header('Location:') with user-controlled URL",
            impact="Phishing attacks, session token theft via referrer leakage",
            effective_sanitizers=["URL whitelist", "Validate relative URLs only"],
            safe_alternatives=["Use framework redirect methods with validation"],
        ),
        SinkDefinition(
            name="http_redirect",
            category=SinkCategory.REDIRECT,
            language="php",
            function_patterns=[
                r"\bhttp_redirect\s*\(",
            ],
            cwe="CWE-601",
            owasp="A01:2021",
            description="Open redirect via http_redirect() (PECL HTTP extension)",
            impact="Phishing attacks",
            effective_sanitizers=["URL validation"],
            safe_alternatives=["Use framework redirect with whitelist"],
        ),
    ])

    # =========================================================================
    # Weak Crypto (Medium) - Custom severity via metadata
    # =========================================================================
    sinks.extend([
        SinkDefinition(
            name="weak_hash",
            category=SinkCategory.RCE,  # Reuse closest category; tagged via metadata
            language="php",
            function_patterns=[
                r"\bmd5\s*\(",
                r"\bsha1\s*\(",
                r"\bcrc32\s*\(",
                r"\bcrc32b\s*\(",
            ],
            cwe="CWE-328",
            owasp="A02:2021",
            description="Use of weak cryptographic hash functions (md5, sha1, crc32)",
            impact="Password cracking, collision attacks, data integrity compromise",
            effective_sanitizers=["Migrate to stronger algorithms"],
            safe_alternatives=["password_hash()", "hash('sha256', ...)", "hash('sha384', ...)", "hash('sha512', ...)"],
            severity="medium",
            metadata={"weak_crypto": True},
        ),
        SinkDefinition(
            name="weak_crypt",
            category=SinkCategory.RCE,
            language="php",
            function_patterns=[
                r"\bcrypt\s*\(",
            ],
            cwe="CWE-328",
            owasp="A02:2021",
            description="Use of crypt() with weak salt or DES-based hashing",
            impact="Password cracking via brute force or rainbow tables",
            effective_sanitizers=["Use password_hash() with PASSWORD_DEFAULT"],
            safe_alternatives=["password_hash()", "password_verify()"],
            severity="medium",
            metadata={"weak_crypto": True},
        ),
        SinkDefinition(
            name="base64_as_encryption",
            category=SinkCategory.RCE,
            language="php",
            function_patterns=[
                r"\bbase64_encode\s*\(",
                r"\bbase64_decode\s*\(",
            ],
            cwe="CWE-327",
            owasp="A02:2021",
            description="Use of base64_encode/decode as a substitute for encryption",
            impact="Data disclosure - base64 is encoding, not encryption",
            effective_sanitizers=["Use proper encryption (AES-256-GCM, sodium_crypto_aead)"],
            safe_alternatives=["openssl_encrypt()", "sodium_crypto_aead_aes256gcm_encrypt()", "sodium_crypto_secretbox()"],
            severity="medium",
            metadata={"weak_crypto": True},
        ),
    ])

    # =========================================================================
    # File Upload (High)
    # =========================================================================
    sinks.extend([
        SinkDefinition(
            name="file_upload_unsafe",
            category=SinkCategory.PATH_TRAVERSAL,
            language="php",
            function_patterns=[
                r"\bmove_uploaded_file\s*\(\s*\$_FILES",
                r"\$_FILES\s*\[\s*['\"][^'\"]+['\"]\s*\]\s*\[\s*['\"]tmp_name['\"]",
                r"\bcopy\s*\(\s*\$_FILES",
            ],
            cwe="CWE-434",
            owasp="A04:2021",
            description="Unrestricted file upload with user-controlled filename or destination",
            impact="Web shell upload, arbitrary code execution, stored XSS",
            effective_sanitizers=["Validate MIME type", "Check file extension against whitelist", "Rename file"],
            safe_alternatives=[
                "Whitelist allowed extensions",
                "Store uploads outside web root",
                "Generate random filenames",
                "Use getimagesize() for image validation",
            ],
        ),
    ])

    return sinks


def _get_php_sources() -> list[SourceDefinition]:
    """Get all PHP source definitions."""
    sources = []

    # =========================================================================
    # PHP Superglobals (Critical / High)
    # =========================================================================
    sources.extend([
        SourceDefinition(
            name="superglobal_get",
            category=SourceCategory.HTTP_PARAM,
            language="php",
            function_patterns=[
                r"\$_GET\s*\[",
                r"\$_GET",
            ],
            variable_patterns=[
                r"\$_GET\s*\[",
                r"\$_GET",
            ],
            risk_level="high",
            controllability="full",
            description="HTTP GET parameters via $_GET superglobal",
            example='$id = $_GET["id"];',
        ),
        SourceDefinition(
            name="superglobal_post",
            category=SourceCategory.HTTP_PARAM,
            language="php",
            function_patterns=[
                r"\$_POST\s*\[",
                r"\$_POST",
            ],
            variable_patterns=[
                r"\$_POST\s*\[",
                r"\$_POST",
            ],
            risk_level="high",
            controllability="full",
            description="HTTP POST parameters via $_POST superglobal",
            example='$name = $_POST["name"];',
        ),
        SourceDefinition(
            name="superglobal_request",
            category=SourceCategory.HTTP_PARAM,
            language="php",
            function_patterns=[
                r"\$_REQUEST\s*\[",
                r"\$_REQUEST",
            ],
            variable_patterns=[
                r"\$_REQUEST\s*\[",
                r"\$_REQUEST",
            ],
            risk_level="high",
            controllability="full",
            description="HTTP parameters via $_REQUEST superglobal (combines GET, POST, COOKIE)",
            example='$value = $_REQUEST["value"];',
        ),
        SourceDefinition(
            name="superglobal_cookie",
            category=SourceCategory.COOKIE,
            language="php",
            function_patterns=[
                r"\$_COOKIE\s*\[",
                r"\$_COOKIE",
            ],
            variable_patterns=[
                r"\$_COOKIE\s*\[",
                r"\$_COOKIE",
            ],
            risk_level="high",
            controllability="full",
            description="HTTP cookies via $_COOKIE superglobal",
            example='$token = $_COOKIE["session"];',
        ),
        SourceDefinition(
            name="superglobal_server_http",
            category=SourceCategory.HTTP_HEADER,
            language="php",
            function_patterns=[
                r"\$_SERVER\s*\[\s*['\"]HTTP_",
            ],
            variable_patterns=[
                r"\$_SERVER\s*\[\s*['\"]HTTP_",
            ],
            risk_level="high",
            controllability="full",
            description="HTTP headers via $_SERVER['HTTP_*'] superglobal entries",
            example='$ua = $_SERVER["HTTP_USER_AGENT"];',
        ),
        SourceDefinition(
            name="superglobal_files",
            category=SourceCategory.FILE_UPLOAD,
            language="php",
            function_patterns=[
                r"\$_FILES\s*\[",
                r"\$_FILES",
            ],
            variable_patterns=[
                r"\$_FILES\s*\[",
                r"\$_FILES",
            ],
            risk_level="critical",
            controllability="full",
            description="Uploaded files via $_FILES superglobal",
            example='$file = $_FILES["attachment"]["tmp_name"];',
        ),
    ])

    # =========================================================================
    # Laravel Sources
    # =========================================================================
    sources.extend([
        SourceDefinition(
            name="laravel_request_input",
            category=SourceCategory.HTTP_PARAM,
            language="php",
            function_patterns=[
                r"Request::input\s*\(",
                r"Request::query\s*\(",
                r"Request::post\s*\(",
                r"Request::get\s*\(",
                r"request\(\)->input\s*\(",
                r"request\(\)->query\s*\(",
                r"request\(\)->post\s*\(",
                r"request\(\)->get\s*\(",
                r"\$request->input\s*\(",
                r"\$request->query\s*\(",
                r"\$request->post\s*\(",
                r"\$request->get\s*\(",
            ],
            risk_level="high",
            controllability="full",
            description="Laravel Request facade and request() helper input methods",
            example='$name = $request->input("name");',
        ),
        SourceDefinition(
            name="laravel_request_all",
            category=SourceCategory.HTTP_PARAM,
            language="php",
            function_patterns=[
                r"request\(\)->all\s*\(",
                r"\$request->all\s*\(",
                r"\$request->only\s*\(",
                r"\$request->except\s*\(",
                r"Request::all\s*\(",
            ],
            risk_level="high",
            controllability="full",
            description="Laravel Request all()/only()/except() mass input methods",
            example='$data = $request->all();',
        ),
        SourceDefinition(
            name="laravel_request_header",
            category=SourceCategory.HTTP_HEADER,
            language="php",
            function_patterns=[
                r"\$request->header\s*\(",
                r"request\(\)->header\s*\(",
                r"Request::header\s*\(",
            ],
            risk_level="high",
            controllability="full",
            description="Laravel Request header methods",
            example='$token = $request->header("Authorization");',
        ),
        SourceDefinition(
            name="laravel_request_cookie",
            category=SourceCategory.COOKIE,
            language="php",
            function_patterns=[
                r"\$request->cookie\s*\(",
                r"request\(\)->cookie\s*\(",
                r"Request::cookie\s*\(",
                r"Cookie::get\s*\(",
            ],
            risk_level="high",
            controllability="full",
            description="Laravel Request cookie methods",
            example='$theme = $request->cookie("theme");',
        ),
        SourceDefinition(
            name="laravel_request_file",
            category=SourceCategory.FILE_UPLOAD,
            language="php",
            function_patterns=[
                r"\$request->file\s*\(",
                r"\$request->files\s*\(",
                r"request\(\)->file\s*\(",
                r"Request::file\s*\(",
            ],
            risk_level="critical",
            controllability="full",
            description="Laravel Request file upload methods",
            example='$file = $request->file("avatar");',
        ),
    ])

    # =========================================================================
    # Symfony Sources
    # =========================================================================
    sources.extend([
        SourceDefinition(
            name="symfony_request_query",
            category=SourceCategory.HTTP_PARAM,
            language="php",
            function_patterns=[
                r"\$request->query->get\s*\(",
                r"\$request->query->all\s*\(",
                r"\$request->query->has\s*\(",
                r"\$request->query->getInt\s*\(",
                r"\$request->query->getAlpha\s*\(",
                r"\$request->query->getAlnum\s*\(",
                r"\$request->query->getDigits\s*\(",
            ],
            risk_level="high",
            controllability="full",
            description="Symfony HttpFoundation query (GET) parameters",
            example='$page = $request->query->get("page");',
        ),
        SourceDefinition(
            name="symfony_request_post",
            category=SourceCategory.HTTP_PARAM,
            language="php",
            function_patterns=[
                r"\$request->request->get\s*\(",
                r"\$request->request->all\s*\(",
                r"\$request->request->has\s*\(",
            ],
            risk_level="high",
            controllability="full",
            description="Symfony HttpFoundation POST parameters",
            example='$name = $request->request->get("name");',
        ),
        SourceDefinition(
            name="symfony_request_headers",
            category=SourceCategory.HTTP_HEADER,
            language="php",
            function_patterns=[
                r"\$request->headers->get\s*\(",
                r"\$request->headers->all\s*\(",
                r"\$request->headers->has\s*\(",
            ],
            risk_level="high",
            controllability="full",
            description="Symfony HttpFoundation request headers",
            example='$auth = $request->headers->get("Authorization");',
        ),
        SourceDefinition(
            name="symfony_request_general",
            category=SourceCategory.HTTP_PARAM,
            language="php",
            function_patterns=[
                r"\$request->get\s*\(",
                r"\$request->getContent\s*\(",
                r"\$request->getPayload\s*\(",
            ],
            risk_level="high",
            controllability="full",
            description="Symfony HttpFoundation general request accessors",
            example='$value = $request->get("key");',
        ),
        SourceDefinition(
            name="symfony_request_cookies",
            category=SourceCategory.COOKIE,
            language="php",
            function_patterns=[
                r"\$request->cookies->get\s*\(",
                r"\$request->cookies->all\s*\(",
            ],
            risk_level="high",
            controllability="full",
            description="Symfony HttpFoundation cookies",
            example='$session = $request->cookies->get("PHPSESSID");',
        ),
        SourceDefinition(
            name="symfony_request_files",
            category=SourceCategory.FILE_UPLOAD,
            language="php",
            function_patterns=[
                r"\$request->files->get\s*\(",
                r"\$request->files->all\s*\(",
            ],
            risk_level="critical",
            controllability="full",
            description="Symfony HttpFoundation uploaded files",
            example='$file = $request->files->get("upload");',
        ),
    ])

    # =========================================================================
    # CodeIgniter Sources
    # =========================================================================
    sources.extend([
        SourceDefinition(
            name="codeigniter_input",
            category=SourceCategory.HTTP_PARAM,
            language="php",
            function_patterns=[
                r"\$this->input->get\s*\(",
                r"\$this->input->post\s*\(",
                r"\$this->input->get_post\s*\(",
                r"\$this->input->cookie\s*\(",
                r"\$this->input->server\s*\(",
                r"\$this->input->get_request_header\s*\(",
                r"\$this->input->request_headers\s*\(",
            ],
            risk_level="high",
            controllability="full",
            description="CodeIgniter Input library methods",
            example='$id = $this->input->get("id");',
        ),
        SourceDefinition(
            name="codeigniter_input_get",
            category=SourceCategory.HTTP_PARAM,
            language="php",
            function_patterns=[
                r"input->get\s*\(",
            ],
            risk_level="high",
            controllability="full",
            description="CodeIgniter GET parameter retrieval",
            example='$search = $this->input->get("q");',
        ),
    ])

    # =========================================================================
    # WordPress Sources
    # =========================================================================
    sources.extend([
        SourceDefinition(
            name="wordpress_superglobals",
            category=SourceCategory.HTTP_PARAM,
            language="php",
            function_patterns=[
                r"\$_POST\s*\[",
                r"\$_GET\s*\[",
                r"\$_REQUEST\s*\[",
            ],
            variable_patterns=[
                r"\$_POST\s*\[",
                r"\$_GET\s*\[",
                r"\$_REQUEST\s*\[",
            ],
            risk_level="high",
            controllability="full",
            description="WordPress direct superglobal access for user input",
            example='$action = $_POST["action"];',
        ),
        SourceDefinition(
            name="wordpress_meta",
            category=SourceCategory.DATABASE,
            language="php",
            function_patterns=[
                r"\bget_post_meta\s*\(",
                r"\bget_user_meta\s*\(",
                r"\bget_term_meta\s*\(",
                r"\bget_comment_meta\s*\(",
                r"\bget_option\s*\(",
                r"\bget_site_option\s*\(",
                r"\bget_network_option\s*\(",
            ],
            risk_level="medium",
            controllability="partial",
            description="WordPress database/meta retrieval functions (second-order injection risk)",
            example='$value = get_post_meta($post_id, "custom_field", true);',
        ),
    ])

    # =========================================================================
    # Slim Framework Sources
    # =========================================================================
    sources.extend([
        SourceDefinition(
            name="slim_request_param",
            category=SourceCategory.HTTP_PARAM,
            language="php",
            function_patterns=[
                r"\$request->getParam\s*\(",
                r"\$request->getQueryParam\s*\(",
                r"\$request->getQueryParams\s*\(\s*\)",
                r"\$request->getParsedBody\s*\(",
                r"\$request->getParsedBodyParam\s*\(",
            ],
            risk_level="high",
            controllability="full",
            description="Slim Framework request parameter accessors",
            example='$name = $request->getParam("name");',
        ),
    ])

    # =========================================================================
    # CakePHP Sources
    # =========================================================================
    sources.extend([
        SourceDefinition(
            name="cakephp_request_data",
            category=SourceCategory.HTTP_PARAM,
            language="php",
            function_patterns=[
                r"\$this->request->getData\s*\(",
                r"\$this->request->getData\s*\(\s*\)",
                r"\$this->request->getQuery\s*\(",
                r"\$this->request->getQueryParams\s*\(\s*\)",
                r"\$this->request->getData\s*\(\s*['\"]",
            ],
            risk_level="high",
            controllability="full",
            description="CakePHP request data and query accessors",
            example='$data = $this->request->getData("field");',
        ),
        SourceDefinition(
            name="cakephp_request_headers",
            category=SourceCategory.HTTP_HEADER,
            language="php",
            function_patterns=[
                r"\$this->request->getHeader\s*\(",
                r"\$this->request->getHeaderLine\s*\(",
            ],
            risk_level="high",
            controllability="full",
            description="CakePHP request header accessors",
            example='$auth = $this->request->getHeaderLine("Authorization");',
        ),
    ])

    # =========================================================================
    # HTTP Header Sources
    # =========================================================================
    sources.extend([
        SourceDefinition(
            name="apache_headers",
            category=SourceCategory.HTTP_HEADER,
            language="php",
            function_patterns=[
                r"\bgetallheaders\s*\(",
                r"\bapache_request_headers\s*\(",
                r"\bhttp_get_request_headers\s*\(",
            ],
            risk_level="high",
            controllability="full",
            description="HTTP headers retrieved via Apache/Nginx functions",
            example='$headers = getallheaders();',
        ),
        SourceDefinition(
            name="server_http_vars",
            category=SourceCategory.HTTP_HEADER,
            language="php",
            function_patterns=[
                r"\$_SERVER\s*\[\s*['\"]HTTP_",
                r"\$_SERVER\s*\[\s*['\"]PHP_AUTH_",
            ],
            variable_patterns=[
                r"\$_SERVER\s*\[\s*['\"]HTTP_",
                r"\$_SERVER\s*\[\s*['\"]PHP_AUTH_",
            ],
            risk_level="high",
            controllability="full",
            description="HTTP headers accessed via $_SERVER['HTTP_*'] variables",
            example='$host = $_SERVER["HTTP_HOST"];',
        ),
    ])

    # =========================================================================
    # File Upload Sources
    # =========================================================================
    sources.extend([
        SourceDefinition(
            name="files_tmp_name",
            category=SourceCategory.FILE_UPLOAD,
            language="php",
            function_patterns=[
                r"\$_FILES\s*\[\s*['\"][^'\"]+['\"]\s*\]\s*\[\s*['\"]tmp_name['\"]",
            ],
            variable_patterns=[
                r"\$_FILES\s*\[\s*['\"][^'\"]+['\"]\s*\]\s*\[\s*['\"]tmp_name['\"]",
            ],
            risk_level="critical",
            controllability="full",
            description="Uploaded file temporary path from $_FILES",
            example='$tmp = $_FILES["upload"]["tmp_name"];',
        ),
        SourceDefinition(
            name="files_name",
            category=SourceCategory.FILE_UPLOAD,
            language="php",
            function_patterns=[
                r"\$_FILES\s*\[\s*['\"][^'\"]+['\"]\s*\]\s*\[\s*['\"]name['\"]",
            ],
            variable_patterns=[
                r"\$_FILES\s*\[\s*['\"][^'\"]+['\"]\s*\]\s*\[\s*['\"]name['\"]",
            ],
            risk_level="critical",
            controllability="full",
            description="Uploaded file original name from $_FILES (user-controlled, can contain malicious values)",
            example='$filename = $_FILES["upload"]["name"];',
        ),
    ])

    return sources


__all__ = [
    "get_sink_library",
    "get_source_library",
]
