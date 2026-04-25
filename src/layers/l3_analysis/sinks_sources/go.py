"""
P6-05: Go Sink and Source Definitions

Integrated from code-audit/references/core/sinks_sources.md
Comprehensive definitions for Go / net/http / Gin / Echo / Chi frameworks.
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
    """Get the Go sink library."""
    return SinkLibrary(
        language="go",
        sinks=_get_go_sinks(),
    )


def get_source_library() -> SourceLibrary:
    """Get the Go source library."""
    return SourceLibrary(
        language="go",
        sources=_get_go_sources(),
    )


def _get_go_sinks() -> list[SinkDefinition]:
    """Get all Go sink definitions."""
    sinks = []

    # =========================================================================
    # RCE - Remote Code Execution (Critical)
    # =========================================================================
    sinks.extend([
        SinkDefinition(
            name="exec_Command",
            category=SinkCategory.RCE,
            language="go",
            function_patterns=[
                r"exec\.Command\s*\(",
                r"exec\.CommandContext\s*\(",
            ],
            cwe="CWE-78",
            owasp="A03:2021",
            description="Command injection via os/exec.Command or CommandContext",
            impact="Remote code execution with process privileges",
            effective_sanitizers=["Use exec.Command with separate argument list, never shell interpolation"],
            safe_alternatives=[
                "exec.Command(\"ls\", userInput)  # each argument is a separate parameter",
                "exec.CommandContext(ctx, \"cmd\", arg1, arg2)",
            ],
        ),
        SinkDefinition(
            name="exec_Cmd_Run",
            category=SinkCategory.RCE,
            language="go",
            function_patterns=[
                r"\.Cmd\s*\{[^}]*\}",
                r"\.Run\s*\(\s*\)",
                r"\.Output\s*\(\s*\)",
                r"\.CombinedOutput\s*\(\s*\)",
                r"\.Start\s*\(\s*\)",
            ],
            cwe="CWE-78",
            owasp="A03:2021",
            description="Command execution via os/exec.Cmd methods (Run, Output, CombinedOutput, Start)",
            impact="Remote code execution",
            effective_sanitizers=["Ensure Cmd struct is built from fixed command paths with separate args"],
        ),
        SinkDefinition(
            name="os_StartProcess",
            category=SinkCategory.RCE,
            language="go",
            function_patterns=[
                r"os\.StartProcess\s*\(",
                r"syscall\.Exec\s*\(",
                r"syscall\.ForkExec\s*\(",
                r"syscall\.StartProcess\s*\(",
            ],
            cwe="CWE-78",
            owasp="A03:2021",
            description="Low-level process creation via os.StartProcess or syscall.Exec",
            impact="Remote code execution at OS level",
            effective_sanitizers=["Validate and sanitize all arguments before passing"],
        ),
        SinkDefinition(
            name="exec_shell_pipes",
            category=SinkCategory.RCE,
            language="go",
            function_patterns=[
                r"exec\.Command\s*\(\s*[\"']sh[\"']\s*,\s*[\"']-c[\"']",
                r"exec\.Command\s*\(\s*[\"']bash[\"']\s*,\s*[\"']-c[\"']",
                r"exec\.Command\s*\(\s*[\"']cmd[\"']\s*,\s*[\"']/c[\"']",
            ],
            cwe="CWE-78",
            owasp="A03:2021",
            description="Shell invocation with user-controlled string via sh -c / bash -c / cmd /c",
            impact="Full shell command injection with pipe and redirect support",
            effective_sanitizers=["Avoid shell invocation; pass arguments directly"],
            safe_alternatives=["exec.Command(\"binary\", arg1, arg2) without shell"],
        ),
    ])

    # =========================================================================
    # PATH_TRAVERSAL - Path Traversal (High)
    # =========================================================================
    sinks.extend([
        SinkDefinition(
            name="os_file_read",
            category=SinkCategory.PATH_TRAVERSAL,
            language="go",
            function_patterns=[
                r"os\.Open\s*\(",
                r"os\.OpenFile\s*\(",
                r"os\.ReadFile\s*\(",
                r"io/ioutil\.ReadFile\s*\(",
                r"os\.ReadDir\s*\(",
            ],
            cwe="CWE-22",
            owasp="A01:2021",
            description="Path traversal via os file read operations",
            impact="Arbitrary file read from the filesystem",
            effective_sanitizers=[
                "filepath.Clean() and validate against base directory",
                "filepath.Rel() to check resolved path stays within allowed dir",
            ],
            safe_alternatives=[
                "filepath.Join(baseDir, filepath.Clean(userInput)) then verify with strings.HasPrefix",
            ],
        ),
        SinkDefinition(
            name="os_file_write",
            category=SinkCategory.PATH_TRAVERSAL,
            language="go",
            function_patterns=[
                r"os\.Create\s*\(",
                r"os\.WriteFile\s*\(",
                r"io/ioutil\.WriteFile\s*\(",
                r"os\.OpenFile\s*\([^)]*os\.O_WRONLY",
                r"os\.OpenFile\s*\([^)]*os\.O_CREATE",
            ],
            cwe="CWE-22",
            owasp="A01:2021",
            description="Path traversal via os file write/create operations",
            impact="Arbitrary file write, potential code planting",
            effective_sanitizers=[
                "filepath.Clean() and validate against base directory",
                "Check resolved path with filepath.EvalSymlinks()",
            ],
        ),
        SinkDefinition(
            name="filepath_Join_user_input",
            category=SinkCategory.PATH_TRAVERSAL,
            language="go",
            function_patterns=[
                r"path/filepath\.Join\s*\(",
                r"path\.Join\s*\(",
            ],
            cwe="CWE-22",
            owasp="A01:2021",
            description="Path traversal via filepath.Join with user-controlled segments containing ../",
            impact="Directory traversal to access files outside intended directory",
            effective_sanitizers=[
                "filepath.Clean() each segment before joining",
                "Validate that the result stays within the intended base directory",
            ],
            safe_alternatives=[
                "filepath.Join(baseDir, filepath.Clean(userInput)) with prefix check",
            ],
            requires_dataflow=True,
        ),
        SinkDefinition(
            name="archive_zip_slip",
            category=SinkCategory.PATH_TRAVERSAL,
            language="go",
            function_patterns=[
                r"zip\.OpenReader\s*\(",
                r"zip\.Reader\s*\{",
                r"\.Create\s*\(\s*.*Name\s*\)",
            ],
            cwe="CWE-22",
            owasp="A01:2021",
            description="Zip Slip vulnerability via archive/zip extraction without validating entry paths",
            impact="Arbitrary file write via malicious zip archive entries containing ../",
            effective_sanitizers=[
                "Validate zip entry names with filepath.Clean() and check against target directory",
            ],
        ),
    ])

    # =========================================================================
    # SQLI - SQL Injection (Critical)
    # =========================================================================
    sinks.extend([
        SinkDefinition(
            name="database_sql_Query",
            category=SinkCategory.SQLI,
            language="go",
            function_patterns=[
                r"\.Query\s*\(",
                r"\.QueryContext\s*\(",
                r"\.QueryRow\s*\(",
                r"\.QueryRowContext\s*\(",
            ],
            cwe="CWE-89",
            owasp="A03:2021",
            description="SQL injection via database/sql Query/QueryRow with string concatenation or fmt.Sprintf",
            impact="Database data theft, modification, or deletion",
            effective_sanitizers=[
                "Use parameterized queries with ? placeholders",
                "sql.Named() for named parameters",
            ],
            safe_alternatives=[
                "db.QueryContext(ctx, \"SELECT * FROM users WHERE id = ?\", userID)",
            ],
            requires_dataflow=True,
        ),
        SinkDefinition(
            name="database_sql_Exec",
            category=SinkCategory.SQLI,
            language="go",
            function_patterns=[
                r"\.Exec\s*\(",
                r"\.ExecContext\s*\(",
                r"\.Prepare\s*\(",
                r"\.PrepareContext\s*\(",
            ],
            cwe="CWE-89",
            owasp="A03:2021",
            description="SQL injection via database/sql Exec/Prepare with unsanitized input",
            impact="Database manipulation, data exfiltration",
            effective_sanitizers=["Use parameterized queries with ? placeholders"],
            safe_alternatives=[
                "db.ExecContext(ctx, \"INSERT INTO users (name) VALUES (?)\", name)",
            ],
            requires_dataflow=True,
        ),
        SinkDefinition(
            name="sql_string_concat",
            category=SinkCategory.SQLI,
            language="go",
            function_patterns=[
                r"fmt\.Sprintf\s*\([^)]*SELECT",
                r"fmt\.Sprintf\s*\([^)]*INSERT",
                r"fmt\.Sprintf\s*\([^)]*UPDATE",
                r"fmt\.Sprintf\s*\([^)]*DELETE",
                r"strings\.ReplaceAll\s*\([^)]*SELECT",
                r"string\s*\(\s*\+\s*.*SELECT",
            ],
            cwe="CWE-89",
            owasp="A03:2021",
            description="SQL query constructed via fmt.Sprintf or string concatenation",
            impact="Full SQL injection with all query manipulation capabilities",
            effective_sanitizers=["Parameterized queries with placeholders"],
            requires_dataflow=True,
        ),
        SinkDefinition(
            name="gorm_raw_query",
            category=SinkCategory.SQLI,
            language="go",
            function_patterns=[
                r"\.Raw\s*\(",
                r"\.Exec\s*\(",
                r"db\.Table\s*\([^)]*\+",
            ],
            cwe="CWE-89",
            owasp="A03:2021",
            description="SQL injection via GORM Raw() or string-concatenated Table() calls",
            impact="Database compromise",
            effective_sanitizers=["Use GORM ORM methods or parameterized Raw()"],
            safe_alternatives=[
                "db.Raw(\"SELECT * FROM users WHERE id = ?\", id)",
            ],
            metadata={"framework": "gorm"},
        ),
    ])

    # =========================================================================
    # SSRF - Server-Side Request Forgery (High)
    # =========================================================================
    sinks.extend([
        SinkDefinition(
            name="net_http_Get",
            category=SinkCategory.SSRF,
            language="go",
            function_patterns=[
                r"http\.Get\s*\(",
                r"http\.Post\s*\(",
                r"http\.PostForm\s*\(",
                r"http\.Head\s*\(",
            ],
            cwe="CWE-918",
            owasp="A10:2021",
            description="SSRF via net/http convenience functions with user-controlled URL",
            impact="Internal network scanning, cloud metadata access (169.254.169.254)",
            effective_sanitizers=[
                "URL whitelist validation",
                "Resolve hostname and reject private/internal IPs",
                "Custom transport with DialContext that blocks private ranges",
            ],
        ),
        SinkDefinition(
            name="net_http_NewRequest",
            category=SinkCategory.SSRF,
            language="go",
            function_patterns=[
                r"http\.NewRequest\s*\(",
                r"http\.NewRequestWithContext\s*\(",
                r"\.Do\s*\(",
            ],
            cwe="CWE-918",
            owasp="A10:2021",
            description="SSRF via http.NewRequest with user-controlled URL passed to client.Do()",
            impact="Internal resource access, SSRF via redirect chains",
            effective_sanitizers=[
                "Validate URL scheme (allow only https://)",
                "Check resolved IP against deny list of internal ranges",
                "Disable redirects or validate redirect targets",
            ],
            safe_alternatives=[
                "Parse and validate URL with url.Parse(), check host against allowlist",
            ],
        ),
        SinkDefinition(
            name="net_http_Client",
            category=SinkCategory.SSRF,
            language="go",
            function_patterns=[
                r"http\.Client\s*\{",
                r"\.Get\s*\([^)]*\+",
                r"\.Post\s*\([^)]*\+",
            ],
            cwe="CWE-918",
            owasp="A10:2021",
            description="SSRF via http.Client with user-influenced request URL",
            impact="Access to internal services and cloud metadata",
            effective_sanitizers=[
                "Custom CheckRedirect function",
                "DialContext with IP range filtering",
            ],
        ),
    ])

    # =========================================================================
    # UNSERIALIZE - Deserialization (Critical / High)
    # =========================================================================
    sinks.extend([
        SinkDefinition(
            name="gob_Decode",
            category=SinkCategory.UNSERIALIZE,
            language="go",
            function_patterns=[
                r"gob\.NewDecoder\s*\(",
                r"\.Decode\s*\(",
            ],
            cwe="CWE-502",
            owasp="A08:2021",
            description="Insecure deserialization via encoding/gob Decode",
            impact="Arbitrary struct instantiation from untrusted data; potential for unexpected type confusion",
            effective_sanitizers=[
                "Validate decoded types against expected interfaces",
                "Avoid gob for untrusted input",
            ],
            safe_alternatives=["encoding/json with strict struct definitions"],
        ),
        SinkDefinition(
            name="json_Unmarshal",
            category=SinkCategory.UNSERIALIZE,
            language="go",
            function_patterns=[
                r"json\.Unmarshal\s*\(",
                r"json\.Decoder\s*\{",
                r"\.Decode\s*\([^)]*json",
            ],
            cwe="CWE-502",
            owasp="A08:2021",
            description="JSON deserialization into interface{} or map[string]interface{} without type validation",
            impact="Unexpected data types, prototype pollution in map-based deserialization",
            effective_sanitizers=[
                "Unmarshal into concrete struct types",
                "Disallow unexpected fields with json struct tags and validation",
            ],
            safe_alternatives=[
                "json.Unmarshal(data, &myConcreteStruct)",
                "Use json.Decoder with DisallowUnknownFields()",
            ],
        ),
        SinkDefinition(
            name="xml_Unmarshal",
            category=SinkCategory.XXE,
            language="go",
            function_patterns=[
                r"xml\.Unmarshal\s*\(",
                r"xml\.Decoder\s*\{",
                r"xml\.NewDecoder\s*\(",
            ],
            cwe="CWE-611",
            owasp="A05:2021",
            description="XML parsing with potential XXE via encoding/xml",
            impact="XML external entity attacks if using custom entity resolution",
            effective_sanitizers=[
                "Go's encoding/xml is generally safe by default",
                "Avoid xml.NewDecoder with custom Entity if untrusted",
            ],
        ),
    ])

    # =========================================================================
    # REDIRECT - Open Redirect (Medium)
    # =========================================================================
    sinks.extend([
        SinkDefinition(
            name="http_Redirect",
            category=SinkCategory.REDIRECT,
            language="go",
            function_patterns=[
                r"http\.Redirect\s*\(",
                r"\.WriteHeader\s*\(\s*301\s*\)",
                r"\.WriteHeader\s*\(\s*302\s*\)",
                r"\.Header\s*\(\s*\)\.Set\s*\(\s*[\"']Location[\"']",
            ],
            cwe="CWE-601",
            owasp="A01:2021",
            description="Open redirect via http.Redirect or Location header with user-controlled URL",
            impact="Phishing attacks, session token theft via referer leakage",
            effective_sanitizers=[
                "Validate redirect target is a relative path or on allowed domain",
                "Parse URL and verify host against whitelist",
            ],
            safe_alternatives=[
                "Parse redirect URL with url.Parse() and verify Host is allowed",
            ],
        ),
    ])

    # =========================================================================
    # XSS - Cross-Site Scripting (Medium)
    # =========================================================================
    sinks.extend([
        SinkDefinition(
            name="html_template_execute",
            category=SinkCategory.XSS,
            language="go",
            function_patterns=[
                r"template\.Must\s*\([^)]*\.Execute\s*\(",
                r"template\.Execute\s*\(",
                r"template\.ExecuteTemplate\s*\(",
                r"html/template.*\.Execute\s*\(",
            ],
            cwe="CWE-79",
            owasp="A03:2021",
            description="XSS via template execution (html/template auto-escapes but text/template does not)",
            impact="Cross-site scripting if text/template is used instead of html/template",
            effective_sanitizers=[
                "Use html/template (auto-escapes by default)",
                "Avoid text/template for HTML output",
            ],
            safe_alternatives=["html/template.New().Parse(tmpl).Execute(w, data)"],
        ),
        SinkDefinition(
            name="response_Write_user_input",
            category=SinkCategory.XSS,
            language="go",
            function_patterns=[
                r"\.Write\s*\(\s*\[\]byte\s*\(",
                r"\.WriteString\s*\([^)]*\+",
                r"fmt\.Fprint\s*\([^)]*\bw\b",
                r"fmt\.Fprintf\s*\([^)]*\bw\b",
            ],
            cwe="CWE-79",
            owasp="A03:2021",
            description="XSS via direct write to http.ResponseWriter with unsanitized user input",
            impact="Reflected or stored cross-site scripting",
            effective_sanitizers=[
                "html/template.HTMLEscapeString()",
                "html/template.JSEscapeString()",
            ],
            safe_alternatives=["html/template.HTMLEscape(w, []byte(userInput))"],
        ),
    ])

    # =========================================================================
    # Weak Crypto - Insecure Cryptography (High)
    # =========================================================================
    sinks.extend([
        SinkDefinition(
            name="crypto_md5",
            category=SinkCategory.SSTI,  # Reusing closest category; md5 is a weak algorithm
            language="go",
            function_patterns=[
                r"crypto/md5",
                r"md5\.Sum\s*\(",
                r"md5\.New\s*\(",
            ],
            cwe="CWE-328",
            owasp="A02:2021",
            description="Use of weak cryptographic hash (MD5) vulnerable to collision attacks",
            impact="Hash collision, password cracking, data integrity violations",
            effective_sanitizers=["Replace with SHA-256 or stronger"],
            safe_alternatives=["crypto/sha256: sha256.Sum256(data)"],
        ),
        SinkDefinition(
            name="crypto_sha1",
            category=SinkCategory.SSTI,
            language="go",
            function_patterns=[
                r"crypto/sha1",
                r"sha1\.Sum\s*\(",
                r"sha1\.New\s*\(",
            ],
            cwe="CWE-328",
            owasp="A02:2021",
            description="Use of weak cryptographic hash (SHA-1) vulnerable to collision attacks",
            impact="Hash collision, digital signature forgery in certain contexts",
            effective_sanitizers=["Replace with SHA-256 or stronger"],
            safe_alternatives=["crypto/sha256: sha256.Sum256(data)"],
        ),
        SinkDefinition(
            name="crypto_des",
            category=SinkCategory.SSTI,
            language="go",
            function_patterns=[
                r"crypto/des",
                r"des\.NewCipher\s*\(",
                r"des\.NewTripleDESCipher\s*\(",
            ],
            cwe="CWE-327",
            owasp="A02:2021",
            description="Use of broken or risky cryptographic algorithm (DES / 3DES)",
            impact="Data decryption via brute force or known attacks",
            effective_sanitizers=["Replace with AES-GCM or AES-CBC with proper key size"],
            safe_alternatives=["crypto/aes + crypto/cipher: aes.NewCipher(key)"],
        ),
    ])

    # =========================================================================
    # LDAP - LDAP Injection (High)
    # =========================================================================
    sinks.extend([
        SinkDefinition(
            name="ldap_Search",
            category=SinkCategory.LDAP,
            language="go",
            function_patterns=[
                r"ldap\.Search\s*\(",
                r"ldap\.SearchWithPaging\s*\(",
                r"ldap\.NewSearchRequest\s*\(",
                r"l\.Search\s*\(",
            ],
            cwe="CWE-90",
            owasp="A03:2021",
            description="LDAP injection via search filter constructed with user input",
            impact="Authentication bypass, directory data disclosure",
            effective_sanitizers=[
                "Escape LDAP special characters: * ( ) \\ / NUL",
                "Use parameterized LDAP queries",
            ],
            metadata={"library": "github.com/go-ldap/ldap"},
        ),
    ])

    return sinks


def _get_go_sources() -> list[SourceDefinition]:
    """Get all Go source definitions."""
    sources = []

    # =========================================================================
    # Standard Library net/http Sources
    # =========================================================================
    sources.extend([
        SourceDefinition(
            name="net_http_Query",
            category=SourceCategory.HTTP_PARAM,
            language="go",
            function_patterns=[
                r"\.URL\.Query\s*\(\s*\)",
                r"\.Query\s*\(\s*\)\.Get\s*\(",
                r"\.Query\s*\(\s*\)\.Set\s*\(",
                r"\.URL\.Query\s*\(\s*\)\.Get\s*\(",
                r"r\.URL\.Query\(\)",
            ],
            risk_level="high",
            controllability="full",
            description="HTTP query string parameters via r.URL.Query()",
            example='name := r.URL.Query().Get("name")',
        ),
        SourceDefinition(
            name="net_http_FormValue",
            category=SourceCategory.HTTP_PARAM,
            language="go",
            function_patterns=[
                r"\.FormValue\s*\(",
                r"\.PostFormValue\s*\(",
                r"\.Form\s*\(",
                r"\.ParseForm\s*\(\s*\)",
            ],
            risk_level="high",
            controllability="full",
            description="HTTP form parameters via r.FormValue() / r.PostFormValue()",
            example='username := r.FormValue("username")',
        ),
        SourceDefinition(
            name="net_http_Header",
            category=SourceCategory.HTTP_HEADER,
            language="go",
            function_patterns=[
                r"\.Header\.Get\s*\(",
                r"\.Header\.Values\s*\(",
                r"\.Header\s*\[\s*[\"']",
                r"r\.Header\.Get\s*\(",
                r"r\.Header\.Values\s*\(",
            ],
            risk_level="high",
            controllability="full",
            description="HTTP request headers via r.Header.Get() / r.Header.Values()",
            example='ua := r.Header.Get("User-Agent")',
        ),
        SourceDefinition(
            name="net_http_Cookie",
            category=SourceCategory.COOKIE,
            language="go",
            function_patterns=[
                r"\.Cookie\s*\(",
                r"\.Cookies\s*\(\s*\)",
                r"r\.Cookie\s*\(",
                r"r\.Cookies\s*\(\s*\)",
            ],
            risk_level="high",
            controllability="full",
            description="HTTP cookies via r.Cookie() / r.Cookies()",
            example='cookie, err := r.Cookie("session")',
        ),
        SourceDefinition(
            name="net_http_Path",
            category=SourceCategory.HTTP_PARAM,
            language="go",
            function_patterns=[
                r"\.URL\.Path\b",
                r"\.URL\.RawPath\b",
                r"\.URL\.RequestURI\s*\(\s*\)",
                r"\.RequestURI\s*\(\s*\)",
                r"r\.URL\.Path",
            ],
            risk_level="high",
            controllability="full",
            description="URL path component from HTTP request",
            example='path := r.URL.Path',
        ),
        SourceDefinition(
            name="net_http_Body",
            category=SourceCategory.HTTP_PARAM,
            language="go",
            function_patterns=[
                r"\.Body\b",
                r"io\.ReadAll\s*\(\s*r\.Body",
                r"io\.ReadAll\s*\(\s*.*\.Body",
                r"io\.Copy\s*\([^,]*r\.Body",
                r"io\.NopCloser\s*\(",
            ],
            risk_level="high",
            controllability="full",
            description="HTTP request body read via io.ReadAll(r.Body) or similar",
            example='body, _ := io.ReadAll(r.Body)',
        ),
        SourceDefinition(
            name="net_http_FileUpload",
            category=SourceCategory.FILE_UPLOAD,
            language="go",
            function_patterns=[
                r"\.FormFile\s*\(",
                r"\.MultipartForm\b",
                r"\.ParseMultipartForm\s*\(",
                r"r\.FormFile\s*\(",
                r"r\.MultipartForm\b",
            ],
            risk_level="critical",
            controllability="full",
            description="File upload via r.FormFile() or r.MultipartForm",
            example='file, header, _ := r.FormFile("upload")',
        ),
    ])

    # =========================================================================
    # Gin Framework Sources
    # =========================================================================
    sources.extend([
        SourceDefinition(
            name="gin_Param",
            category=SourceCategory.HTTP_PARAM,
            language="go",
            function_patterns=[
                r"c\.Param\s*\(",
                r"c\.Params\s*\.",
            ],
            risk_level="high",
            controllability="full",
            description="Gin URL path parameter via c.Param()",
            example='id := c.Param("id")',
            metadata={"framework": "gin"},
        ),
        SourceDefinition(
            name="gin_Query",
            category=SourceCategory.HTTP_PARAM,
            language="go",
            function_patterns=[
                r"c\.Query\s*\(",
                r"c\.DefaultQuery\s*\(",
                r"c\.GetQuery\s*\(",
            ],
            risk_level="high",
            controllability="full",
            description="Gin query string parameter via c.Query() / c.DefaultQuery()",
            example='name := c.Query("name")',
            metadata={"framework": "gin"},
        ),
        SourceDefinition(
            name="gin_PostForm",
            category=SourceCategory.HTTP_PARAM,
            language="go",
            function_patterns=[
                r"c\.PostForm\s*\(",
                r"c\.DefaultPostForm\s*\(",
                r"c\.GetPostForm\s*\(",
            ],
            risk_level="high",
            controllability="full",
            description="Gin form POST parameter via c.PostForm() / c.DefaultPostForm()",
            example='email := c.PostForm("email")',
            metadata={"framework": "gin"},
        ),
        SourceDefinition(
            name="gin_Body",
            category=SourceCategory.HTTP_PARAM,
            language="go",
            function_patterns=[
                r"c\.GetRawData\s*\(",
                r"c\.Copy\s*\(\s*\)\.GetRawData",
            ],
            risk_level="high",
            controllability="full",
            description="Gin raw request body via c.GetRawData()",
            example='data, _ := c.GetRawData()',
            metadata={"framework": "gin"},
        ),
        SourceDefinition(
            name="gin_Header",
            category=SourceCategory.HTTP_HEADER,
            language="go",
            function_patterns=[
                r"c\.GetHeader\s*\(",
                r"c\.Request\.Header\.Get\s*\(",
            ],
            risk_level="high",
            controllability="full",
            description="Gin HTTP header via c.GetHeader()",
            example='auth := c.GetHeader("Authorization")',
            metadata={"framework": "gin"},
        ),
        SourceDefinition(
            name="gin_Cookie",
            category=SourceCategory.COOKIE,
            language="go",
            function_patterns=[
                r"c\.Cookie\s*\(",
            ],
            risk_level="high",
            controllability="full",
            description="Gin cookie via c.Cookie()",
            example='token, _ := c.Cookie("token")',
            metadata={"framework": "gin"},
        ),
    ])

    # =========================================================================
    # Echo Framework Sources
    # =========================================================================
    sources.extend([
        SourceDefinition(
            name="echo_Param",
            category=SourceCategory.HTTP_PARAM,
            language="go",
            function_patterns=[
                r"c\.Param\s*\(",
                r"c\.ParamNames\s*\(\s*\)",
                r"c\.ParamValues\s*\(\s*\)",
            ],
            risk_level="high",
            controllability="full",
            description="Echo URL path parameter via c.Param()",
            example='id := c.Param("id")',
            metadata={"framework": "echo"},
        ),
        SourceDefinition(
            name="echo_QueryParam",
            category=SourceCategory.HTTP_PARAM,
            language="go",
            function_patterns=[
                r"c\.QueryParam\s*\(",
                r"c\.QueryParams\s*\(\s*\)",
            ],
            risk_level="high",
            controllability="full",
            description="Echo query string parameter via c.QueryParam()",
            example='page := c.QueryParam("page")',
            metadata={"framework": "echo"},
        ),
        SourceDefinition(
            name="echo_FormValue",
            category=SourceCategory.HTTP_PARAM,
            language="go",
            function_patterns=[
                r"c\.FormValue\s*\(",
                r"c\.FormParams\s*\(\s*\)",
            ],
            risk_level="high",
            controllability="full",
            description="Echo form parameter via c.FormValue()",
            example='name := c.FormValue("name")',
            metadata={"framework": "echo"},
        ),
        SourceDefinition(
            name="echo_Header",
            category=SourceCategory.HTTP_HEADER,
            language="go",
            function_patterns=[
                r"c\.Request\s*\(\s*\)\.Header\.Get\s*\(",
            ],
            risk_level="high",
            controllability="full",
            description="Echo request header",
            example='ua := c.Request().Header.Get("User-Agent")',
            metadata={"framework": "echo"},
        ),
    ])

    # =========================================================================
    # Chi Router Sources
    # =========================================================================
    sources.extend([
        SourceDefinition(
            name="chi_URLParam",
            category=SourceCategory.HTTP_PARAM,
            language="go",
            function_patterns=[
                r"chi\.URLParam\s*\(",
                r"chi\.URLParamFromCtx\s*\(",
                r"URLParam\s*\(\s*r\s*,",
            ],
            risk_level="high",
            controllability="full",
            description="Chi URL parameter via chi.URLParam()",
            example='id := chi.URLParam(r, "id")',
            metadata={"framework": "chi"},
        ),
    ])

    # =========================================================================
    # Gorilla/mux Sources
    # =========================================================================
    sources.extend([
        SourceDefinition(
            name="gorilla_mux_Vars",
            category=SourceCategory.HTTP_PARAM,
            language="go",
            function_patterns=[
                r"mux\.Vars\s*\(",
                r"mux\.CurrentRoute\s*\(",
            ],
            risk_level="high",
            controllability="full",
            description="Gorilla mux URL variables via mux.Vars()",
            example='vars := mux.Vars(r); id := vars["id"]',
            metadata={"framework": "gorilla/mux"},
        ),
    ])

    # =========================================================================
    # WebSocket Sources
    # =========================================================================
    sources.extend([
        SourceDefinition(
            name="gorilla_websocket_ReadMessage",
            category=SourceCategory.WEBSOCKET,
            language="go",
            function_patterns=[
                r"\.ReadMessage\s*\(\s*\)",
                r"\.ReadJSON\s*\(\s*",
                r"\.NextReader\s*\(\s*\)",
                r"\.Read\s*\(",
            ],
            risk_level="high",
            controllability="full",
            description="WebSocket message data via gorilla/websocket ReadMessage / ReadJSON",
            example='_, msg, _ := conn.ReadMessage()',
            metadata={"library": "github.com/gorilla/websocket"},
        ),
        SourceDefinition(
            name="nhooyr_websocket_Read",
            category=SourceCategory.WEBSOCKET,
            language="go",
            function_patterns=[
                r"websocket\.Read\s*\(",
                r"wsjson\.Read\s*\(",
            ],
            risk_level="high",
            controllability="full",
            description="WebSocket message data via nhooyr.io/websocket",
            example='_, msg, _ := websocket.Read(ctx, conn)',
            metadata={"library": "nhooyr.io/websocket"},
        ),
    ])

    # =========================================================================
    # Environment Sources
    # =========================================================================
    sources.extend([
        SourceDefinition(
            name="os_Getenv",
            category=SourceCategory.ENVIRONMENT,
            language="go",
            function_patterns=[
                r"os\.Getenv\s*\(",
                r"os\.LookupEnv\s*\(",
                r"os\.Environ\s*\(\s*\)",
                r"os\.ExpandEnv\s*\(",
            ],
            risk_level="low",
            controllability="none",
            description="Environment variable via os.Getenv() / os.LookupEnv()",
            example='dbURL := os.Getenv("DATABASE_URL")',
        ),
    ])

    # =========================================================================
    # File Read Sources
    # =========================================================================
    sources.extend([
        SourceDefinition(
            name="os_file_read_source",
            category=SourceCategory.FILE_READ,
            language="go",
            function_patterns=[
                r"os\.ReadFile\s*\(",
                r"io/ioutil\.ReadFile\s*\(",
                r"os\.Open\s*\([^)]*\)\.Read\s*\(",
                r"bufio\.NewScanner\s*\(",
                r"bufio\.NewReader\s*\(",
            ],
            risk_level="medium",
            controllability="none",
            description="File content read as input to further processing",
            example='data, _ := os.ReadFile("/etc/config.yaml")',
        ),
    ])

    # =========================================================================
    # Command Line Sources
    # =========================================================================
    sources.extend([
        SourceDefinition(
            name="os_Args",
            category=SourceCategory.COMMAND_LINE,
            language="go",
            function_patterns=[
                r"os\.Args\b",
                r"os\.Args\s*\[",
                r"flag\.Arg\s*\(",
                r"flag\.Args\s*\(\s*\)",
                r"flag\.String\s*\(",
                r"flag\.Int\s*\(",
                r"flag\.Bool\s*\(",
            ],
            risk_level="medium",
            controllability="full",
            description="Command line arguments via os.Args or flag package",
            example='name := flag.String("name", "", "user name")',
        ),
    ])

    # =========================================================================
    # Database Sources (Second-Order Injection)
    # =========================================================================
    sources.extend([
        SourceDefinition(
            name="database_sql_Rows",
            category=SourceCategory.DATABASE,
            language="go",
            function_patterns=[
                r"\.Scan\s*\(",
                r"rows\.Next\s*\(\s*\)",
                r"\.Query\s\(.*\)\.Scan",
            ],
            risk_level="medium",
            controllability="partial",
            description="Database query result used in subsequent queries (second-order injection)",
            example='rows.Scan(&id, &name, &email)',
        ),
    ])

    return sources


__all__ = [
    "get_sink_library",
    "get_source_library",
]
