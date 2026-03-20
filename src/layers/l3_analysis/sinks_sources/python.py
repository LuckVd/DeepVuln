"""
P6-05: Python Sink and Source Definitions

Integrated from code-audit/references/core/sinks_sources.md
Comprehensive definitions for Python/Flask/Django/FastAPI.
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
    """Get the Python sink library."""
    return SinkLibrary(
        language="python",
        sinks=_get_python_sinks(),
    )


def get_source_library() -> SourceLibrary:
    """Get the Python source library."""
    return SourceLibrary(
        language="python",
        sources=_get_python_sources(),
    )


def _get_python_sinks() -> list[SinkDefinition]:
    """Get all Python sink definitions."""
    sinks = []

    # =========================================================================
    # RCE - Remote Code Execution (Critical)
    # =========================================================================
    sinks.extend([
        SinkDefinition(
            name="os_system",
            category=SinkCategory.RCE,
            language="python",
            function_patterns=[
                r"os\.system\s*\(",
                r"os\.popen\s*\(",
                r"commands\.getoutput\s*\(",
                r"commands\.getstatusoutput\s*\(",
            ],
            cwe="CWE-78",
            owasp="A03:2021",
            description="Command injection via os.system()",
            impact="Remote code execution",
            effective_sanitizers=["subprocess with shell=False", "shlex.quote()"],
            safe_alternatives=["subprocess.run([cmd, arg1, arg2])"],
        ),
        SinkDefinition(
            name="subprocess_shell",
            category=SinkCategory.RCE,
            language="python",
            function_patterns=[
                r"subprocess\.call\s*\([^)]*shell\s*=\s*True",
                r"subprocess\.Popen\s*\([^)]*shell\s*=\s*True",
                r"subprocess\.run\s*\([^)]*shell\s*=\s*True",
                r"subprocess\.check_output\s*\([^)]*shell\s*=\s*True",
            ],
            cwe="CWE-78",
            owasp="A03:2021",
            description="Command injection via subprocess with shell=True",
            impact="Remote code execution",
            effective_sanitizers=["Use shell=False with list arguments"],
        ),
        SinkDefinition(
            name="eval_exec",
            category=SinkCategory.RCE,
            language="python",
            function_patterns=[
                r"\beval\s*\(",
                r"\bexec\s*\(",
                r"compile\s*\([^)]*,\s*['\"]exec['\"]",
            ],
            cwe="CWE-95",
            owasp="A03:2021",
            description="Code injection via eval/exec",
            impact="Arbitrary Python code execution",
            effective_sanitizers=["ast.literal_eval() for safe evaluation"],
        ),
        SinkDefinition(
            name="import_dynamic",
            category=SinkCategory.RCE,
            language="python",
            function_patterns=[
                r"__import__\s*\(",
                r"importlib\.import_module\s*\(",
                r"importlib\.__import__\s*\(",
            ],
            cwe="CWE-94",
            owasp="A03:2021",
            description="Dynamic module import with user input",
            impact="Arbitrary module loading and code execution",
        ),
    ])

    # =========================================================================
    # UNSERIALIZE - Deserialization (Critical)
    # =========================================================================
    sinks.extend([
        SinkDefinition(
            name="pickle_load",
            category=SinkCategory.UNSERIALIZE,
            language="python",
            function_patterns=[
                r"pickle\.loads\s*\(",
                r"pickle\.load\s*\(",
                r"cPickle\.loads\s*\(",
                r"cPickle\.load\s*\(",
            ],
            cwe="CWE-502",
            owasp="A08:2021",
            description="Insecure pickle deserialization",
            impact="Remote code execution via malicious pickle",
            effective_sanitizers=["Only unpickle trusted data", "Use HMAC signature"],
            safe_alternatives=["JSON", "msgpack"],
        ),
        SinkDefinition(
            name="yaml_load",
            category=SinkCategory.UNSERIALIZE,
            language="python",
            function_patterns=[
                r"yaml\.load\s*\(",
                r"yaml\.unsafe_load\s*\(",
                r"yaml\.full_load\s*\(",
            ],
            cwe="CWE-502",
            owasp="A08:2021",
            description="Insecure YAML deserialization",
            impact="Remote code execution via YAML tags",
            effective_sanitizers=["yaml.safe_load()"],
            safe_alternatives=["yaml.safe_load()", "yaml.load(data, Loader=yaml.SafeLoader)"],
        ),
        SinkDefinition(
            name="marshal_load",
            category=SinkCategory.UNSERIALIZE,
            language="python",
            function_patterns=[
                r"marshal\.loads\s*\(",
                r"marshal\.load\s*\(",
            ],
            cwe="CWE-502",
            owasp="A08:2021",
            description="Marshal deserialization",
            impact="Code execution",
            effective_sanitizers=["Avoid untrusted data"],
        ),
        SinkDefinition(
            name="shelve_open",
            category=SinkCategory.UNSERIALIZE,
            language="python",
            function_patterns=[
                r"shelve\.open\s*\(",
            ],
            cwe="CWE-502",
            owasp="A08:2021",
            description="Shelve uses pickle internally",
            impact="Code execution via pickle",
        ),
    ])

    # =========================================================================
    # SQLI - SQL Injection (Critical)
    # =========================================================================
    sinks.extend([
        SinkDefinition(
            name="db_execute",
            category=SinkCategory.SQLI,
            language="python",
            function_patterns=[
                r"cursor\.execute\s*\(",
                r"cursor\.executemany\s*\(",
                r"cursor\.executescript\s*\(",
                r"connection\.execute\s*\(",
                r"engine\.execute\s*\(",
            ],
            cwe="CWE-89",
            owasp="A03:2021",
            description="SQL injection via DB-API execute",
            impact="Database compromise",
            effective_sanitizers=["Parameterized queries with %s or ?"],
            safe_alternatives=["cursor.execute('SELECT * FROM users WHERE id = %s', (user_id,))"],
        ),
        SinkDefinition(
            name="django_raw",
            category=SinkCategory.SQLI,
            language="python",
            function_patterns=[
                r"Model\.objects\.raw\s*\(",
                r"Model\.objects\.extra\s*\(",
                r"RawSQL\s*\(",
            ],
            cwe="CWE-89",
            owasp="A03:2021",
            description="SQL injection via Django raw SQL",
            impact="Database compromise",
            effective_sanitizers=["Use ORM methods", "Parameterized raw queries"],
        ),
        SinkDefinition(
            name="sqlalchemy_text",
            category=SinkCategory.SQLI,
            language="python",
            function_patterns=[
                r"text\s*\([^)]*\+",  # text() with string concat
                r"\.execute\s*\([^)]*\+",  # execute with concat
            ],
            cwe="CWE-89",
            owasp="A03:2021",
            description="SQL injection via SQLAlchemy text()",
            impact="Database compromise",
            effective_sanitizers=["Use bind parameters"],
        ),
    ])

    # =========================================================================
    # SSRF - Server-Side Request Forgery (High)
    # =========================================================================
    sinks.extend([
        SinkDefinition(
            name="requests",
            category=SinkCategory.SSRF,
            language="python",
            function_patterns=[
                r"requests\.get\s*\(",
                r"requests\.post\s*\(",
                r"requests\.put\s*\(",
                r"requests\.delete\s*\(",
                r"requests\.request\s*\(",
                r"requests\.Session\(\).*\.get\s*\(",
            ],
            cwe="CWE-918",
            owasp="A10:2021",
            description="SSRF via requests library",
            impact="Internal network access, cloud metadata exposure",
            effective_sanitizers=["URL whitelist", "Disable redirects to internal IPs"],
        ),
        SinkDefinition(
            name="urllib",
            category=SinkCategory.SSRF,
            language="python",
            function_patterns=[
                r"urllib\.request\.urlopen\s*\(",
                r"urllib\.urlopen\s*\(",
                r"urllib2\.urlopen\s*\(",
                r"URLopener\(\).*\.open\s*\(",
            ],
            cwe="CWE-918",
            owasp="A10:2021",
            description="SSRF via urllib",
            impact="Internal resource access",
            effective_sanitizers=["URL validation"],
        ),
        SinkDefinition(
            name="httpx",
            category=SinkCategory.SSRF,
            language="python",
            function_patterns=[
                r"httpx\.get\s*\(",
                r"httpx\.post\s*\(",
                r"httpx\.Client\(\).*\.get\s*\(",
            ],
            cwe="CWE-918",
            owasp="A10:2021",
            description="SSRF via httpx library",
            impact="Internal resource access",
            effective_sanitizers=["URL whitelist"],
        ),
    ])

    # =========================================================================
    # PATH_TRAVERSAL - Path Traversal (High)
    # =========================================================================
    sinks.extend([
        SinkDefinition(
            name="file_operations",
            category=SinkCategory.PATH_TRAVERSAL,
            language="python",
            function_patterns=[
                r"\bopen\s*\(",
                r"File\s*\(",
                r"fileinput\.input\s*\(",
            ],
            cwe="CWE-22",
            owasp="A01:2021",
            description="Path traversal via file operations",
            impact="Arbitrary file read/write",
            effective_sanitizers=["os.path.realpath()", "Validate path doesn't contain ../"],
        ),
        SinkDefinition(
            name="pathlib",
            category=SinkCategory.PATH_TRAVERSAL,
            language="python",
            function_patterns=[
                r"Path\s*\(",
                r"PurePath\s*\(",
                r"Path\([^)]*\)\.read_text\s*\(",
                r"Path\([^)]*\)\.write_text\s*\(",
            ],
            cwe="CWE-22",
            owasp="A01:2021",
            description="Path traversal via pathlib",
            impact="Arbitrary file access",
            effective_sanitizers=["resolve() and validate"],
        ),
        SinkDefinition(
            name="shutil",
            category=SinkCategory.PATH_TRAVERSAL,
            language="python",
            function_patterns=[
                r"shutil\.copy\s*\(",
                r"shutil\.copytree\s*\(",
                r"shutil\.move\s*\(",
                r"shutil\.rmtree\s*\(",
            ],
            cwe="CWE-22",
            owasp="A01:2021",
            description="Path traversal via shutil",
            impact="Arbitrary file operations",
            effective_sanitizers=["Validate paths"],
        ),
    ])

    # =========================================================================
    # XSS - Cross-Site Scripting (Medium)
    # =========================================================================
    sinks.extend([
        SinkDefinition(
            name="template_render",
            category=SinkCategory.XSS,
            language="python",
            function_patterns=[
                r"render_template_string\s*\(",
                r"Template\s*\([^)]*\)\.render\s*\(",
                r"Environment\(\).*\.from_string\s*\(",
            ],
            cwe="CWE-79",
            owasp="A03:2021",
            description="XSS via template rendering",
            impact="Cross-site scripting",
            effective_sanitizers=["Auto-escape enabled", "mark_safe only for trusted content"],
        ),
        SinkDefinition(
            name="response_write",
            category=SinkCategory.XSS,
            language="python",
            function_patterns=[
                r"HttpResponse\s*\(",
                r"make_response\s*\(",
                r"Response\s*\(",
                r"mark_safe\s*\(",
            ],
            cwe="CWE-79",
            owasp="A03:2021",
            description="XSS via response output",
            impact="Cross-site scripting",
            effective_sanitizers=["escape() filter", "auto-escape templates"],
        ),
    ])

    # =========================================================================
    # SSTI - Server-Side Template Injection (High)
    # =========================================================================
    sinks.extend([
        SinkDefinition(
            name="jinja2_render",
            category=SinkCategory.SSTI,
            language="python",
            function_patterns=[
                r"jinja2\.Template\s*\([^)]*\)\.render\s*\(",
                r"Environment\(\).*\.from_string\s*\(",
                r"BaseLoader\(\).*\.from_string\s*\(",
            ],
            cwe="CWE-94",
            owasp="A03:2021",
            description="Server-side template injection via Jinja2",
            impact="Remote code execution",
            effective_sanitizers=["Sandboxed environment", "Disable dangerous filters"],
        ),
        SinkDefinition(
            name="mako_render",
            category=SinkCategory.SSTI,
            language="python",
            function_patterns=[
                r"mako\.template\.Template\s*\(",
                r"Template\s*\([^)]*\)\.render\s*\(",
            ],
            cwe="CWE-94",
            owasp="A03:2021",
            description="Server-side template injection via Mako",
            impact="Remote code execution",
        ),
    ])

    return sinks


def _get_python_sources() -> list[SourceDefinition]:
    """Get all Python source definitions."""
    sources = []

    # =========================================================================
    # Flask Sources
    # =========================================================================
    sources.extend([
        SourceDefinition(
            name="flask_request",
            category=SourceCategory.HTTP_PARAM,
            language="python",
            function_patterns=[
                r"request\.args\.get\s*\(",
                r"request\.args\s*\[",
                r"request\.form\.get\s*\(",
                r"request\.form\s*\[",
                r"request\.values\.get\s*\(",
                r"request\.values\s*\[",
            ],
            risk_level="high",
            controllability="full",
            description="Flask request parameters",
            example='name = request.args.get("name")',
        ),
        SourceDefinition(
            name="flask_json",
            category=SourceCategory.HTTP_PARAM,
            language="python",
            function_patterns=[
                r"request\.json",
                r"request\.get_json\s*\(",
                r"request\.data",
            ],
            risk_level="high",
            controllability="full",
            description="Flask JSON body",
        ),
        SourceDefinition(
            name="flask_headers",
            category=SourceCategory.HTTP_HEADER,
            language="python",
            function_patterns=[
                r"request\.headers\.get\s*\(",
                r"request\.headers\s*\[",
            ],
            risk_level="high",
            controllability="full",
            description="Flask request headers",
        ),
        SourceDefinition(
            name="flask_cookies",
            category=SourceCategory.COOKIE,
            language="python",
            function_patterns=[
                r"request\.cookies\.get\s*\(",
                r"request\.cookies\s*\[",
            ],
            risk_level="high",
            controllability="full",
            description="Flask cookies",
        ),
        SourceDefinition(
            name="flask_files",
            category=SourceCategory.FILE_UPLOAD,
            language="python",
            function_patterns=[
                r"request\.files\s*\[",
                r"request\.files\.get\s*\(",
            ],
            risk_level="critical",
            controllability="full",
            description="Flask uploaded files",
        ),
    ])

    # =========================================================================
    # Django Sources
    # =========================================================================
    sources.extend([
        SourceDefinition(
            name="django_request",
            category=SourceCategory.HTTP_PARAM,
            language="python",
            function_patterns=[
                r"request\.GET\.get\s*\(",
                r"request\.GET\s*\[",
                r"request\.POST\.get\s*\(",
                r"request\.POST\s*\[",
                r"request\.body",
            ],
            risk_level="high",
            controllability="full",
            description="Django request parameters",
        ),
        SourceDefinition(
            name="django_meta",
            category=SourceCategory.HTTP_HEADER,
            language="python",
            function_patterns=[
                r"request\.META\.get\s*\(",
                r"request\.META\s*\[",
            ],
            risk_level="high",
            controllability="full",
            description="Django META (headers)",
        ),
        SourceDefinition(
            name="django_cookies",
            category=SourceCategory.COOKIE,
            language="python",
            function_patterns=[
                r"request\.COOKIES\.get\s*\(",
                r"request\.COOKIES\s*\[",
            ],
            risk_level="high",
            controllability="full",
            description="Django cookies",
        ),
        SourceDefinition(
            name="django_files",
            category=SourceCategory.FILE_UPLOAD,
            language="python",
            function_patterns=[
                r"request\.FILES\s*\[",
                r"request\.FILES\.get\s*\(",
            ],
            risk_level="critical",
            controllability="full",
            description="Django uploaded files",
        ),
    ])

    # =========================================================================
    # FastAPI Sources
    # =========================================================================
    sources.extend([
        SourceDefinition(
            name="fastapi_param",
            category=SourceCategory.HTTP_PARAM,
            language="python",
            annotation_patterns=[
                r"Query\s*\(",
                r"Path\s*\(",
                r"Form\s*\(",
                r"Body\s*\(",
            ],
            risk_level="high",
            controllability="full",
            description="FastAPI parameter annotations",
            example='def handler(name: str = Query(...))',
        ),
        SourceDefinition(
            name="fastapi_header",
            category=SourceCategory.HTTP_HEADER,
            language="python",
            annotation_patterns=[
                r"Header\s*\(",
            ],
            risk_level="high",
            controllability="full",
            description="FastAPI header annotation",
        ),
        SourceDefinition(
            name="fastapi_cookie",
            category=SourceCategory.COOKIE,
            language="python",
            annotation_patterns=[
                r"Cookie\s*\(",
            ],
            risk_level="high",
            controllability="full",
            description="FastAPI cookie annotation",
        ),
        SourceDefinition(
            name="fastapi_file",
            category=SourceCategory.FILE_UPLOAD,
            language="python",
            annotation_patterns=[
                r"UploadFile",
                r"File\s*\(",
            ],
            risk_level="critical",
            controllability="full",
            description="FastAPI file upload",
        ),
    ])

    # =========================================================================
    # General Python Sources
    # =========================================================================
    sources.extend([
        SourceDefinition(
            name="input_func",
            category=SourceCategory.COMMAND_LINE,
            language="python",
            function_patterns=[
                r"\binput\s*\(",
            ],
            risk_level="medium",
            controllability="full",
            description="User input from console",
        ),
        SourceDefinition(
            name="sys_argv",
            category=SourceCategory.COMMAND_LINE,
            language="python",
            variable_patterns=[
                r"sys\.argv",
            ],
            risk_level="medium",
            controllability="full",
            description="Command line arguments",
        ),
        SourceDefinition(
            name="os_environ",
            category=SourceCategory.ENVIRONMENT,
            language="python",
            function_patterns=[
                r"os\.environ\.get\s*\(",
                r"os\.getenv\s*\(",
                r"os\.environ\s*\[",
            ],
            risk_level="low",
            controllability="none",
            description="Environment variables",
        ),
        SourceDefinition(
            name="file_read",
            category=SourceCategory.FILE_READ,
            language="python",
            function_patterns=[
                r"\bopen\s*\([^)]*\)\.read\s*\(",
                r"read_file\s*\(",
            ],
            risk_level="medium",
            controllability="none",
            description="File content",
        ),
    ])

    return sources


__all__ = [
    "get_sink_library",
    "get_source_library",
]
