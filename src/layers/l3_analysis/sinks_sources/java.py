"""
P6-05: Java Sink and Source Definitions

Integrated from code-audit/references/core/sinks_sources.md
Comprehensive definitions for Java/Spring framework.
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
    """Get the Java sink library."""
    return SinkLibrary(
        language="java",
        sinks=_get_java_sinks(),
    )


def get_source_library() -> SourceLibrary:
    """Get the Java source library."""
    return SourceLibrary(
        language="java",
        sources=_get_java_sources(),
    )


def _get_java_sinks() -> list[SinkDefinition]:
    """Get all Java sink definitions."""
    sinks = []

    # =========================================================================
    # RCE - Remote Code Execution (Critical)
    # =========================================================================
    sinks.extend([
        # Command Execution
        SinkDefinition(
            name="Runtime.exec",
            category=SinkCategory.RCE,
            language="java",
            function_patterns=[
                r"Runtime\.getRuntime\(\)\.exec\s*\(",
                r"Runtime\.exec\s*\(",
            ],
            cwe="CWE-78",
            owasp="A03:2021",
            description="Command injection via Runtime.exec()",
            impact="Remote code execution with application privileges",
            effective_sanitizers=["ProcessBuilder with argument list"],
            safe_alternatives=["ProcessBuilder with command list"],
        ),
        SinkDefinition(
            name="ProcessBuilder",
            category=SinkCategory.RCE,
            language="java",
            function_patterns=[
                r"ProcessBuilder\s*\(",
                r"ProcessBuilder\.command\s*\(",
                r"\.start\s*\(\s*\)",
            ],
            cwe="CWE-78",
            owasp="A03:2021",
            description="Command injection via ProcessBuilder",
            impact="Remote code execution",
            effective_sanitizers=["Use List<String> for commands, avoid shell=True equivalent"],
        ),
        # Script Engine
        SinkDefinition(
            name="ScriptEngine.eval",
            category=SinkCategory.RCE,
            language="java",
            function_patterns=[
                r"ScriptEngine.*\.eval\s*\(",
                r"GroovyShell.*\.evaluate\s*\(",
                r"GroovyShell.*\.parse\s*\(",
            ],
            cwe="CWE-94",
            owasp="A03:2021",
            description="Code injection via script engine evaluation",
            impact="Arbitrary code execution",
            effective_sanitizers=["Sandboxing", "Input validation"],
        ),
        # Expression Language Injection
        SinkDefinition(
            name="SpELInjection",
            category=SinkCategory.RCE,
            language="java",
            function_patterns=[
                r"SpelExpressionParser.*parseExpression\s*\(",
                r"ExpressionParser.*parseExpression\s*\(",
                r"StandardEvaluationContext\.setVariable\s*\(",
                r"Ognl\.getValue\s*\(",
                r"Ognl\.setValue\s*\(",
                r"ValueStack\.findValue\s*\(",
                r"MVEL\.eval\s*\(",
            ],
            cwe="CWE-917",
            owasp="A03:2021",
            description="Expression language injection (SpEL/OGNL/MVEL)",
            impact="Remote code execution via expression evaluation",
            effective_sanitizers=["SimpleEvaluationContext", "Input validation"],
        ),
        # Reflection
        SinkDefinition(
            name="Reflection",
            category=SinkCategory.RCE,
            language="java",
            function_patterns=[
                r"Class\.forName\s*\(",
                r"\.getMethod\s*\(",
                r"Method\.invoke\s*\(",
                r"Constructor\.newInstance\s*\(",
                r"ClassLoader\.loadClass\s*\(",
            ],
            cwe="CWE-470",
            owasp="A03:2021",
            description="Dangerous reflection with user-controlled input",
            impact="Arbitrary class loading and method invocation",
        ),
    ])

    # =========================================================================
    # UNSERIALIZE - Deserialization (Critical)
    # =========================================================================
    sinks.extend([
        # Java Native
        SinkDefinition(
            name="ObjectInputStream",
            category=SinkCategory.UNSERIALIZE,
            language="java",
            function_patterns=[
                r"ObjectInputStream.*\.readObject\s*\(",
                r"ObjectInputStream.*\.readUnshared\s*\(",
            ],
            cwe="CWE-502",
            owasp="A08:2021",
            description="Java native deserialization vulnerability",
            impact="Remote code execution via gadget chains",
            effective_sanitizers=["ValidatingObjectInputStream", "Whitelist classes"],
            requires_dataflow=True,
        ),
        # XML Decoder
        SinkDefinition(
            name="XMLDecoder",
            category=SinkCategory.UNSERIALIZE,
            language="java",
            function_patterns=[
                r"XMLDecoder.*\.readObject\s*\(",
            ],
            cwe="CWE-502",
            owasp="A08:2021",
            description="XML deserialization leading to RCE",
            impact="Arbitrary object creation and method invocation",
        ),
        # Fastjson
        SinkDefinition(
            name="Fastjson",
            category=SinkCategory.UNSERIALIZE,
            language="java",
            function_patterns=[
                r"JSON\.parse\s*\(",
                r"JSON\.parseObject\s*\(",
                r"JSONObject\.parse\s*\(",
                r"JSONObject\.parseObject\s*\(",
            ],
            cwe="CWE-502",
            owasp="A08:2021",
            description="Fastjson deserialization with autoType",
            impact="Remote code execution via @type directive",
            effective_sanitizers=["Disable autoType", "Use safeMode"],
            metadata={"versions_affected": "< 1.2.83"},
        ),
        # Jackson
        SinkDefinition(
            name="Jackson",
            category=SinkCategory.UNSERIALIZE,
            language="java",
            function_patterns=[
                r"ObjectMapper.*\.readValue\s*\(",
                r"enableDefaultTyping\s*\(",
            ],
            cwe="CWE-502",
            owasp="A08:2021",
            description="Jackson polymorphic deserialization",
            impact="Remote code execution with enableDefaultTyping",
            effective_sanitizers=["Disable default typing", "Use @JsonTypeInfo with explicit types"],
        ),
        # SnakeYAML
        SinkDefinition(
            name="SnakeYAML",
            category=SinkCategory.UNSERIALIZE,
            language="java",
            function_patterns=[
                r"Yaml\s*\(\s*\)\.load\s*\(",
                r"Yaml.*\.load\s*\(",
                r"Yaml.*\.loadAs\s*\(",
            ],
            cwe="CWE-502",
            owasp="A08:2021",
            description="SnakeYAML unsafe deserialization",
            impact="Remote code execution via YAML !!type directive",
            effective_sanitizers=["SafeConstructor", "SafePropertyUtils"],
            safe_alternatives=["new Yaml(new SafeConstructor())"],
        ),
        # XStream
        SinkDefinition(
            name="XStream",
            category=SinkCategory.UNSERIALIZE,
            language="java",
            function_patterns=[
                r"XStream.*\.fromXML\s*\(",
                r"XStream.*\.unmarshal\s*\(",
            ],
            cwe="CWE-502",
            owasp="A08:2021",
            description="XStream deserialization vulnerability",
            impact="Remote code execution",
            effective_sanitizers=["Security framework", "Whitelist"],
        ),
    ])

    # =========================================================================
    # SQLI - SQL Injection (Critical)
    # =========================================================================
    sinks.extend([
        # JDBC
        SinkDefinition(
            name="JDBC_Statement",
            category=SinkCategory.SQLI,
            language="java",
            function_patterns=[
                r"Statement.*\.execute\s*\(",
                r"Statement.*\.executeQuery\s*\(",
                r"Statement.*\.executeUpdate\s*\(",
                r"Statement.*\.executeBatch\s*\(",
            ],
            cwe="CWE-89",
            owasp="A03:2021",
            description="SQL injection via JDBC Statement",
            impact="Database data theft, modification, or deletion",
            effective_sanitizers=["PreparedStatement", "Parameterized queries"],
            safe_alternatives=["PreparedStatement with ? placeholders"],
        ),
        # JPA/Hibernate
        SinkDefinition(
            name="JPA_Query",
            category=SinkCategory.SQLI,
            language="java",
            function_patterns=[
                r"EntityManager.*\.createQuery\s*\(",
                r"EntityManager.*\.createNativeQuery\s*\(",
                r"Session.*\.createQuery\s*\(",
                r"Session.*\.createSQLQuery\s*\(",
            ],
            cwe="CWE-89",
            owasp="A03:2021",
            description="SQL injection via JPA/Hibernate query",
            impact="Database compromise",
            effective_sanitizers=["Parameterized queries", "Criteria API"],
        ),
        # MyBatis
        SinkDefinition(
            name="MyBatis",
            category=SinkCategory.SQLI,
            language="java",
            function_patterns=[
                r"SqlSession.*\.selectOne\s*\(",
                r"SqlSession.*\.selectList\s*\(",
                r"SqlSession.*\.insert\s*\(",
                r"SqlSession.*\.update\s*\(",
                r"SqlSession.*\.delete\s*\(",
            ],
            cwe="CWE-89",
            owasp="A03:2021",
            description="SQL injection via MyBatis ${} syntax",
            impact="Database compromise",
            effective_sanitizers=["Use #{} instead of ${}"],
            metadata={"note": "Check XML mapper files for ${} usage"},
        ),
        # Spring JDBC
        SinkDefinition(
            name="SpringJDBC",
            category=SinkCategory.SQLI,
            language="java",
            function_patterns=[
                r"JdbcTemplate.*\.query\s*\(",
                r"JdbcTemplate.*\.queryForObject\s*\(",
                r"JdbcTemplate.*\.queryForList\s*\(",
                r"JdbcTemplate.*\.execute\s*\(",
                r"JdbcTemplate.*\.update\s*\(",
            ],
            cwe="CWE-89",
            owasp="A03:2021",
            description="SQL injection via Spring JdbcTemplate",
            impact="Database compromise",
            effective_sanitizers=["PreparedStatementCreator", "NamedParameterJdbcTemplate"],
        ),
    ])

    # =========================================================================
    # SSRF - Server-Side Request Forgery (High)
    # =========================================================================
    sinks.extend([
        SinkDefinition(
            name="URL_Connection",
            category=SinkCategory.SSRF,
            language="java",
            function_patterns=[
                r"URL\s*\([^)]*\)\.openConnection\s*\(",
                r"URL\s*\([^)]*\)\.openStream\s*\(",
                r"URLConnection.*\.connect\s*\(",
                r"HttpURLConnection.*\.connect\s*\(",
            ],
            cwe="CWE-918",
            owasp="A10:2021",
            description="SSRF via URL connection",
            impact="Access to internal resources, cloud metadata",
            effective_sanitizers=["URL validation", "Whitelist allowed hosts"],
        ),
        SinkDefinition(
            name="HttpClient",
            category=SinkCategory.SSRF,
            language="java",
            function_patterns=[
                r"HttpClient.*\.execute\s*\(",
                r"CloseableHttpClient.*\.execute\s*\(",
                r"HttpGet\s*\(",
                r"HttpPost\s*\(",
                r"OkHttpClient.*\.newCall.*\.execute\s*\(",
            ],
            cwe="CWE-918",
            owasp="A10:2021",
            description="SSRF via Apache HttpClient or OkHttp",
            impact="Internal network access, cloud metadata exposure",
            effective_sanitizers=["URL whitelist", "Disable redirects to internal IPs"],
        ),
        SinkDefinition(
            name="RestTemplate",
            category=SinkCategory.SSRF,
            language="java",
            function_patterns=[
                r"RestTemplate.*\.getForObject\s*\(",
                r"RestTemplate.*\.getForEntity\s*\(",
                r"RestTemplate.*\.postForObject\s*\(",
                r"RestTemplate.*\.exchange\s*\(",
                r"WebClient\.create\s*\(",
            ],
            cwe="CWE-918",
            owasp="A10:2021",
            description="SSRF via Spring RestTemplate/WebClient",
            impact="Internal resource access",
            effective_sanitizers=["URL validation", "Allowed hosts whitelist"],
        ),
    ])

    # =========================================================================
    # XXE - XML External Entity (High)
    # =========================================================================
    sinks.extend([
        SinkDefinition(
            name="XML_Parser",
            category=SinkCategory.XXE,
            language="java",
            function_patterns=[
                r"DocumentBuilder.*\.parse\s*\(",
                r"SAXParser.*\.parse\s*\(",
                r"XMLReader.*\.parse\s*\(",
                r"XMLInputFactory.*\.createXMLStreamReader\s*\(",
                r"XMLInputFactory.*\.createXMLEventReader\s*\(",
            ],
            cwe="CWE-611",
            owasp="A05:2021",
            description="XXE via XML parser",
            impact="File disclosure, SSRF, DoS",
            effective_sanitizers=["Disable DTD", "Disable external entities"],
            safe_alternatives=["Configure parser with secure settings"],
        ),
    ])

    # =========================================================================
    # PATH_TRAVERSAL - Path Traversal (High)
    # =========================================================================
    sinks.extend([
        SinkDefinition(
            name="File_Operations",
            category=SinkCategory.PATH_TRAVERSAL,
            language="java",
            function_patterns=[
                r"new\s+File\s*\(",
                r"FileInputStream\s*\(",
                r"FileOutputStream\s*\(",
                r"FileReader\s*\(",
                r"FileWriter\s*\(",
                r"RandomAccessFile\s*\(",
                r"Files\.readAllBytes\s*\(",
                r"Files\.readAllLines\s*\(",
                r"Files\.write\s*\(",
                r"Paths\.get\s*\(",
            ],
            cwe="CWE-22",
            owasp="A01:2021",
            description="Path traversal via file operations",
            impact="Arbitrary file read/write",
            effective_sanitizers=["Path normalization", "Whitelist allowed directories"],
            safe_alternatives=["Use getCanonicalPath() and validate"],
        ),
        SinkDefinition(
            name="Zip_Slip",
            category=SinkCategory.PATH_TRAVERSAL,
            language="java",
            function_patterns=[
                r"ZipEntry.*\.getName\s*\(",
                r"ZipUtil\.unpack\s*\(",
                r"ZipUtil\.unzip\s*\(",
            ],
            cwe="CWE-22",
            owasp="A01:2021",
            description="Zip Slip vulnerability",
            impact="Arbitrary file write via malicious zip entries",
            effective_sanitizers=["Validate entry names don't contain ../"],
        ),
    ])

    # =========================================================================
    # XSS - Cross-Site Scripting (Medium)
    # =========================================================================
    sinks.extend([
        SinkDefinition(
            name="Response_Output",
            category=SinkCategory.XSS,
            language="java",
            function_patterns=[
                r"HttpServletResponse.*\.getWriter\s*\(\s*\)\.write\s*\(",
                r"HttpServletResponse.*\.getOutputStream\s*\(\s*\)\.write\s*\(",
                r"PrintWriter.*\.write\s*\(",
                r"PrintWriter.*\.print\s*\(",
                r"JspWriter.*\.write\s*\(",
                r"JspWriter.*\.print\s*\(",
            ],
            cwe="CWE-79",
            owasp="A03:2021",
            description="XSS via response output",
            impact="Cross-site scripting, session hijacking",
            effective_sanitizers=["HTML entity encoding", "OWASP ESAPI"],
            safe_alternatives=["Use templating with auto-escaping"],
        ),
        SinkDefinition(
            name="Template_Unescaped",
            category=SinkCategory.XSS,
            language="java",
            function_patterns=[
                r"\$!\{",  # Velocity unescaped
                r"\?no_esc",  # FreeMarker no escape
                r"th:utext",  # Thymeleaf unescaped text
            ],
            cwe="CWE-79",
            owasp="A03:2021",
            description="XSS via unescaped template output",
            impact="Cross-site scripting",
            effective_sanitizers=["Use escaped output by default"],
        ),
    ])

    # =========================================================================
    # REDIRECT - Open Redirect (Medium)
    # =========================================================================
    sinks.extend([
        SinkDefinition(
            name="URL_Redirect",
            category=SinkCategory.REDIRECT,
            language="java",
            function_patterns=[
                r"HttpServletResponse.*\.sendRedirect\s*\(",
                r"RedirectView\s*\(",
                r'"redirect:"\s*\+',  # Spring redirect prefix
            ],
            cwe="CWE-601",
            owasp="A01:2021",
            description="Open redirect vulnerability",
            impact="Phishing attacks, authentication bypass",
            effective_sanitizers=["URL whitelist", "Relative URL validation"],
        ),
    ])

    # =========================================================================
    # LDAP - LDAP Injection (High)
    # =========================================================================
    sinks.extend([
        SinkDefinition(
            name="LDAP_Query",
            category=SinkCategory.LDAP,
            language="java",
            function_patterns=[
                r"DirContext.*\.search\s*\(",
                r"InitialDirContext.*\.search\s*\(",
                r"LdapContext.*\.search\s*\(",
                r"LdapTemplate.*\.search\s*\(",
            ],
            cwe="CWE-90",
            owasp="A03:2021",
            description="LDAP injection",
            impact="Authentication bypass, data disclosure",
            effective_sanitizers=["Parameterized LDAP queries", "Input escaping"],
        ),
    ])

    # =========================================================================
    # SSTI - Server-Side Template Injection (High)
    # =========================================================================
    sinks.extend([
        SinkDefinition(
            name="Template_Engine",
            category=SinkCategory.SSTI,
            language="java",
            function_patterns=[
                r"Velocity\.evaluate\s*\(",
                r"Velocity\.merge\s*\(",
                r"FreeMarker.*\.process\s*\(",
                r"Thymeleaf.*\.process\s*\(",
            ],
            cwe="CWE-94",
            owasp="A03:2021",
            description="Server-side template injection",
            impact="Remote code execution via template engine",
            effective_sanitizers=["Sandbox mode", "Disable dangerous directives"],
        ),
    ])

    return sinks


def _get_java_sources() -> list[SourceDefinition]:
    """Get all Java source definitions."""
    sources = []

    # =========================================================================
    # Servlet Sources
    # =========================================================================
    sources.extend([
        SourceDefinition(
            name="ServletRequest",
            category=SourceCategory.HTTP_PARAM,
            language="java",
            function_patterns=[
                r"request\.getParameter\s*\(",
                r"request\.getParameterValues\s*\(",
                r"request\.getParameterMap\s*\(",
            ],
            risk_level="high",
            controllability="full",
            description="HTTP parameter from Servlet request",
            example='String name = request.getParameter("name");',
        ),
        SourceDefinition(
            name="ServletHeader",
            category=SourceCategory.HTTP_HEADER,
            language="java",
            function_patterns=[
                r"request\.getHeader\s*\(",
                r"request\.getHeaders\s*\(",
                r"request\.getIntHeader\s*\(",
                r"request\.getDateHeader\s*\(",
            ],
            risk_level="high",
            controllability="full",
            description="HTTP header from Servlet request",
        ),
        SourceDefinition(
            name="ServletCookie",
            category=SourceCategory.COOKIE,
            language="java",
            function_patterns=[
                r"request\.getCookies\s*\(",
                r"request\.getCookie\s*\(",
            ],
            risk_level="high",
            controllability="full",
            description="Cookie from Servlet request",
        ),
        SourceDefinition(
            name="ServletBody",
            category=SourceCategory.HTTP_PARAM,
            language="java",
            function_patterns=[
                r"request\.getInputStream\s*\(",
                r"request\.getReader\s*\(",
                r"request\.getPart\s*\(",
                r"request\.getParts\s*\(",
            ],
            risk_level="high",
            controllability="full",
            description="Request body or file upload",
        ),
        SourceDefinition(
            name="ServletURL",
            category=SourceCategory.HTTP_PARAM,
            language="java",
            function_patterns=[
                r"request\.getRequestURI\s*\(",
                r"request\.getQueryString\s*\(",
                r"request\.getRequestURL\s*\(",
            ],
            risk_level="high",
            controllability="full",
            description="URL components from request",
        ),
    ])

    # =========================================================================
    # Spring MVC Sources (Annotations)
    # =========================================================================
    sources.extend([
        SourceDefinition(
            name="SpringRequestParam",
            category=SourceCategory.HTTP_PARAM,
            language="java",
            annotation_patterns=[
                r"@RequestParam",
                r"@PathVariable",
                r"@MatrixVariable",
            ],
            risk_level="high",
            controllability="full",
            description="Spring MVC request parameter annotation",
            example='public void method(@RequestParam String name)',
        ),
        SourceDefinition(
            name="SpringRequestBody",
            category=SourceCategory.HTTP_PARAM,
            language="java",
            annotation_patterns=[
                r"@RequestBody",
                r"@ModelAttribute",
            ],
            risk_level="high",
            controllability="full",
            description="Spring MVC request body annotation",
        ),
        SourceDefinition(
            name="SpringRequestHeader",
            category=SourceCategory.HTTP_HEADER,
            language="java",
            annotation_patterns=[
                r"@RequestHeader",
            ],
            risk_level="high",
            controllability="full",
            description="Spring MVC request header annotation",
        ),
        SourceDefinition(
            name="SpringCookie",
            category=SourceCategory.COOKIE,
            language="java",
            annotation_patterns=[
                r"@CookieValue",
            ],
            risk_level="high",
            controllability="full",
            description="Spring MVC cookie annotation",
        ),
        SourceDefinition(
            name="SpringSessionAttribute",
            category=SourceCategory.HTTP_PARAM,
            language="java",
            annotation_patterns=[
                r"@SessionAttribute",
            ],
            risk_level="medium",
            controllability="partial",
            description="Spring MVC session attribute",
        ),
    ])

    # =========================================================================
    # JAX-RS Sources (Annotations)
    # =========================================================================
    sources.extend([
        SourceDefinition(
            name="JAXRSParam",
            category=SourceCategory.HTTP_PARAM,
            language="java",
            annotation_patterns=[
                r"@PathParam",
                r"@QueryParam",
                r"@FormParam",
                r"@DefaultValue",
            ],
            risk_level="high",
            controllability="full",
            description="JAX-RS parameter annotation",
        ),
        SourceDefinition(
            name="JAXRSHeader",
            category=SourceCategory.HTTP_HEADER,
            language="java",
            annotation_patterns=[
                r"@HeaderParam",
                r"@CookieParam",
            ],
            risk_level="high",
            controllability="full",
            description="JAX-RS header/cookie annotation",
        ),
        SourceDefinition(
            name="JAXRSBody",
            category=SourceCategory.HTTP_PARAM,
            language="java",
            annotation_patterns=[
                r"@FormDataParam",
            ],
            risk_level="high",
            controllability="full",
            description="JAX-RS form data parameter",
        ),
    ])

    # =========================================================================
    # File/Environment Sources
    # =========================================================================
    sources.extend([
        SourceDefinition(
            name="FileRead",
            category=SourceCategory.FILE_READ,
            language="java",
            function_patterns=[
                r"FileReader\s*\(",
                r"FileInputStream\s*\(",
                r"Files\.readAllBytes\s*\(",
                r"Scanner\s*\(",
            ],
            risk_level="medium",
            controllability="none",
            description="File content input",
            requires_auth=True,
        ),
        SourceDefinition(
            name="Environment",
            category=SourceCategory.ENVIRONMENT,
            language="java",
            function_patterns=[
                r"System\.getenv\s*\(",
                r"System\.getProperty\s*\(",
            ],
            risk_level="low",
            controllability="none",
            description="Environment variable or system property",
        ),
        SourceDefinition(
            name="CommandLine",
            category=SourceCategory.COMMAND_LINE,
            language="java",
            function_patterns=[
                r"System\.in",
                r"Scanner\s*\(\s*System\.in",
            ],
            risk_level="medium",
            controllability="partial",
            description="Command line input",
        ),
    ])

    # =========================================================================
    # Network Sources
    # =========================================================================
    sources.extend([
        SourceDefinition(
            name="SocketInput",
            category=SourceCategory.WEBSOCKET,
            language="java",
            function_patterns=[
                r"Socket.*\.getInputStream\s*\(",
                r"BufferedReader\s*\(",
            ],
            risk_level="high",
            controllability="full",
            description="Network socket input",
        ),
        SourceDefinition(
            name="DatabaseResult",
            category=SourceCategory.DATABASE,
            language="java",
            function_patterns=[
                r"ResultSet.*\.getString\s*\(",
                r"ResultSet.*\.getObject\s*\(",
            ],
            risk_level="medium",
            controllability="partial",
            description="Database query result (second-order injection)",
        ),
    ])

    return sources


__all__ = [
    "get_sink_library",
    "get_source_library",
]
