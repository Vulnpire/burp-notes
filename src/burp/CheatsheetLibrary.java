package burp;

import java.util.Arrays;
import java.util.List;

final class CheatsheetLibrary {
    private static final List<CheatsheetEntry> ENTRIES = Arrays.asList(
        new CheatsheetEntry(
            "Business Logic",
            Arrays.asList(
                "Map critical flows and state transitions.",
                "Try step skipping, order changes, and replay.",
                "Manipulate price/quantity/currency/discount fields.",
                "Check server-side recalculation and idempotency."
            ),
            "Look for multi-step workflows where the client controls totals, status, refunds, or approvals. "
                + "Identify hidden fields, client-side validation, or state transitions that are not rechecked server-side.\n"
                + "- Checkout, refunds, account changes\n"
                + "- Coupons, credits, shipping, inventory\n"
                + "- Approval or review steps",
            "Map every step and capture the exact requests and responses. "
                + "Track how state changes across steps and which parameters are trusted.\n"
                + "- Compare UI state vs server-side response\n"
                + "- Note idempotency tokens and order IDs\n"
                + "- Look for missing server recomputation",
            "Modify parameters (price/qty), skip steps, or replay finalize/refund to exceed limits or bypass checks. "
                + "Try out-of-order transitions and parallel submissions to break invariants."
        ),
        new CheatsheetEntry(
            "SQL Injection",
            Arrays.asList(
                "Test URL/body/JSON/header/cookie parameters.",
                "Use error/boolean/time-based probes.",
                "Confirm with UNION or out-of-band if possible."
            ),
            "Identify inputs that likely hit the database: search, filters, sort, IDs, pagination, and JSON fields. "
                + "Look for SQL error messages, response length changes, or timing anomalies.\n"
                + "- SQL errors or stack traces\n"
                + "- Response size/status variance\n"
                + "- Time-based delays",
            "Enumerate all parameters and verify how input is processed. "
                + "Fingerprint the DB (error strings, functions) and note any WAF behavior.\n"
                + "- Single quote and comment probes\n"
                + "- Boolean true/false comparisons\n"
                + "- Time delays to confirm execution",
            "Use boolean/time-based payloads to confirm, then extract via UNION or OOB if possible. "
                + "Prefer least intrusive confirmation before deeper extraction."
        ),
        new CheatsheetEntry(
            "Cross-Site Scripting (XSS)",
            Arrays.asList(
                "Identify context: HTML, attribute, JS, URL, CSS.",
                "Test reflected, stored, and DOM sinks.",
                "Check CSP and encoding behavior."
            ),
            "Identify reflections and sinks: templated output, DOM updates, or stored content. "
                + "Look for places where user input is rendered without proper encoding.\n"
                + "- innerHTML/document.write/template rendering\n"
                + "- Attribute or JS string contexts\n"
                + "- Stored content like comments or profiles",
            "Map output contexts and check encoding and CSP behavior. "
                + "Test reflected, stored, and DOM-based paths separately.\n"
                + "- Confirm context and quote handling\n"
                + "- Identify CSP restrictions\n"
                + "- Find safe bypasses for each context",
            "Use context-appropriate payloads to execute JS and show impact. "
                + "Demonstrate session compromise, actions, or data exfiltration where allowed."
        ),
        new CheatsheetEntry(
            "Race Condition",
            Arrays.asList(
                "Use parallel requests on non-atomic actions.",
                "Look for double-spend or duplicate submissions.",
                "Check idempotency token handling."
            ),
            "Identify actions that should be atomic or single-use: balances, inventory, coupons, refunds, or approvals. "
                + "Look for missing idempotency keys or locks.\n"
                + "- Counted resources or limits\n"
                + "- Single-use tokens or confirmations\n"
                + "- Multi-step finalize endpoints",
            "Map the state-changing request and confirm behavior on retries. "
                + "Measure how the system handles duplicates and concurrent actions.\n"
                + "- Repeater group / Turbo Intruder\n"
                + "- Compare success/failure responses\n"
                + "- Watch for partial updates",
            "Send concurrent requests (5+ in Repeater group) to exceed limits or trigger duplicates. "
                + "Vary timing and order to expose weak locking."
        ),
        new CheatsheetEntry(
            "Insecure Direct Object Reference (IDOR)",
            Arrays.asList(
                "Swap object IDs in URL/body/JSON.",
                "Test read/write operations across users.",
                "Check predictable identifiers."
            ),
            "Identify object IDs in URLs, JSON, GraphQL, and file names. "
                + "Look for sequential IDs or leaked identifiers in responses.\n"
                + "- /users/123, orderId, fileId\n"
                + "- GraphQL node IDs\n"
                + "- Hidden admin endpoints",
            "Enumerate every operation on the object (read, update, delete). "
                + "Test across users and roles with a clean session.\n"
                + "- Verify authorization per request\n"
                + "- Compare response codes and data\n"
                + "- Check multi-tenant boundaries",
            "Replace IDs with another user's and confirm unauthorized access or modification. "
                + "Escalate from read to write if possible."
        ),
        new CheatsheetEntry(
            "Broken Authentication",
            Arrays.asList(
                "Check reset tokens for expiry and single-use.",
                "Verify session invalidation on logout/reset.",
                "Test for session fixation."
            ),
            "Identify weak auth flows: predictable reset tokens, long-lived sessions, missing MFA, or weak password policy. "
                + "Look for inconsistent session handling.\n"
                + "- Password reset and email links\n"
                + "- Remember-me or refresh tokens\n"
                + "- Login error message differences",
            "Map login, reset, MFA, and session management endpoints. "
                + "Inspect token lifetimes, invalidation rules, and cookie flags.\n"
                + "- Check session rotation on login\n"
                + "- Verify logout invalidates server-side\n"
                + "- Test MFA enforcement per action",
            "Reuse reset tokens, keep old sessions alive after password changes, or bypass MFA where possible. "
                + "Demonstrate account takeover or persistence."
        ),
        new CheatsheetEntry(
            "Password Reset",
            Arrays.asList(
                "Normalize responses to prevent user enumeration.",
                "Verify reset tokens are random, single-use, and short-lived.",
                "Send parallel reset requests to ensure tokens are unique.",
                "Ensure reset links use a trusted host and safe redirects.",
                "Require re-login and invalidate old sessions.",
                "Rate limit reset requests to prevent abuse."
            ),
            "Identify every reset entry point: forgot password forms, email/SMS links, magic links, and recovery screens. "
                + "Check whether responses or timing differ for valid vs invalid accounts.\n"
                + "- Consistent messages and timing\n"
                + "- Redirect/return URL parameters\n"
                + "- Link generation (absolute vs relative URLs)",
            "Map the full flow (request -> token delivery -> reset form). "
                + "Verify tokens are random, long, single-use, and expire; confirm the account is not changed before a valid token is presented.\n"
                + "- Token lifetime and single-use rules\n"
                + "- Rate limiting / CAPTCHA on reset requests\n"
                + "- Do not auto-login; invalidate existing sessions",
            "Attempt enumeration via response differences, reuse of reset tokens, and abuse of reset request limits. "
                + "Test for Host header poisoning in reset links and open redirects in return URLs to demonstrate phishing risk safely."
        ),
        new CheatsheetEntry(
            "Account Takeover (ATO)",
            Arrays.asList(
                "Test credential stuffing and password spraying defenses.",
                "Validate MFA/step-up for risky logins and actions.",
                "Rotate session IDs after login/privilege changes.",
                "Scrutinize recovery and reset flows for abuse."
            ),
            "Identify all authentication entry points: web, mobile, API, SSO, and recovery. "
                + "Focus on endpoints that can change credentials or session state.\n"
                + "- Login and OTP endpoints\n"
                + "- Password reset and account recovery\n"
                + "- Email/phone change flows",
            "Assess defenses against credential stuffing and spraying. "
                + "Verify MFA or step-up triggers on new device, location, or abnormal login patterns.\n"
                + "- Rate limiting and CAPTCHA\n"
                + "- Risk-based MFA/step-up\n"
                + "- Session ID regeneration after auth",
            "Validate takeover paths by testing weak recovery, session fixation, or missing step-up on high-risk actions. "
                + "Demonstrate impact with controlled proofs (no destructive actions)."
        ),
        new CheatsheetEntry(
            "Broken Access Control",
            Arrays.asList(
                "Force browse privileged endpoints.",
                "Test method tampering and hidden flags.",
                "Verify role checks on every request."
            ),
            "Identify sensitive endpoints and role-specific actions hidden from the UI. "
                + "Look for role flags in requests or responses.\n"
                + "- /admin, /manage, /export\n"
                + "- Role or isAdmin fields\n"
                + "- Feature flags",
            "Inventory endpoints per role and compare responses. "
                + "Try different HTTP methods and parameter combinations.\n"
                + "- GET vs POST vs PUT\n"
                + "- Hidden parameters or flags\n"
                + "- Alternate API versions",
            "Access admin-only endpoints or modify role flags as a normal user. "
                + "Show privilege escalation, data exposure, or unauthorized actions."
        ),
        new CheatsheetEntry(
            "Server-Side Request Forgery (SSRF)",
            Arrays.asList(
                "Find URL fetchers (webhooks/importers/PDF).",
                "Test internal IPs and metadata services.",
                "Try redirect or DNS rebinding bypass."
            ),
            "Identify features that fetch URLs: webhooks, importers, image fetch, PDF generation, link previews. "
                + "Confirm which protocols and redirects are allowed.\n"
                + "- URL parameters or JSON fields\n"
                + "- File upload that fetches URLs\n"
                + "- Metadata or preview features",
            "Map allowlist/denylist behavior and test parsing quirks. "
                + "Check if redirects or DNS rebinding are followed.\n"
                + "- Alternate IP encodings\n"
                + "- 127.0.0.1, localhost, metadata IP\n"
                + "- Redirect chain behavior",
            "Request internal endpoints or metadata (169.254.169.254). "
                + "Use redirects or DNS rebinding to bypass filters and demonstrate impact."
        ),
        new CheatsheetEntry(
            "Cross-Site Request Forgery (CSRF)",
            Arrays.asList(
                "Check state-changing endpoints for tokens.",
                "Verify SameSite and Origin/Referer checks.",
                "Look for GET actions that change state."
            ),
            "Identify state-changing endpoints that rely on cookies without CSRF defenses. "
                + "Look for missing tokens or weak origin validation.\n"
                + "- Account settings\n"
                + "- Password/email changes\n"
                + "- Payment or transfer actions",
            "Inspect requests for CSRF tokens and server validation. "
                + "Check SameSite cookie behavior and Origin/Referer enforcement.\n"
                + "- Token presence and rotation\n"
                + "- Acceptable origins\n"
                + "- GET vs POST handling",
            "Craft auto-submitting form or fetch to trigger state changes without a valid token. "
                + "Demonstrate action performed under victim session."
        ),
        new CheatsheetEntry(
            "Command Injection",
            Arrays.asList(
                "Test parameters in backup/export/diagnostics.",
                "Try separators: ; & | && || $( ).",
                "Check output or timing changes."
            ),
            "Identify features that invoke system utilities: ping, traceroute, conversion, backups, file processing. "
                + "Look for unsanitized parameters passed to shell.\n"
                + "- Diagnostics tools\n"
                + "- Admin utilities\n"
                + "- File or image processing",
            "Test for command parsing behavior and observe errors/timing. "
                + "Use safe probes to validate execution.\n"
                + "- Sleep or timeout delays\n"
                + "- Output redirection\n"
                + "- Quoting behavior",
            "Inject shell metacharacters to execute commands. "
                + "Show controlled output or time-based proof without destructive actions."
        ),
        new CheatsheetEntry(
            "Path Traversal",
            Arrays.asList(
                "Test file path parameters for ../ or ..\\",
                "Try URL and double encoding.",
                "Check read and write paths."
            ),
            "Identify file path parameters in download, export, template, or image endpoints. "
                + "Look for file names or directory inputs.\n"
                + "- filename=, path=, template=\n"
                + "- File preview endpoints\n"
                + "- Log or backup downloads",
            "Test traversal patterns and encoding variations. "
                + "Verify normalization behavior and OS-specific paths.\n"
                + "- ../, ..\\\n"
                + "- URL encoding and double encoding\n"
                + "- Mixed path separators",
            "Traverse to read sensitive files or overwrite writable paths. "
                + "Demonstrate read access to config or secrets where allowed."
        ),
        new CheatsheetEntry(
            "File Upload",
            Arrays.asList(
                "Try double extensions and polyglots.",
                "Check content-type vs magic bytes.",
                "Verify storage location and access controls."
            ),
            "Identify upload endpoints and how files are stored and served. "
                + "Look for weak validation or public access.\n"
                + "- Profile images, attachments, imports\n"
                + "- Content-type validation\n"
                + "- Public CDN or web root storage",
            "Enumerate allowed extensions, size limits, and scanning behavior. "
                + "Test how the app determines file type.\n"
                + "- Magic bytes vs filename\n"
                + "- MIME type checks\n"
                + "- Rename and overwrite behavior",
            "Upload a scriptable file, polyglot, or SVG to execute or read data. "
                + "Demonstrate impact via stored file access."
        ),
        new CheatsheetEntry(
            "XXE (XML External Entities)",
            Arrays.asList(
                "Check XML parsers (SOAP/SAML/SVG).",
                "Test external entity resolution.",
                "Confirm secure parser settings."
            ),
            "Identify any XML input handling: SOAP, SAML, XML uploads, or SVG parsing. "
                + "Check for DTD support or parser errors.\n"
                + "- XML endpoints\n"
                + "- File upload with XML\n"
                + "- Error messages mentioning DTD",
            "Test if external entities are resolved and how errors are returned. "
                + "Try inline DTD and observe responses.\n"
                + "- Simple entity expansion\n"
                + "- External system identifiers\n"
                + "- Error-based leaks",
            "Use external entities to read local files or SSRF internal services. "
                + "Avoid destructive payloads; use safe proof."
        ),
        new CheatsheetEntry(
            "SSTI (Server-Side Template Injection)",
            Arrays.asList(
                "Probe with {{7*7}} or ${7*7}.",
                "Identify template contexts in emails/pages.",
                "Check sandbox escape."
            ),
            "Identify where user input is rendered in templates: emails, PDFs, reports, or UI fragments. "
                + "Look for template errors or reflected expressions.\n"
                + "- Error messages with template syntax\n"
                + "- Rendered previews\n"
                + "- Server-side rendering",
            "Probe with simple math expressions and identify template engine. "
                + "Map context and escaping.\n"
                + "- {{7*7}}, ${7*7}, <% %>\n"
                + "- Error messages reveal engine\n"
                + "- Find available objects",
            "Use engine-specific payloads to read data or execute code. "
                + "Demonstrate safe impact like reading config or env variables."
        ),
        new CheatsheetEntry(
            "Open Redirect",
            Arrays.asList(
                "Test next/return/url parameters.",
                "Check allowlists and URL normalization.",
                "Try encoding tricks."
            ),
            "Identify redirect parameters in login/logout, SSO, or account flows. "
                + "Look for parameters that control target URLs.\n"
                + "- next=, return=, redirect=\n"
                + "- OAuth redirect_uri\n"
                + "- post-auth redirects",
            "Test normalization and allowlist behavior. "
                + "Try scheme-relative URLs and encoded payloads.\n"
                + "- //evil.com\n"
                + "- URL-encoded and double-encoded\n"
                + "- Open redirect chaining",
            "Redirect users to a malicious domain for phishing or token theft. "
                + "Chain with OAuth if applicable."
        ),
        new CheatsheetEntry(
            "CORS Misconfiguration",
            Arrays.asList(
                "Check ACAO with credentials.",
                "Look for reflected Origin.",
                "Verify preflight handling."
            ),
            "Identify sensitive endpoints that return data to authenticated users. "
                + "Look for permissive CORS headers.\n"
                + "- ACAO reflects Origin\n"
                + "- ACAO=* with credentials\n"
                + "- Missing Vary: Origin",
            "Test with custom Origin headers and credentialed requests. "
                + "Validate preflight and simple request behavior.\n"
                + "- Origin: https://evil.example\n"
                + "- Access-Control-Allow-Credentials\n"
                + "- Preflight caching",
            "Use a malicious origin to read sensitive data via fetch with credentials. "
                + "Demonstrate data exposure with a PoC page."
        ),
        new CheatsheetEntry(
            "JWT / Token Issues",
            Arrays.asList(
                "Check alg=none or weak secrets.",
                "Validate exp/aud/iss claims.",
                "Verify signature enforcement."
            ),
            "Identify JWT usage in auth or API requests. "
                + "Check for weak signing, long expiry, or missing validation.\n"
                + "- alg=none acceptance\n"
                + "- Weak HMAC secrets\n"
                + "- Missing exp or audience validation",
            "Decode tokens and map claims used for authorization. "
                + "Test server behavior with modified claims.\n"
                + "- Change role/uid claims\n"
                + "- Verify signature checks\n"
                + "- Check key ID handling",
            "Forge tokens with weak secrets or signature bypass. "
                + "Demonstrate unauthorized access or privilege escalation."
        ),
        new CheatsheetEntry(
            "OAuth / SSO",
            Arrays.asList(
                "Validate redirect_uri allowlist.",
                "Ensure state parameter is required.",
                "Test open redirect chaining."
            ),
            "Identify OAuth/OIDC flows and callback endpoints. "
                + "Look for missing state/PKCE or weak redirect validation.\n"
                + "- /oauth/authorize endpoints\n"
                + "- redirect_uri parameters\n"
                + "- Token exchange endpoints",
            "Map the full flow and verify CSRF protections and redirect validation. "
                + "Test multiple client IDs and scopes.\n"
                + "- Missing or predictable state\n"
                + "- Improper redirect allowlist\n"
                + "- Mix-up or token leakage",
            "Abuse redirect_uri or missing state to hijack sessions or tokens. "
                + "Chain with open redirects if needed."
        ),
        new CheatsheetEntry(
            "Clickjacking",
            Arrays.asList(
                "Check X-Frame-Options / frame-ancestors.",
                "Test sensitive pages in iframe."
            ),
            "Identify sensitive pages without frame protection. "
                + "Check headers and CSP frame-ancestors.\n"
                + "- Account or payment pages\n"
                + "- Admin actions\n"
                + "- Dangerous buttons",
            "Attempt to frame sensitive endpoints and observe behavior. "
                + "Verify if headers are missing or misconfigured.\n"
                + "- X-Frame-Options\n"
                + "- CSP frame-ancestors\n"
                + "- Legacy browser behavior",
            "Create an iframe overlay PoC to trick users into actions. "
                + "Demonstrate clickjacking impact safely."
        ),
        new CheatsheetEntry(
            "Rate Limiting / Brute Force",
            Arrays.asList(
                "Attempt slow credential stuffing.",
                "Check lockout and throttling.",
                "Look for user enumeration."
            ),
            "Identify endpoints that should be rate-limited: login, OTP, password reset, API keys. "
                + "Look for differences that allow enumeration.\n"
                + "- Login/OTP endpoints\n"
                + "- Forgot password responses\n"
                + "- Token generation endpoints",
            "Measure throttling and lockout behavior per IP and per account. "
                + "Test how counters reset and whether CAPTCHA is enforced.\n"
                + "- Slow ramp vs burst\n"
                + "- Account lockout windows\n"
                + "- IP rotation behavior",
            "Automate attempts without lockout to gain access. "
                + "Demonstrate feasible attack rate and account takeover risk."
        ),
        new CheatsheetEntry(
            "Host Header Injection",
            Arrays.asList(
                "Test Host and X-Forwarded-Host usage.",
                "Check reset links and cache poisoning.",
                "Look for URL generation issues."
            ),
            "Identify places where the app builds absolute URLs: password reset, email links, redirects. "
                + "Check if Host headers are trusted.\n"
                + "- Password reset links\n"
                + "- Email verification\n"
                + "- Absolute redirects",
            "Test Host, X-Forwarded-Host, and X-Original-Host behavior. "
                + "Observe how links are generated and cached.\n"
                + "- Cache poisoning behavior\n"
                + "- Multi-tenant routing\n"
                + "- CDN/proxy influence",
            "Inject Host to generate malicious reset links or poison cache. "
                + "Demonstrate a safe proof of URL manipulation."
        ),
        new CheatsheetEntry(
            "Deserialization",
            Arrays.asList(
                "Identify serialized blobs (Java/PHP).",
                "Check gadget chains and type controls.",
                "Verify integrity protections."
            ),
            "Identify serialized payloads: base64 blobs, magic bytes, or framework markers. "
                + "Look for untrusted input reaching deserializers.\n"
                + "- Java serialization headers\n"
                + "- PHP serialized strings\n"
                + "- .NET type hints",
            "Determine the language/framework and available gadget chains. "
                + "Check for signing or integrity verification.\n"
                + "- Check HMAC or signatures\n"
                + "- Error messages reveal classes\n"
                + "- Payload size limits",
            "Use known gadget chains or type confusion to achieve code execution or data access. "
                + "Prefer non-destructive proofs and document impact clearly."
        ),
        new CheatsheetEntry(
            "Prototype Pollution",
            Arrays.asList(
                "Find deep-merge of user input (JSON/query/body).",
                "Test __proto__ and constructor.prototype payloads.",
                "Confirm impact via inherited property changes."
            ),
            "Identify endpoints that accept object-like input and merge it into server-side options. "
                + "Look for JSON bodies, query params, or URL-encoded objects that are deep-merged.\n"
                + "- JSON payloads and nested parameters\n"
                + "- qs-style parsing and nested keys\n"
                + "- Deep-merge utility usage in JS",
            "Send controlled payloads that set properties on Object.prototype and verify the effect.\n"
                + "- __proto__ or constructor.prototype keys\n"
                + "- Use harmless flags like polluted=yes\n"
                + "- Check behavior changes across requests",
            "Abuse polluted properties to bypass auth flags or alter app logic. "
                + "Look for gadgets that read options from inherited properties and demonstrate safe impact."
        ),
        new CheatsheetEntry(
            "GraphQL",
            Arrays.asList(
                "Confirm endpoint with __typename.",
                "Check introspection and schema exposure.",
                "Enumerate queries/mutations for sensitive fields.",
                "Test IDOR and authorization per resolver.",
                "Check batching for rate-limit bypass or data harvesting.",
                "Test CSRF via GET and weak SameSite settings.",
                "Review error messages for leaks."
            ),
            "Identify GraphQL endpoints and confirm they're active. "
                + "Look for /graphql, /api/graphql, or schema references in JS.\\n"
                + "- Test __typename for a quick live check\\n"
                + "- Inspect network traffic for GraphQL requests\\n"
                + "- Check if GET is allowed for queries",
            "Use introspection (if enabled) to enumerate schema, queries, and mutations. "
                + "Map sensitive fields and role-specific operations.\\n"
                + "- __schema and __type queries\\n"
                + "- Identify auth-required resolvers\\n"
                + "- Look for password, token, or admin fields",
            "Exploit missing authorization (IDOR) or weak mutation checks to access or modify data. "
                + "Use batching to bypass rate limits or harvest data without triggering per-request controls. "
                + "Demonstrate access to unauthorized objects or actions without DoS."
        ),
        new CheatsheetEntry(
            "Cryptographic Failures",
            Arrays.asList(
                "Check TLS settings and HSTS.",
                "Verify secure cookie flags.",
                "Check encryption at rest and in transit.",
                "Avoid weak hashes or hardcoded secrets."
            ),
            "Identify sensitive data flows and storage locations: auth tokens, PII, payment data. "
                + "Look for weak ciphers, missing TLS, or exposed secrets.\n"
                + "- Plaintext secrets\n"
                + "- Weak hashing (MD5/SHA1)\n"
                + "- Missing HSTS",
            "Review TLS configuration and data handling end-to-end. "
                + "Inspect cookies, token lifetimes, and key management.\n"
                + "- Cookie flags and scope\n"
                + "- Key rotation and storage\n"
                + "- Encryption boundaries",
            "Demonstrate exposure of sensitive data or downgrade/weak crypto issues. "
                + "Avoid destructive actions; focus on concrete risk."
        ),
        new CheatsheetEntry(
            "Insecure Design",
            Arrays.asList(
                "Identify missing abuse-case coverage.",
                "Validate trust boundaries and roles.",
                "Check for missing compensating controls."
            ),
            "Identify design-level gaps: missing rate limits, lack of validation, or unsafe trust assumptions. "
                + "Look for workflows without server-side enforcement.\n"
                + "- Critical flows without checks\n"
                + "- Trusting client-side state\n"
                + "- Missing abuse-case handling",
            "Map trust boundaries and data flows across roles and services. "
                + "Consider how a malicious actor could bypass intended design.\n"
                + "- Role boundary validation\n"
                + "- Privilege transitions\n"
                + "- Multi-tenant access",
            "Abuse design gaps to perform actions outside intended limits. "
                + "Document how to reproduce and the business impact."
        ),
        new CheatsheetEntry(
            "Security Misconfiguration",
            Arrays.asList(
                "Check default credentials or demo endpoints.",
                "Look for verbose errors or debug endpoints.",
                "Review CORS and directory listing."
            ),
            "Identify misconfigurations in services, headers, and debug tooling. "
                + "Look for default creds, exposed admin panels, or verbose errors.\n"
                + "- /debug or /actuator\n"
                + "- Directory listing\n"
                + "- Exposed admin consoles",
            "Enumerate misconfigured endpoints and environment differences (dev/stage/prod). "
                + "Check headers, error pages, and service banners.\n"
                + "- Server version disclosure\n"
                + "- Debug modes enabled\n"
                + "- Insecure CORS",
            "Exploit misconfigurations to access data, admin panels, or sensitive functionality. "
                + "Provide minimal, safe proof."
        ),
        new CheatsheetEntry(
            "Vulnerable and Outdated Components",
            Arrays.asList(
                "Identify library/framework versions.",
                "Check for known CVEs.",
                "Flag EOL dependencies."
            ),
            "Identify component versions from headers, static assets, package metadata, or error pages. "
                + "Look for known vulnerable versions.\n"
                + "- Server and framework headers\n"
                + "- JS/CSS file versions\n"
                + "- Package or SBOM data",
            "Validate versions and map to known vulnerabilities. "
                + "Confirm exposure and reachable attack paths.\n"
                + "- CVE applicability\n"
                + "- Attack preconditions\n"
                + "- Exploit availability",
            "Demonstrate impact using safe PoCs where allowed. "
                + "Document upgrade or mitigation guidance."
        ),
        new CheatsheetEntry(
            "Identification and Authentication Failures",
            Arrays.asList(
                "Check weak password policy.",
                "Verify MFA is required where needed.",
                "Ensure brute-force protections exist."
            ),
            "Identify weak identity controls: weak passwords, missing MFA, or unreliable verification. "
                + "Look for user enumeration or weak recovery.\n"
                + "- Predictable usernames\n"
                + "- Password reset flows\n"
                + "- MFA optional or bypassable",
            "Map authentication endpoints and test verification rules. "
                + "Check for rate limits and lockout behavior.\n"
                + "- Login, OTP, magic links\n"
                + "- Account recovery\n"
                + "- Session lifecycle",
            "Demonstrate account takeover or unauthorized access via weak identification flows. "
                + "Use controlled accounts where possible."
        ),
        new CheatsheetEntry(
            "Software and Data Integrity Failures",
            Arrays.asList(
                "Check for unsigned updates.",
                "Verify dependency integrity.",
                "Review deserialization protections."
            ),
            "Identify places where code or data integrity is assumed: update mechanisms, plugins, CI/CD artifacts. "
                + "Look for unsigned or tamperable artifacts.\n"
                + "- Update downloads\n"
                + "- CI/CD artifacts\n"
                + "- Build pipelines",
            "Assess integrity checks on updates and dependencies. "
                + "Verify signature validation and artifact provenance.\n"
                + "- Signature validation\n"
                + "- Dependency pinning\n"
                + "- Trusted sources",
            "Demonstrate how a tampered artifact or dependency could be accepted. "
                + "Keep proof non-destructive and document impact."
        ),
        new CheatsheetEntry(
            "Security Logging and Monitoring Failures",
            Arrays.asList(
                "Ensure auth and privileged actions are logged.",
                "Check alerts on suspicious activity.",
                "Verify log retention and integrity."
            ),
            "Identify missing or incomplete logs for critical actions. "
                + "Look for absent alerts or tamperable logs.\n"
                + "- Login failures\n"
                + "- Privileged changes\n"
                + "- Data export events",
            "Attempt suspicious actions and verify log generation and alerting. "
                + "Review log retention and access controls.\n"
                + "- Failed login bursts\n"
                + "- Admin changes\n"
                + "- Sensitive data access",
            "Demonstrate that critical events are not logged or alerted, increasing dwell time. "
                + "Document detection gaps and recommended fixes."
        ),
        new CheatsheetEntry(
            "Web Cache Poisoning",
            Arrays.asList(
                "Identify cacheable endpoints and shared caches.",
                "Test cache key variance on headers and query params.",
                "Try extension and delimiter tricks on dynamic pages.",
                "Confirm poisoned cache is served to unauthenticated users."
            ),
            "Identify endpoints served via cache (CDN, reverse proxy) and check headers like Cache-Control, Age, X-Cache. "
                + "Look for dynamic pages that are mistakenly cacheable.\n"
                + "- Authenticated pages returning cache headers\n"
                + "- Public cacheable assets with dynamic content\n"
                + "- Vary or Cache-Control inconsistencies",
            "Test cache key manipulation and parsing quirks to force caching of sensitive content. "
                + "Compare responses across authenticated and unauthenticated sessions.\n"
                + "- Append .js/.css to dynamic paths\n"
                + "- Use delimiters like ; or ? to bypass routing\n"
                + "- Try header variations (Host, X-Forwarded-Host)",
            "Poison the cache with sensitive content, then fetch it without auth to demonstrate exposure. "
                + "Show a clean reproduction path and emphasize user impact."
        ),
        new CheatsheetEntry(
            "WSS (WebSocket Secure)",
            Arrays.asList(
                "Enumerate WS endpoints and message types.",
                "Verify auth and role checks per message.",
                "Test replay and token reuse after logout.",
                "Check for IDOR in payload fields.",
                "Validate rate limits and payload size handling."
            ),
            "Identify WebSocket connections, upgrade requests, and message schemas. "
                + "Note role-specific actions and any client-side-only controls.\n"
                + "- Message types like ASSIGN ROLE, KICK, MUTE\n"
                + "- connection_id/user_id fields\n"
                + "- Broadcast vs direct messages",
            "Capture and replay traffic while changing roles, IDs, and message types. "
                + "Test if server enforces permissions and input validation.\n"
                + "- Replay captured requests after removal\n"
                + "- Modify role or target IDs\n"
                + "- Send oversized payloads",
            "Trigger unauthorized actions (kick, mute, role change), leaks (room info), or DoS via large payloads. "
                + "Demonstrate impact with minimal disruption."
        ),
        new CheatsheetEntry(
            "2FA / MFA",
            Arrays.asList(
                "Attempt direct access to protected endpoints.",
                "Test OTP brute-force and rate limits.",
                "Check OTP reuse, expiry, and default codes.",
                "Verify 2FA disable and backup code security.",
                "Test OAuth/SSO flows for 2FA enforcement."
            ),
            "Identify the full 2FA flow: enrollment, verification, recovery, and disable paths. "
                + "Look for inconsistent enforcement across endpoints.\n"
                + "- /2fa/verify and /2fa/disable\n"
                + "- Password reset and API token flows\n"
                + "- OAuth/SSO login paths",
            "Test OTP validation rules, rate limits, and session handling. "
                + "Check whether 2FA gates all sensitive actions.\n"
                + "- OTP reuse and expiry checks\n"
                + "- Cross-account OTP usage\n"
                + "- Session persistence after 2FA",
            "Bypass 2FA via direct endpoint access, OAuth flow gaps, or OTP weaknesses. "
                + "Document the exact bypass path and required conditions."
        ),
        new CheatsheetEntry(
            "AI Pentest (LLM)",
            Arrays.asList(
                "Inventory AI features, data sources, and tools.",
                "Check for sensitive data exposure or prompt leakage.",
                "Test tool/agent authorization boundaries.",
                "Assess guardrails, rate limits, and abuse controls."
            ),
            "Identify how the AI system is integrated: chat UI, RAG, tools, plugins, and background agents. "
                + "Map data sources, permissions, and where outputs are used.\n"
                + "- RAG documents and embeddings\n"
                + "- Tool calls (HTTP, file, DB)\n"
                + "- System/developer prompts\n"
                + "- Training data or fine-tune sources",
            "Probe model boundaries and data access paths while staying in scope. "
                + "Test for indirect prompt injection via retrieved content, data poisoning, and weak output validation.\n"
                + "- Inject instructions in documents\n"
                + "- Check for tool call misuse\n"
                + "- Validate output used in security decisions\n"
                + "- Assess model extraction/membership inference",
            "Demonstrate data exposure, tool abuse, or unsafe actions caused by model outputs. "
                + "Keep payloads safe and show minimal proof with clear impact."
        )
    );

    private CheatsheetLibrary() {
    }

    static List<CheatsheetEntry> getEntries() {
        return ENTRIES;
    }

    static CheatsheetEntry getEntryByTitle(String title) {
        if (title == null || title.trim().isEmpty()) {
            return null;
        }
        String needle = title.trim().toLowerCase();
        for (CheatsheetEntry entry : ENTRIES) {
            if (entry.getTitle().toLowerCase().equals(needle)) {
                return entry;
            }
        }
        return null;
    }
}
