package burp;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;

final class TagLibrary {
    private static final Map<String, TagDefinition> TAGS = new LinkedHashMap<>();
    private static final Map<String, TagDefinition> TAGS_LOWER = new HashMap<>();
    private static final Object LOCK = new Object();
    private static boolean loaded;

    static boolean isLoaded() {
        return loaded;
    }

    private static void ensureLoaded() {
        if (loaded) {
            return;
        }
        synchronized (LOCK) {
            if (loaded) {
                return;
            }
            loadTags();
            loaded = true;
        }
    }

    private static void loadTags() {
        add(new TagDefinition(
            "Business Logic",
            TagCategory.VULNERABILITY,
            Arrays.asList(
                "Map critical flows, state transitions, and invariants (price, balance, inventory).",
                "Attempt step skipping or out-of-order completion; verify server-enforced sequencing.",
                "Tamper with client-controlled values (totals, discounts, shipping, currency, quantity).",
                "Replay or re-submit finalize/refund/coupon actions; verify idempotency.",
                "Check object state manipulation (hidden flags, role fields, internal statuses).",
                "Probe rate limits/quotas on costly actions (exports, emails, SMS, credits)."
            ),
            Arrays.asList(
                "Modify totals after client-side calculation and re-submit.",
                "Replay checkout/settlement requests to duplicate credits or orders.",
                "Race refund + cancel to trigger double credits.",
                "Apply coupons in the wrong sequence or after step changes."
            ),
            true
        ));

        add(new TagDefinition(
            "SQL Injection",
            TagCategory.VULNERABILITY,
            Arrays.asList(
                "Test URL/body/JSON/header/cookie parameters.",
                "Error-based: single quote and observe SQL errors.",
                "Boolean-based: compare true vs false conditions.",
                "Time-based: introduce delays and compare timings.",
                "Union-based: enumerate column count and data extraction.",
                "Check response length/status/timing for blind clues.",
                "Try stacked queries if the DB supports them."
            ),
            Arrays.asList(
                "' OR '1'='1",
                "' AND '1'='2",
                "SLEEP(5) / WAITFOR DELAY '0:0:5'",
                "UNION SELECT NULL,... to find column count"
            ),
            true
        ));

        add(new TagDefinition(
            "Cross-Site Scripting (XSS)",
            TagCategory.VULNERABILITY,
            Arrays.asList(
                "Identify context (HTML, attribute, JS string, URL, CSS).",
                "Test reflected, stored, and DOM sinks.",
                "Audit postMessage handlers for origin checks and unsafe sinks.",
                "Test DOM XSS via JSON.parse or message data (untrusted objects).",
                "Check javascript: URLs and URL fragment-based injection.",
                "Check output encoding and CSP behavior.",
                "Try context-specific payloads (event handlers, SVG, JS).",
                "Test attribute breaking and quote handling.",
                "Verify HttpOnly/secure cookies where relevant."
            ),
            Arrays.asList(
                "<svg onload=alert(1)>",
                "\" autofocus onfocus=alert(1) x=\"",
                "Test innerHTML/document.write sinks"
            ),
            true
        ));

        add(new TagDefinition(
            "Race Condition",
            TagCategory.VULNERABILITY,
            Arrays.asList(
                "Run parallel request groups against single-use or atomic actions; compare success vs limit enforcement.",
                "Target multi-endpoint sequences (add-to-cart + checkout, coupon apply + checkout) in parallel.",
                "Race verification flows (email/phone change) to mis-bind tokens or confirmations.",
                "Check for non-atomic actions (balance, inventory, coupon) and partial updates.",
                "Look for duplicate submissions and double-spend behavior.",
                "Verify idempotency keys/locks are enforced on repeats.",
                "Bypass per-session locking by using multiple sessions in parallel.",
                "Test time-based token collisions in reset/verification flows."
            ),
            Arrays.asList(
                "Use Turbo Intruder / parallel requests.",
                "Vary timing and order of requests."
            ),
            true
        ));

        add(new TagDefinition(
            "Insecure Direct Object Reference (IDOR)",
            TagCategory.VULNERABILITY,
            Arrays.asList(
                "Swap object IDs to another user/tenant.",
                "Test both read and write operations.",
                "Check predictable IDs or short UUIDs.",
                "Verify server-side authorization checks."
            ),
            Arrays.asList(
                "Change /users/123 to /users/124.",
                "Modify JSON body IDs."
            ),
            true
        ));

        add(new TagDefinition(
            "Broken Authentication",
            TagCategory.VULNERABILITY,
            Arrays.asList(
                "Reset tokens expire and are single-use.",
                "Sessions invalidated on logout/reset/password change.",
                "Session ID changes on login (fixation check).",
                "MFA enforced on sensitive actions.",
                "Rate limiting and lockout defenses.",
                "Inspect remember-me/stay-logged-in cookies for predictability or weak hashing."
            ),
            Arrays.asList(
                "Try reusing password reset tokens.",
                "Check session persistence after password change."
            ),
            true
        ));

        add(new TagDefinition(
            "Password Reset",
            TagCategory.VULNERABILITY,
            Arrays.asList(
                "Check reset token randomness, length, and expiration.",
                "Send parallel reset requests; ensure tokens are unique and old ones invalidated.",
                "Issue reset requests from different sessions to spot timestamp-based token collisions.",
                "Verify tokens are single-use and invalidated after reset.",
                "Check token binding to account (swap user/email parameter).",
                "Test for user enumeration in reset requests.",
                "Check reset flow enforces rate limits and CAPTCHA.",
                "Attempt reuse of old reset links after password change.",
                "Test reset link host/header poisoning and open redirects.",
                "Verify reset does not log user in without reauth.",
                "Ensure reset tokens are not leaked via Referer/logs.",
                "Test for CSRF on reset completion endpoints."
            ),
            Arrays.asList(
                "Use the same reset token twice",
                "Check host header reset poisoning"
            ),
            true
        ));

        add(new TagDefinition(
            "Account Takeover (ATO)",
            TagCategory.VULNERABILITY,
            Arrays.asList(
                "Test credential stuffing and password spraying defenses.",
                "Check MFA/step-up enforcement on risky actions.",
                "Verify session fixation and session rotation on login.",
                "Look for session hijacking (token reuse, missing Secure/HttpOnly).",
                "Check account recovery and password reset weaknesses.",
                "Test OAuth/SSO flows for bypasses.",
                "Verify device/IP anomaly detection and alerts.",
                "Check for email/phone change without reauth."
            ),
            Arrays.asList(
                "Use known breached creds on login",
                "Test new device login without MFA"
            ),
            true
        ));

        add(new TagDefinition(
            "Broken Access Control",
            TagCategory.VULNERABILITY,
            Arrays.asList(
                "Force browse privileged endpoints.",
                "Verify role checks on every request.",
                "Test method tampering (GET/POST).",
                "Try hidden admin flags.",
                "Test IDOR + role changes in the same flow."
            ),
            Arrays.asList(
                "Access /admin as normal user.",
                "Switch HTTP method and compare result."
            ),
            true
        ));

        add(new TagDefinition(
            "Cryptographic Failures",
            TagCategory.VULNERABILITY,
            Arrays.asList(
                "Check TLS settings and HSTS.",
                "Verify secure cookie flags.",
                "Check encryption at rest and in transit.",
                "Avoid weak hashes or hardcoded secrets."
            ),
            Arrays.asList(
                "Look for plaintext secrets in responses.",
                "Check for MD5/SHA1 usage."
            ),
            false
        ));

        add(new TagDefinition(
            "Insecure Design",
            TagCategory.VULNERABILITY,
            Arrays.asList(
                "Identify missing abuse-case coverage.",
                "Validate trust boundaries and roles.",
                "Check for missing compensating controls."
            ),
            Arrays.asList(
                "Look for feature-level abuse scenarios.",
                "Review critical flows without server checks."
            ),
            false
        ));

        add(new TagDefinition(
            "Security Misconfiguration",
            TagCategory.VULNERABILITY,
            Arrays.asList(
                "Check default credentials or demo endpoints.",
                "Look for verbose errors or debug endpoints.",
                "Review CORS and directory listing."
            ),
            Arrays.asList(
                "Try /debug or /actuator endpoints.",
                "Check for exposed admin consoles."
            ),
            false
        ));

        add(new TagDefinition(
            "Vulnerable and Outdated Components",
            TagCategory.VULNERABILITY,
            Arrays.asList(
                "Identify library/framework versions.",
                "Check for known CVEs.",
                "Flag EOL dependencies."
            ),
            Arrays.asList(
                "Check headers and static assets for versions.",
                "Review SBOM if available."
            ),
            false
        ));

        add(new TagDefinition(
            "Identification and Authentication Failures",
            TagCategory.VULNERABILITY,
            Arrays.asList(
                "Check weak password policy.",
                "Verify MFA is required where needed.",
                "Ensure brute-force protections exist.",
                "Look for username enumeration via subtle response or timing differences."
            ),
            Arrays.asList(
                "Try credential stuffing with slow ramp.",
                "Check login response differences."
            ),
            false
        ));

        add(new TagDefinition(
            "Software and Data Integrity Failures",
            TagCategory.VULNERABILITY,
            Arrays.asList(
                "Check for unsigned updates.",
                "Verify dependency integrity.",
                "Review deserialization protections."
            ),
            Arrays.asList(
                "Check CI/CD artifact signing.",
                "Inspect update endpoints."
            ),
            false
        ));

        add(new TagDefinition(
            "Security Logging and Monitoring Failures",
            TagCategory.VULNERABILITY,
            Arrays.asList(
                "Ensure auth and privileged actions are logged.",
                "Check alerts on suspicious activity.",
                "Verify log retention and integrity."
            ),
            Arrays.asList(
                "Trigger login failures and verify logs.",
                "Check admin actions for audit trails."
            ),
            false
        ));

        add(new TagDefinition(
            "Server-Side Request Forgery (SSRF)",
            TagCategory.VULNERABILITY,
            Arrays.asList(
                "Identify URL fetchers: webhooks, PDF, importers.",
                "Test internal IPs and metadata services.",
                "Try alternative IP formats (hex, decimal, octal).",
                "Bypass filters with redirects or DNS rebinding.",
                "Test HTTP and non-HTTP schemes if supported.",
                "Probe routing-based SSRF via Host/X-Forwarded-Host and absolute URL requests.",
                "Test URL parser confusion (userinfo @, fragments, mixed slashes).",
                "Check OAuth/OpenID dynamic registration fields (logo_uri, jwks_uri) for SSRF."
            ),
            Arrays.asList(
                "http://169.254.169.254/latest/meta-data/",
                "http://127.0.0.1:8080/"
            ),
            true
        ));

        add(new TagDefinition(
            "Cross-Site Request Forgery (CSRF)",
            TagCategory.VULNERABILITY,
            Arrays.asList(
                "Cover state-changing endpoints across form, JSON, and GraphQL.",
                "Ensure tokens are tied to the active session/user (no cross-account reuse).",
                "Test double-submit patterns: token duplicated in cookie or non-session cookie.",
                "Reject requests when token is missing, blank, or malformed.",
                "Verify token checks are not bypassed via method override or content-type changes.",
                "Probe SameSite bypasses via top-level redirects and sibling subdomains.",
                "Test Origin/Referer validation for missing headers and weak allowlists.",
                "Check GET endpoints that change state."
            ),
            Arrays.asList(
                "Attempt request without CSRF token.",
                "Test with different Origin header."
            ),
            true
        ));

        add(new TagDefinition(
            "Command Injection",
            TagCategory.VULNERABILITY,
            Arrays.asList(
                "Identify shell-outs in backup/export/diagnostics.",
                "Test command separators and chaining operators.",
                "Check for unsanitized user input.",
                "Look for blind command injection via timing."
            ),
            Arrays.asList(
                ";id",
                "&& whoami",
                "| uname -a",
                "sleep 5"
            ),
            true
        ));

        add(new TagDefinition(
            "Path Traversal",
            TagCategory.VULNERABILITY,
            Arrays.asList(
                "Test file path parameters for traversal.",
                "Try URL/double encoding.",
                "Check both read and write paths.",
                "Try mixed separators and absolute paths."
            ),
            Arrays.asList(
                "../../etc/passwd",
                "..\\..\\windows\\win.ini",
                "%2e%2e%2f",
                "..%2f..%2f"
            ),
            true
        ));

        add(new TagDefinition(
            "XXE (XML External Entities)",
            TagCategory.VULNERABILITY,
            Arrays.asList(
                "Locate XML parsers (SOAP/SAML/SVG/Docx).",
                "Test inline DTD with external entity.",
                "Test parameter entities and external DTDs for OOB exfil.",
                "Try XInclude payloads in XML or SVG.",
                "Check file uploads (SVG/Docx) for XXE vectors.",
                "Confirm external entity resolution disabled."
            ),
            Arrays.asList(
                "<!DOCTYPE x [ <!ENTITY xxe SYSTEM \"file:///etc/passwd\"> ]>"
            ),
            true
        ));

        add(new TagDefinition(
            "SSTI (Server-Side Template Injection)",
            TagCategory.VULNERABILITY,
            Arrays.asList(
                "Probe with simple arithmetic payloads.",
                "Fingerprint the template engine and rendering context.",
                "Identify template contexts in emails/pages/reports.",
                "Test object traversal for config/env disclosure.",
                "Check for sandbox escape primitives."
            ),
            Arrays.asList(
                "{{7*7}}", "${7*7}", "<%= 7*7 %>"
            ),
            true
        ));

        add(new TagDefinition(
            "Open Redirect",
            TagCategory.VULNERABILITY,
            Arrays.asList(
                "Test next/return/url parameters.",
                "Check allowlist validation.",
                "Verify use of relative URLs."
            ),
            Arrays.asList(
                "?next=https://evil.com"
            ),
            true
        ));

        add(new TagDefinition(
            "CORS Misconfiguration",
            TagCategory.VULNERABILITY,
            Arrays.asList(
                "Check ACAO with credentials.",
                "Look for reflected origin patterns.",
                "Verify preflight responses."
            ),
            Arrays.asList(
                "Origin: https://evil.com with credentials"
            ),
            false
        ));

        add(new TagDefinition(
            "JWT / Token Issues",
            TagCategory.VULNERABILITY,
            Arrays.asList(
                "Check alg=none or weak secrets.",
                "Verify signature validation.",
                "Validate exp/aud/iss claims."
            ),
            Arrays.asList(
                "Try alg=none or HS256 with guessable secret"
            ),
            false
        ));

        add(new TagDefinition(
            "OAuth / SSO",
            TagCategory.VULNERABILITY,
            Arrays.asList(
                "Validate redirect_uri allowlist.",
                "Ensure state parameter is required.",
                "Check for open redirect chaining.",
                "Test account linking endpoints for missing state/CSRF (forced linking).",
                "Ensure auth codes are bound to correct client and redirect_uri.",
                "Require re-auth for linking/unlinking and sensitive SSO actions."
            ),
            Arrays.asList(
                "Try redirect_uri=https://evil.com"
            ),
            false
        ));

        add(new TagDefinition(
            "Clickjacking",
            TagCategory.VULNERABILITY,
            Arrays.asList(
                "Check X-Frame-Options / frame-ancestors.",
                "Test sensitive pages in an iframe.",
                "Look for UI redress on critical actions.",
                "Bypass frame-busting scripts with sandboxed iframes."
            ),
            Arrays.asList(
                "Create a PoC iframe on attacker page"
            ),
            false
        ));

        add(new TagDefinition(
            "Rate Limiting / Brute Force",
            TagCategory.VULNERABILITY,
            Arrays.asList(
                "Test brute force with slow ramp.",
                "Check account lockout and cooldown.",
                "Verify CAPTCHA/bot protection.",
                "Check for username enumeration.",
                "See if successful login resets the lockout counter (interleaving valid creds).",
                "Bypass IP throttles via X-Forwarded-For or alternate endpoints."
            ),
            Arrays.asList(
                "Attempt credential stuffing"
            ),
            false
        ));

        add(new TagDefinition(
            "Host Header Injection",
            TagCategory.VULNERABILITY,
            Arrays.asList(
                "Check password reset links built from Host.",
                "Look for cache poisoning via Host.",
                "Test X-Forwarded-Host handling."
            ),
            Arrays.asList(
                "Host: evil.com"
            ),
            false
        ));

        add(new TagDefinition(
            "Deserialization",
            TagCategory.VULNERABILITY,
            Arrays.asList(
                "Identify serialized blobs (Java/PHP/.NET) and magic bytes.",
                "Check whether input reaches deserializers directly.",
                "Verify integrity protections (HMAC/signature).",
                "Modify serialized properties/IDs to change authorization logic.",
                "Change data types (int/string/boolean) to trigger logic flaws.",
                "Look for base64/URL-encoded serialized data in cookies/headers.",
                "Test type restrictions and class allowlists.",
                "Look for known gadget chains for the stack.",
                "Check error messages for class names or stack traces.",
                "Test for insecure deserialization over cookies/headers."
            ),
            Arrays.asList(
                "Look for Java rO0AB / PHP O:"
            ),
            false
        ));

        add(new TagDefinition(
            "Prototype Pollution",
            TagCategory.VULNERABILITY,
            Arrays.asList(
                "Identify endpoints that deep-merge user input into objects.",
                "Test JSON bodies for __proto__ or constructor.prototype keys.",
                "Test URL-encoded params like __proto__[polluted]=yes.",
                "Try alternate vectors (constructor[prototype], arrays, nested objects).",
                "Detect pollution without reflection by checking behavior changes.",
                "Look for auth/role checks that rely on inherited properties.",
                "Check for gadget sinks (template options, file paths, command exec).",
                "Test client-side sinks (DOM XSS) via polluted properties.",
                "Verify impact persists across requests (global prototype).",
                "Ensure app uses allowlists/hasOwnProperty protections."
            ),
            Arrays.asList(
                "{\"__proto__\":{\"polluted\":\"yes\"}}",
                "{\"constructor\":{\"prototype\":{\"polluted\":\"yes\"}}}",
                "__proto__[isAdmin]=true"
            ),
            true
        ));

        add(new TagDefinition(
            "GraphQL",
            TagCategory.VULNERABILITY,
            Arrays.asList(
                "Confirm endpoint is live with __typename query.",
                "Check if introspection is enabled in production.",
                "Enumerate queries/mutations and sensitive fields.",
                "Test object-level access control on IDs (IDOR).",
                "Check auth/role enforcement on mutations.",
                "Test batching for rate-limit bypass or data harvesting.",
                "Check for CSRF on GraphQL GET endpoints.",
                "Test input validation for injection-style issues.",
                "Check error messages for data leakage."
            ),
            Arrays.asList(
                "{__typename}",
                "{__schema{types{name}}}",
                "Batched login or user queries (no DoS)"
            ),
            true
        ));

        add(new TagDefinition(
            "Web Cache Poisoning",
            TagCategory.VULNERABILITY,
            Arrays.asList(
                "Identify cacheable endpoints and confirm cache headers (Cache-Control, Age, X-Cache).",
                "Check whether authenticated responses are cached and shared.",
                "Test cache key variance on headers (Host, X-Forwarded-Host, X-Original-URL).",
                "Look for unkeyed headers or cookies reflected into responses.",
                "Test multiple header interactions (X-Forwarded-Host + X-Forwarded-Scheme).",
                "Use Param Miner/guess headers to discover hidden inputs and check Vary.",
                "Try static extensions on dynamic pages (.js, .css, .png).",
                "Use path delimiters (? ; /) to force cacheable variants.",
                "Confirm a victim can retrieve poisoned content without auth."
            ),
            Arrays.asList(
                "/account.js, /profile.css",
                "/my-account;123.js",
                "Host/X-Forwarded-Host poisoning"
            ),
            true
        ));

        add(new TagDefinition(
            "Cache Deception",
            TagCategory.VULNERABILITY,
            Arrays.asList(
                "Identify authenticated pages that are cacheable by path rules.",
                "Test static-extension tricks on sensitive pages (/.css, /.js).",
                "Use path delimiters (;, /, ?) to reach the same handler.",
                "Check cache hit headers (Age, X-Cache) after priming.",
                "Fetch the primed URL as a different user or unauthenticated.",
                "Confirm caches ignore or bypass Cookie/Authorization as expected."
            ),
            Arrays.asList(
                "/account/profile.css",
                "/settings;v1.js",
                "/profile/?x=.css"
            ),
            true
        ));

        add(new TagDefinition(
            "Request Smuggling",
            TagCategory.VULNERABILITY,
            Arrays.asList(
                "Confirm a front-end proxy/CDN sits in front of the origin.",
                "Test TE.CL and CL.TE with ambiguous headers.",
                "Try duplicate Content-Length headers with different values.",
                "Look for desync signs: hangs, odd status, response queueing.",
                "Verify impact on next request (auth bypass, cache poisoning).",
                "Focus on HTTP/1.1 keep-alive and connection reuse behavior.",
                "Use differential responses (smuggle /404) to confirm desync.",
                "Test HTTP/2 downgrade paths (H2.TE) for response queue poisoning.",
                "Check for front-end request rewriting by smuggling unique headers.",
                "Attempt to capture or influence other users' requests."
            ),
            Arrays.asList(
                "Transfer-Encoding: chunked + Content-Length: 4",
                "Two Content-Length headers with different values"
            ),
            true
        ));

        add(new TagDefinition(
            "WSS (WebSocket Secure)",
            TagCategory.VULNERABILITY,
            Arrays.asList(
                "Enumerate WebSocket endpoints and message types.",
                "Verify auth/role enforcement on every message type.",
                "Check Origin validation to prevent cross-site WebSocket hijacking.",
                "Test replay of captured messages after logout or removal.",
                "Check IDOR in message payloads (user_id, connection_id).",
                "Attempt privilege escalation via role change messages.",
                "Tamper WebSocket messages to bypass client-side encoding/filters.",
                "Manipulate handshake headers (X-Forwarded-For) to bypass IP bans.",
                "Validate server-side input validation and rate limits.",
                "Check for information leaks in broadcast messages."
            ),
            Arrays.asList(
                "Replay KICK/MUTE/ASSIGN ROLE messages.",
                "Send large payloads to test DoS handling."
            ),
            true
        ));

        add(new TagDefinition(
            "2FA / MFA",
            TagCategory.VULNERABILITY,
            Arrays.asList(
                "Attempt direct access to protected pages without 2FA.",
                "Test OTP brute-force and rate limits.",
                "Check OTP reuse and expiry enforcement.",
                "Try default OTPs (000000, 123456).",
                "Test cross-account OTP usage.",
                "Verify 2FA disable requires recent verification.",
                "Check OAuth/SSO flows still enforce 2FA.",
                "Test backup code reuse and invalidation.",
                "Check for CSRF/clickjacking on 2FA disable."
            ),
            Arrays.asList(
                "Modify 2FA flags in requests (2fa=false).",
                "Check 2FA on password reset and API token creation."
            ),
            true
        ));

        add(new TagDefinition(
            "AI Pentest (LLM)",
            TagCategory.VULNERABILITY,
            Arrays.asList(
                "Inventory AI features: chat, RAG, tools, agents, and plugins.",
                "Check for sensitive data exposure from prompts or retrieval.",
                "Test tool/agent authorization and least privilege.",
                "Probe for prompt leakage of system or developer instructions.",
                "Test output manipulation and policy bypass via indirect inputs.",
                "Check for training data or PII leakage signals.",
                "Assess model extraction or membership inference risk.",
                "Test data poisoning of RAG/embeddings sources.",
                "Assess rate limiting, abuse controls, and logging.",
                "Validate model output is not used for security decisions."
            ),
            Arrays.asList(
                "Try indirect prompt injection via retrieved documents.",
                "Attempt tool misuse (SSRF, file access) within allowed scope."
            ),
            true
        ));

        add(new TagDefinition(
            "Auth",
            TagCategory.COMPONENT,
            Arrays.asList(
                "Test login, logout, reset, and MFA flows end-to-end.",
                "Check session fixation and session rotation on login.",
                "Verify logout invalidates server-side sessions.",
                "Test remember-me tokens and refresh tokens.",
                "Check account enumeration via error messages/timing.",
                "Validate password policy and lockout behavior.",
                "Verify 2FA enforced on sensitive actions."
            ),
            Collections.emptyList(),
            false
        ));

        add(new TagDefinition(
            "Payments",
            TagCategory.COMPONENT,
            Arrays.asList(
                "Check totals, currency, discounts, and tax calculations.",
                "Verify server-side recalculation on checkout.",
                "Test price/quantity manipulation on client and API.",
                "Attempt coupon stacking or negative prices.",
                "Test refunds, chargebacks, and partial refunds.",
                "Verify invoice generation and payment status transitions.",
                "Check idempotency on payment and refund endpoints.",
                "Test multi-currency rounding and conversion.",
                "Verify authorization on payment methods and saved cards."
            ),
            Collections.emptyList(),
            false
        ));

        add(new TagDefinition(
            "Admin",
            TagCategory.COMPONENT,
            Arrays.asList(
                "Force browse admin endpoints (UI hidden paths).",
                "Test role checks on every admin action.",
                "Attempt IDOR on admin resources (user_id, org_id).",
                "Check mass assignment on admin APIs.",
                "Verify audit logging for admin actions.",
                "Test CSRF on admin state changes."
            ),
            Collections.emptyList(),
            false
        ));

        add(new TagDefinition(
            "API",
            TagCategory.COMPONENT,
            Arrays.asList(
                "Check auth on every endpoint (missing auth).",
                "Test object-level access control (IDOR).",
                "Test for mass assignment in JSON bodies.",
                "Review rate limiting and abuse controls.",
                "Validate input types and schema enforcement.",
                "Check pagination/filters for data leakage."
            ),
            Collections.emptyList(),
            false
        ));

        add(new TagDefinition(
            "File Upload",
            TagCategory.COMPONENT,
            Arrays.asList(
                "Check extension allowlist and content-type validation.",
                "Try double extensions and polyglots (e.g., .php.jpg).",
                "Verify magic bytes and server-side validation.",
                "Check upload path for traversal and filename issues.",
                "Verify files are stored outside web root.",
                "Test client-side only validation bypass.",
                "Check if uploaded files are directly accessible."
            ),
            Arrays.asList(
                ".php.jpg", ".jsp;.jpg", "SVG script payload"
            ),
            true
        ));
    }

    private TagLibrary() {
    }

    private static void add(TagDefinition definition) {
        TAGS.put(definition.getName(), definition);
        TAGS_LOWER.put(definition.getName().toLowerCase(Locale.ROOT), definition);
    }

    static List<String> getAllTagNames() {
        ensureLoaded();
        return new ArrayList<>(TAGS.keySet());
    }

    static TagDefinition getDefinition(String tag) {
        ensureLoaded();
        if (tag == null) {
            return null;
        }
        TagDefinition def = TAGS_LOWER.get(tag.toLowerCase(Locale.ROOT));
        if (def != null) {
            return def;
        }
        return TAGS.get(tag);
    }

    static List<String> getChecklistForTag(String tag) {
        ensureLoaded();
        TagDefinition def = getDefinition(tag);
        if (def == null) {
            return Collections.emptyList();
        }
        return def.getChecklist();
    }

    // Templates removed; tag checklists remain in the checklist panel.
}
