# Cloud Deployment Security Checklist (AWS / GCP)

## 1. Network & Perimeter
- [ ] Deploy in a dedicated VPC; database subnet has **no** internet gateway route (AWS: private subnet + NAT for egress only; GCP: Private Google Access, no external IP on Cloud SQL).
- [ ] Security Groups / firewall rules are default-deny; DB security group allows inbound 5432 **only** from the app-tier security group, not 0.0.0.0/0.
- [ ] Put a managed WAF in front of the API Gateway (AWS WAF / Cloud Armor) with rulesets for SQLi, XSS, and rate-based rules per IP/client_id.
- [ ] Enable DDoS protection (AWS Shield Standard/Advanced, GCP Cloud Armor Adaptive Protection).
- [ ] Use a service mesh or mTLS between internal services so lateral movement requires a valid workload identity, not just network reachability.

## 2. Identity & Access Management
- [ ] Enforce OAuth2/OIDC with Authorization Code + PKCE for all browser/mobile clients; never use the implicit flow.
- [ ] MFA (TOTP or WebAuthn) mandatory for all staff, admin, and wholesale-portal roles at minimum.
- [ ] Access tokens short-lived (10–15 min); refresh tokens rotated on use, with reuse detection to catch token theft.
- [ ] Principle of least privilege on cloud IAM: each microservice has its own IAM role/service account with only the permissions it needs (e.g., POS service cannot read Subscription tables).
- [ ] No long-lived static cloud credentials in code or CI — use workload identity federation (GCP) or IAM roles for service accounts (AWS IRSA on EKS, or ECS task roles).
- [ ] Break-glass admin access is logged, time-boxed, and requires separate approval (e.g., AWS IAM Identity Center session with MFA + short TTL).

## 3. Data Protection
- [ ] TLS 1.3 enforced at the load balancer/API Gateway; disable TLS 1.0/1.1/1.2 where feasible, HSTS enabled.
- [ ] AES-256 encryption at rest on the RDS/Cloud SQL instance, backed by a customer-managed KMS key (not the default provider key), with key rotation enabled.
- [ ] Encrypt application-level secrets (MFA TOTP seeds, etc.) with envelope encryption before writing to the DB — DB-at-rest encryption alone is not sufficient defense-in-depth for these fields.
- [ ] All secrets (DB creds, JWT signing keys, Stripe API keys) live in a secrets manager (AWS Secrets Manager / GCP Secret Manager), injected at runtime, never in env files committed to source control.
- [ ] Automated encrypted backups with tested restore procedure; backups stored in a separate account/project from production to survive account compromise.

## 4. Payments / PCI-DSS Scope
- [ ] Card data never touches your servers — use Stripe Elements / Payment Element (client-side tokenization) or Stripe-hosted Checkout so raw PAN never hits your backend (keeps you in SAQ A / SAQ A-EP, the lowest PCI burden).
- [ ] Only store Stripe `customer_id`, `payment_method_id`, `last4`, `brand` — verified against the schema in this deliverable.
- [ ] Validate all Stripe webhooks using the signing secret (`Stripe-Signature` header) to prevent spoofed payment-confirmation events.
- [ ] Idempotency keys on every payment-mutating endpoint to prevent duplicate charges on client retry.

## 5. Application Security
- [ ] Schema validation (Zod/Pydantic) on every input at the API boundary — reject unknown fields (`.strict()` / `extra="forbid"`) to reduce mass-assignment risk.
- [ ] Parameterized queries / ORM only — no string-concatenated SQL anywhere in the codebase; enforce via linter rule + code review.
- [ ] Object-level authorization checked server-side on every request touching a resource ID (anti-BOLA) — never trust a client-supplied `client_id`/`order_id` without a server-side ownership check.
- [ ] Return 404 (not 403) for resources outside a caller's scope, to avoid confirming existence of other tenants' data.
- [ ] Content-Security-Policy, X-Frame-Options, X-Content-Type-Options headers set on all web responses.
- [ ] Dependency scanning (Dependabot/Snyk) and container image scanning (Trivy/ECR scanning/Artifact Registry vulnerability scanning) in CI, blocking on critical CVEs.
- [ ] Static analysis / SAST in CI (Semgrep, CodeQL) for injection and auth-bypass patterns.
- [ ] Rate limiting per user/IP on auth endpoints specifically (`/auth/login`, `/auth/mfa/verify`) to blunt credential-stuffing and OTP brute-force.

## 6. Logging, Monitoring & Audit
- [ ] `audit_logs` table is append-only at the DB grant level (no UPDATE/DELETE) as shown in the schema; consider also shipping a copy to an external, tamper-evident store (e.g., S3 with Object Lock / GCS with retention policy).
- [ ] Centralized logging (CloudWatch Logs / Cloud Logging) with alerts on: repeated auth failures, privilege escalation (role grants), refund/void spikes, and access from unexpected geographies.
- [ ] Enable cloud-native threat detection: AWS GuardDuty / GCP Security Command Center.
- [ ] Enable database audit logging (pgAudit extension) in addition to application-level audit logs, to catch access outside the app's own code path.

## 7. Infrastructure & Operations
- [ ] Infrastructure as Code (Terraform/Pulumi) with a security review step (tfsec/Checkov) in CI before apply.
- [ ] Multi-AZ / regional redundancy for the database (RDS Multi-AZ, Cloud SQL HA) and defined RPO/RTO with tested failover.
- [ ] Patch management: base container images rebuilt on a schedule (weekly) to pull latest security patches, not left static for months.
- [ ] Separate AWS accounts/GCP projects per environment (dev/staging/prod) with no shared credentials between them.
- [ ] Formal incident response runbook, including how to revoke compromised tokens (short access-token TTL + refresh-token blacklist table) and rotate the JWT signing key.

## 8. Compliance Process
- [ ] Complete the appropriate PCI-DSS SAQ (A or A-EP depending on integration method) annually; do not self-certify as fully PCI-DSS "compliant" without going through the actual attestation process with a QSA or approved scan vendor (ASV) as required by your acquiring bank.
- [ ] Data retention and deletion policy documented for subscriber PII (right-to-erasure handling under GDPR/CCPA if applicable to your customer base).