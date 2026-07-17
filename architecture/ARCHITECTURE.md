# Multi-Channel Ice Cream Platform — System Architecture

## 1. Design Goals

- One secure backend serving four channels (POS, B2B Wholesale, Corporate Catering, D2C Subscriptions)
- Strict tenant/role isolation — a Wholesale Partner must never reach POS or Admin endpoints (BOLA prevention)
- PCI-DSS scope minimization — no cardholder data touches our servers (Stripe tokenization only)
- Defense in depth: network isolation, gateway-level auth, service-level RBAC, row-level data checks, audit trail

## 2. Three-Tier Architecture (ASCII Diagram)

                                   ┌───────────────────────────────────────────┐
                                   │              PRESENTATION TIER              │
                                   │  (Public Internet — TLS 1.3 everywhere)      │
                                   │                                             │
  ┌───────────────┐   ┌───────────────┐   ┌──────────────────┐   ┌───────────────────┐
  │  POS Terminal  │   │  Web (Next.js) │   │  Mobile App (RN) │   │  B2B Partner Portal │
  │  (in-store)    │   │  D2C storefront │  │  Catering booking │  │  (Wholesale/Gyms)   │
  └───────┬────────┘   └───────┬────────┘   └────────┬─────────┘   └──────────┬──────────┘
          │                    │                      │                       │
          └────────────────────┴──────────┬───────────┴───────────────────────┘
                                           │  HTTPS/TLS 1.3 + JWT (OIDC access token)
                                           ▼
                     ┌─────────────────────────────────────────────┐
                     │               API GATEWAY (WAF)              │
                     │  - TLS termination                           │
                     │  - Rate limiting / throttling per client_id  │
                     │  - JWT signature + expiry validation          │
                     │  - Coarse-grained route ACL (role claim)      │
                     │  - Request size / schema pre-filter           │
                     └───────────────────────┬───────────────────────┘
                                              │  mTLS (internal)
                                              ▼
                     ┌─────────────────────────────────────────────┐
                     │            IDENTITY PROVIDER (OIDC)           │
                     │  Auth0 / Keycloak / AWS Cognito               │
                     │  - OAuth2.0 Authorization Code + PKCE          │
                     │  - MFA (TOTP / WebAuthn) enforced per role     │
                     │  - Issues short-lived access + refresh tokens  │
                     └───────────────────────┬───────────────────────┘
                                              │
                                              ▼
   ┌──────────────────────────────────────── LOGIC TIER ─────────────────────────────────────────┐
   │                      Private Subnet — no direct internet ingress                             │
   │                                                                                                │
   │  ┌────────────┐  ┌──────────────────┐  ┌────────────────────┐  ┌──────────────────────────┐ │
   │  │ POS Service │  │ Wholesale Service │  │ Catering Service    │  │ Subscription Service      │ │
   │  │ (Node/Fast  │  │ (order mgmt,      │  │ (booking, staff     │  │ (recurring billing via    │ │
   │  │  API)       │  │  invoicing)       │  │  scheduling)        │  │  Stripe Billing)           │ │
   │  └──────┬──────┘  └─────────┬─────────┘  └──────────┬──────────┘  └────────────┬──────────────┘ │
   │         │                   │                       │                          │                │
   │         └───────────┬───────┴───────────┬───────────┴──────────────┬───────────┘                │
   │                     ▼                   ▼                          ▼                            │
   │            ┌─────────────────┐  ┌───────────────┐         ┌──────────────────┐                  │
   │            │  Auth/RBAC Mid- │  │  Zod/Pydantic  │         │  Audit Log        │                  │
   │            │  dleware (every │  │  Validation    │         │  Writer (async)   │                  │
   │            │  service)       │  │  Layer         │         │                   │                  │
   │            └─────────────────┘  └───────────────┘         └──────────────────┘                  │
   └───────────────────────────────────────┬──────────────────────────────────────────────────────────┘
                                            │  Encrypted connection (TLS, IAM/DB creds via Secrets Manager)
                                            ▼
                     ┌─────────────────────────────────────────────┐
                     │                 DATA TIER                     │
                     │      Private Subnet, NO public IP/route       │
                     │                                                │
                     │   PostgreSQL (RDS/Cloud SQL, Multi-AZ)         │
                     │   - AES-256 at rest (KMS-managed keys)         │
                     │   - Row-level security by tenant/role          │
                     │   - Automated encrypted backups                │
                     └─────────────────────────────────────────────┘

                     ┌─────────────────────────────────────────────┐
                     │            EXTERNAL PCI BOUNDARY              │
                     │  Stripe (Payment Intents, Billing, Connect)   │
                     │  - We store only: customer_id, payment_method │
                     │    _id (token), last4, brand — never PAN/CVV  │
                     └─────────────────────────────────────────────┘

## 3. Channel-to-Service Mapping

| Channel | Client | Primary Service | Key Roles |
|---|---|---|---|
| Physical Retail/POS | POS Terminal (kiosk/tablet) | POS Service | `pos_cashier`, `store_manager` |
| B2B Wholesale | Partner Web Portal | Wholesale Service | `wholesale_partner`, `wholesale_ops` |
| Corporate Catering | Web + Mobile | Catering Service | `catering_coordinator`, `corporate_client` |
| D2C Subscription | Web (Next.js) storefront | Subscription Service | `subscriber`, `support_agent` |
| All | Admin Console | All services (read) | `global_admin` |

## 4. Network Segmentation

- **Public subnet**: only the API Gateway/Load Balancer + WAF live here.
- **Private app subnet**: all business logic services; egress-only via NAT for Stripe/webhooks.
- **Private data subnet**: PostgreSQL only; security group allows inbound *only* from app subnet on 5432; no internet gateway route at all.
- Service-to-service traffic uses mTLS or a service mesh (e.g., AWS App Mesh / Istio) with SPIFFE identities so services authenticate each other, not just users.

## 5. Key Cross-Cutting Concerns

- **RBAC enforcement happens twice**: coarse-grained at the Gateway (role must be permitted on route), fine-grained inside each service (row-level ownership checks — e.g., a `wholesale_partner` can only fetch orders where `wholesale_orders.client_id = jwt.client_id`) to prevent BOLA.
- **Audit Logs** are written asynchronously (via an event queue, e.g., SQS/PubSub) so a slow audit write never blocks the request path, but is never dropped (dead-letter queue + retry).
- **Idempotency keys** required on all payment-mutating endpoints to avoid double-charging on retries.