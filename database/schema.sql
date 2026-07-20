-- =====================================================================
-- Multi-Channel Ice Cream Platform — PostgreSQL Schema
-- PCI-DSS-aware: no PAN/CVV/full card data stored anywhere in this schema.
-- All payment fields are Stripe tokens/IDs only.
-- =====================================================================

CREATE EXTENSION IF NOT EXISTS "pgcrypto";   -- for gen_random_uuid()
CREATE EXTENSION IF NOT EXISTS "citext";     -- case-insensitive email

-- ---------------------------------------------------------------------
-- 1. IDENTITY & RBAC
-- ---------------------------------------------------------------------

CREATE TABLE roles (
    role_id         SMALLSERIAL PRIMARY KEY,
    role_name       VARCHAR(50) UNIQUE NOT NULL,   -- e.g. 'pos_cashier', 'wholesale_partner'
    description     TEXT,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE users (
    user_id             UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    email               CITEXT UNIQUE NOT NULL,
    -- Password hash only used as a local fallback; primary auth is OIDC (external_idp_subject).
    password_hash       TEXT,                       -- bcrypt/argon2id hash, NEVER plaintext
    external_idp_subject TEXT UNIQUE,                -- 'sub' claim from OIDC provider (Auth0/Cognito/Keycloak)
    full_name           VARCHAR(150) NOT NULL,
    phone               VARCHAR(30),
    mfa_enabled          BOOLEAN NOT NULL DEFAULT FALSE,
    mfa_secret_encrypted BYTEA,                      -- TOTP secret, encrypted at application layer (KMS envelope)
    status               VARCHAR(20) NOT NULL DEFAULT 'active'
                          CHECK (status IN ('active','suspended','disabled')),
    failed_login_attempts SMALLINT NOT NULL DEFAULT 0,
    locked_until          TIMESTAMPTZ,
    created_at            TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at            TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE user_roles (
    user_role_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id     UUID NOT NULL REFERENCES users(user_id) ON DELETE CASCADE,
    role_id     SMALLINT NOT NULL REFERENCES roles(role_id) ON DELETE RESTRICT,
    -- Optional scoping: a wholesale_partner role is scoped to one client account
    scope_type  VARCHAR(30),              -- 'store', 'wholesale_client', 'global', NULL
    scope_id    UUID,                     -- FK-like pointer resolved per scope_type
    granted_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    granted_by  UUID REFERENCES users(user_id)
);

-- PRIMARY KEY can't contain expressions, so uniqueness (treating NULL scope_id as a
-- single shared value) is enforced via this index instead of a composite PK.
CREATE UNIQUE INDEX uq_user_roles_scope ON user_roles (
    user_id, role_id, COALESCE(scope_id, '00000000-0000-0000-0000-000000000000')
);

CREATE INDEX idx_user_roles_user ON user_roles(user_id);

-- Stripe linkage — never store card data, only the Stripe customer reference
CREATE TABLE payment_profiles (
    payment_profile_id     UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id                 UUID REFERENCES users(user_id) ON DELETE CASCADE,
    wholesale_client_id     UUID,   -- nullable FK, set below after wholesale_clients exists
    stripe_customer_id      VARCHAR(255) NOT NULL,
    default_payment_method_id VARCHAR(255),   -- Stripe PaymentMethod token (pm_xxx)
    card_brand              VARCHAR(20),      -- display only, e.g. 'visa'
    card_last4               CHAR(4),          -- display only
    created_at               TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT chk_owner CHECK (
        (user_id IS NOT NULL)::int + (wholesale_client_id IS NOT NULL)::int = 1
    )
);

-- ---------------------------------------------------------------------
-- 2. PRODUCT CATALOG (shared across channels)
-- ---------------------------------------------------------------------

CREATE TABLE products (
    product_id       UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    sku               VARCHAR(60) UNIQUE NOT NULL,
    name              VARCHAR(150) NOT NULL,
    category          VARCHAR(50) NOT NULL,        -- 'ln2_lab', 'high_protein_pint', 'gourmet_pint', 'catering_item'
    unit_price_cents  INTEGER NOT NULL CHECK (unit_price_cents >= 0),
    wholesale_price_cents INTEGER CHECK (wholesale_price_cents >= 0),
    is_active          BOOLEAN NOT NULL DEFAULT TRUE,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- ---------------------------------------------------------------------
-- 3. CHANNEL 1 — PHYSICAL RETAIL / POS (Liquid Nitrogen Lab)
-- ---------------------------------------------------------------------

CREATE TABLE stores (
    store_id     UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name          VARCHAR(120) NOT NULL,
    address       TEXT NOT NULL,
    timezone      VARCHAR(50) NOT NULL DEFAULT 'UTC'
);

CREATE TABLE pos_transactions (
    transaction_id     UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    store_id            UUID NOT NULL REFERENCES stores(store_id),
    cashier_user_id      UUID NOT NULL REFERENCES users(user_id),
    customer_user_id      UUID REFERENCES users(user_id),         -- nullable: guest checkout
    subtotal_cents         INTEGER NOT NULL CHECK (subtotal_cents >= 0),
    tax_cents               INTEGER NOT NULL DEFAULT 0,
    total_cents              INTEGER NOT NULL CHECK (total_cents >= 0),
    payment_method            VARCHAR(20) NOT NULL CHECK (payment_method IN ('card','cash','wallet')),
    stripe_payment_intent_id  VARCHAR(255),      -- only set when payment_method = 'card'
    status                     VARCHAR(20) NOT NULL DEFAULT 'completed'
                                CHECK (status IN ('completed','refunded','voided')),
    idempotency_key             VARCHAR(100) UNIQUE,   -- prevents duplicate charge on retry
    created_at                   TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE pos_transaction_items (
    item_id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    transaction_id     UUID NOT NULL REFERENCES pos_transactions(transaction_id) ON DELETE CASCADE,
    product_id          UUID NOT NULL REFERENCES products(product_id),
    quantity              SMALLINT NOT NULL CHECK (quantity > 0),
    unit_price_cents      INTEGER NOT NULL,
    line_total_cents      INTEGER NOT NULL
);

CREATE INDEX idx_pos_tx_store_date ON pos_transactions(store_id, created_at);

-- ---------------------------------------------------------------------
-- 4. CHANNEL 2 — B2B WHOLESALE (Gyms/Cafes)
-- ---------------------------------------------------------------------

CREATE TABLE wholesale_clients (
    wholesale_client_id  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    business_name          VARCHAR(150) NOT NULL,
    tax_id                  VARCHAR(50),
    billing_address          TEXT NOT NULL,
    net_terms_days             SMALLINT NOT NULL DEFAULT 30,   -- e.g. Net 30
    status                       VARCHAR(20) NOT NULL DEFAULT 'active'
                                  CHECK (status IN ('active','suspended','closed')),
    created_at                   TIMESTAMPTZ NOT NULL DEFAULT now()
);

ALTER TABLE payment_profiles
    ADD CONSTRAINT fk_payment_wholesale
    FOREIGN KEY (wholesale_client_id) REFERENCES wholesale_clients(wholesale_client_id) ON DELETE CASCADE;

-- Links a portal user (login) to the wholesale account they represent
CREATE TABLE wholesale_client_users (
    wholesale_client_id  UUID NOT NULL REFERENCES wholesale_clients(wholesale_client_id) ON DELETE CASCADE,
    user_id                UUID NOT NULL REFERENCES users(user_id) ON DELETE CASCADE,
    is_primary_contact       BOOLEAN NOT NULL DEFAULT FALSE,
    PRIMARY KEY (wholesale_client_id, user_id)
);

CREATE TABLE wholesale_orders (
    order_id                UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    wholesale_client_id       UUID NOT NULL REFERENCES wholesale_clients(wholesale_client_id),
    placed_by_user_id           UUID NOT NULL REFERENCES users(user_id),
    status                        VARCHAR(20) NOT NULL DEFAULT 'pending'
                                   CHECK (status IN ('pending','confirmed','shipped','delivered','invoiced','paid','cancelled')),
    subtotal_cents                 INTEGER NOT NULL CHECK (subtotal_cents >= 0),
    total_cents                     INTEGER NOT NULL CHECK (total_cents >= 0),
    stripe_invoice_id                 VARCHAR(255),   -- Stripe Invoicing for Net-terms billing
    requested_delivery_date             DATE,
    created_at                           TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE wholesale_order_items (
    item_id      UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    order_id      UUID NOT NULL REFERENCES wholesale_orders(order_id) ON DELETE CASCADE,
    product_id     UUID NOT NULL REFERENCES products(product_id),
    quantity         INTEGER NOT NULL CHECK (quantity > 0),
    unit_price_cents  INTEGER NOT NULL,
    line_total_cents   INTEGER NOT NULL
);

CREATE INDEX idx_wholesale_orders_client ON wholesale_orders(wholesale_client_id, created_at);

-- ---------------------------------------------------------------------
-- 5. CHANNEL 3 — CORPORATE MOBILE CATERING
-- ---------------------------------------------------------------------

CREATE TABLE catering_bookings (
    booking_id             UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    corporate_client_user_id UUID NOT NULL REFERENCES users(user_id),
    coordinator_user_id       UUID REFERENCES users(user_id),   -- internal staff assigned
    event_name                  VARCHAR(150) NOT NULL,
    event_address                 TEXT NOT NULL,
    event_start_at                  TIMESTAMPTZ NOT NULL,
    event_end_at                     TIMESTAMPTZ NOT NULL,
    guest_count                        INTEGER NOT NULL CHECK (guest_count > 0),
    status                               VARCHAR(20) NOT NULL DEFAULT 'requested'
                                          CHECK (status IN ('requested','quoted','confirmed','completed','cancelled')),
    quote_cents                            INTEGER,
    deposit_paid_cents                      INTEGER NOT NULL DEFAULT 0,
    stripe_payment_intent_id                  VARCHAR(255),
    created_at                                 TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE catering_staff_assignments (
    assignment_id   UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    booking_id       UUID NOT NULL REFERENCES catering_bookings(booking_id) ON DELETE CASCADE,
    staff_user_id      UUID NOT NULL REFERENCES users(user_id),
    role_on_event         VARCHAR(50)    -- 'lead', 'server', 'ln2_operator'
);

CREATE INDEX idx_catering_bookings_client ON catering_bookings(corporate_client_user_id);

-- ---------------------------------------------------------------------
-- 6. CHANNEL 4 — D2C MONTHLY SUBSCRIPTION
-- ---------------------------------------------------------------------

CREATE TABLE subscription_plans (
    plan_id        UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name            VARCHAR(100) NOT NULL,
    pints_per_month  SMALLINT NOT NULL,
    price_cents        INTEGER NOT NULL CHECK (price_cents >= 0),
    stripe_price_id       VARCHAR(255) NOT NULL,   -- Stripe recurring Price object
    is_active              BOOLEAN NOT NULL DEFAULT TRUE
);

CREATE TABLE subscriptions (
    subscription_id       UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id                 UUID NOT NULL REFERENCES users(user_id),
    plan_id                   UUID NOT NULL REFERENCES subscription_plans(plan_id),
    stripe_subscription_id      VARCHAR(255) UNIQUE NOT NULL,
    status                        VARCHAR(20) NOT NULL DEFAULT 'active'
                                   CHECK (status IN ('active','paused','past_due','cancelled')),
    current_period_start            TIMESTAMPTZ NOT NULL,
    current_period_end                TIMESTAMPTZ NOT NULL,
    shipping_address_id                 UUID,   -- FK to addresses table
    created_at                            TIMESTAMPTZ NOT NULL DEFAULT now(),
    cancelled_at                            TIMESTAMPTZ
);

CREATE TABLE addresses (
    address_id     UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id         UUID NOT NULL REFERENCES users(user_id) ON DELETE CASCADE,
    line1            VARCHAR(200) NOT NULL,
    line2             VARCHAR(200),
    city               VARCHAR(100) NOT NULL,
    state_region         VARCHAR(100) NOT NULL,
    postal_code            VARCHAR(20) NOT NULL,
    country                  CHAR(2) NOT NULL,
    is_default                 BOOLEAN NOT NULL DEFAULT FALSE
);

ALTER TABLE subscriptions
    ADD CONSTRAINT fk_sub_address FOREIGN KEY (shipping_address_id) REFERENCES addresses(address_id);

CREATE TABLE subscription_shipments (
    shipment_id       UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    subscription_id     UUID NOT NULL REFERENCES subscriptions(subscription_id) ON DELETE CASCADE,
    scheduled_for          DATE NOT NULL,
    shipped_at                TIMESTAMPTZ,
    tracking_number             VARCHAR(100),
    status                        VARCHAR(20) NOT NULL DEFAULT 'scheduled'
                                   CHECK (status IN ('scheduled','shipped','delivered','skipped','failed'))
);

CREATE INDEX idx_subscriptions_user ON subscriptions(user_id);

-- ---------------------------------------------------------------------
-- 7. AUDIT LOG (immutable, append-only)
-- ---------------------------------------------------------------------

CREATE TABLE audit_logs (
    audit_id        BIGSERIAL PRIMARY KEY,
    actor_user_id     UUID REFERENCES users(user_id),
    actor_role          VARCHAR(50),
    action                VARCHAR(100) NOT NULL,     -- e.g. 'REFUND_ISSUED', 'ROLE_GRANTED', 'ORDER_CANCELLED'
    target_entity_type      VARCHAR(50) NOT NULL,    -- e.g. 'pos_transactions'
    target_entity_id          UUID,
    before_state                 JSONB,
    after_state                    JSONB,
    ip_address                       INET,
    user_agent                         TEXT,
    created_at                           TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Prevent UPDATE/DELETE at the DB level to guarantee immutability of audit trail
REVOKE UPDATE, DELETE ON audit_logs FROM PUBLIC;
CREATE INDEX idx_audit_actor ON audit_logs(actor_user_id, created_at);
CREATE INDEX idx_audit_target ON audit_logs(target_entity_type, target_entity_id);

-- ---------------------------------------------------------------------
-- 8. ROW-LEVEL SECURITY EXAMPLE (Wholesale isolation — prevents BOLA at DB layer)
-- ---------------------------------------------------------------------
-- Application sets: SET app.current_wholesale_client_id = '<uuid>'; per request (via a pooled,
-- per-transaction SET LOCAL, not a shared connection) after validating the JWT claim server-side.

ALTER TABLE wholesale_orders ENABLE ROW LEVEL SECURITY;

CREATE POLICY wholesale_orders_isolation ON wholesale_orders
    USING (wholesale_client_id = current_setting('app.current_wholesale_client_id', true)::UUID)
    WITH CHECK (wholesale_client_id = current_setting('app.current_wholesale_client_id', true)::UUID);

-- global_admin role bypasses RLS via a separate DB role with BYPASSRLS, granted only to the
-- admin service's connection pool, never to end-user-facing service connections.

-- ---------------------------------------------------------------------
-- 9. SEED ROLES
-- ---------------------------------------------------------------------

INSERT INTO roles (role_name, description) VALUES
    ('global_admin', 'Full platform access, all channels'),
    ('pos_cashier', 'Can create/void POS transactions at assigned store'),
    ('store_manager', 'POS + refunds + staff mgmt for assigned store'),
    ('wholesale_partner', 'B2B portal user, scoped to own wholesale_client_id'),
    ('wholesale_ops', 'Internal staff managing wholesale fulfillment, all clients'),
    ('catering_coordinator', 'Manages catering bookings and staff assignment'),
    ('corporate_client', 'Books and views own catering bookings'),
    ('subscriber', 'D2C subscription customer'),
    ('support_agent', 'Read/limited-write access across channels for customer support');