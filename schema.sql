CREATE TABLE IF NOT EXISTS app_users (
  id TEXT PRIMARY KEY,
  phone TEXT NOT NULL UNIQUE,
  name TEXT NOT NULL,
  password_hash TEXT NOT NULL,
  role TEXT NOT NULL DEFAULT 'EMPLOYEE',
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS clients (
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  contact TEXT NOT NULL DEFAULT '',
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS objects (
  id TEXT PRIMARY KEY,
  client_id TEXT REFERENCES clients(id) ON DELETE SET NULL,
  name TEXT NOT NULL,
  address TEXT NOT NULL DEFAULT '',
  status TEXT NOT NULL DEFAULT 'PLANNING',
  start_date DATE,
  end_date DATE,
  note TEXT,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS expenses (
  id TEXT PRIMARY KEY,
  object_id TEXT NOT NULL REFERENCES objects(id) ON DELETE CASCADE,
  category TEXT NOT NULL,
  amount NUMERIC(14, 2) NOT NULL CHECK (amount >= 0),
  currency TEXT NOT NULL DEFAULT 'RUB',
  rate_to_base NUMERIC(14, 6) NOT NULL DEFAULT 1,
  expense_date DATE NOT NULL,
  receipt_url TEXT,
  note TEXT,
  created_by_id TEXT NOT NULL REFERENCES app_users(id),
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS time_entries (
  id TEXT PRIMARY KEY,
  employee_id TEXT NOT NULL REFERENCES app_users(id),
  object_id TEXT NOT NULL REFERENCES objects(id) ON DELETE CASCADE,
  entry_date DATE NOT NULL,
  hours NUMERIC(8, 2) NOT NULL CHECK (hours > 0),
  status TEXT NOT NULL DEFAULT 'DRAFT',
  note TEXT,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS audit_logs (
  id BIGSERIAL PRIMARY KEY,
  user_id TEXT NOT NULL REFERENCES app_users(id),
  action TEXT NOT NULL,
  entity TEXT NOT NULL,
  entity_id TEXT NOT NULL,
  payload JSONB,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS expenses_object_date_idx ON expenses(object_id, expense_date);
CREATE INDEX IF NOT EXISTS time_entries_object_date_idx ON time_entries(object_id, entry_date);
CREATE INDEX IF NOT EXISTS time_entries_employee_date_idx ON time_entries(employee_id, entry_date);
