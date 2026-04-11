-- Vulnerable fixture migration.

create table if not exists profiles (
  id uuid primary key,
  email text,
  role text default 'user'
);

-- VULN AUTH-002: profiles table referenced in code but no ENABLE ROW LEVEL SECURITY.

-- VULN UPLOAD-008: public bucket without a matching policy.
insert into storage.buckets (id, name, public) values ('avatars', 'avatars', true);
