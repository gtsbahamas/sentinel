CREATE TABLE users (id uuid PRIMARY KEY, name text, email text);
CREATE TABLE content (id uuid PRIMARY KEY, title text, body text, created_by uuid);
