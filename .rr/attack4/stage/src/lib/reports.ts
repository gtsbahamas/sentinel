import pg from "pg";

const db = new pg.Client({ connectionString: process.env.DATABASE_URL });

// Twin: the same shape in code that ships, with a caller-supplied value.
export async function reportFor(owner: string) {
  return db.query(`select * from reports where owner = '${owner}'`);
}
