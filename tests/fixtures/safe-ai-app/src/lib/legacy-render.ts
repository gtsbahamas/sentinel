import { db } from "./db";

// No LLM anywhere in this file. It has the scary shapes on purpose — the
// llm-features rules must not fire on code the model never touches.
export function renderBio(el: HTMLElement, bio: string) {
  el.innerHTML = bio;
}

export async function searchItems(term: string) {
  return db.query(`SELECT * FROM items WHERE name = '${term}'`);
}
