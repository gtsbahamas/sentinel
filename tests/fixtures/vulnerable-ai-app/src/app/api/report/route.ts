import OpenAI from "openai";
import { db } from "@/lib/db";

const openai = new OpenAI({ apiKey: process.env.OPENAI_API_KEY });

// VULN LLM-004: the model writes SQL and the app runs it.
export async function GET() {
  const completion = await openai.chat.completions.create({
    model: "gpt-4o-mini",
    messages: [
      { role: "user", content: "Write a Postgres query returning last week's signups." },
    ],
  });
  const sql = completion.choices[0].message.content ?? "";

  const rows = await db.query(sql);
  return Response.json(rows);
}
