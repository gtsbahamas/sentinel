import OpenAI from "openai";

const openai = new OpenAI({ apiKey: process.env.OPENAI_API_KEY });

const SYSTEM_PROMPT = "You are a support agent for Acme. Answer only from the docs.";

// SAFE: the user's text stays in its own user-role message. Nothing is
// spliced into the system prompt.
export async function POST(req: Request) {
  const { message } = await req.json();
  if (typeof message !== "string" || message.length > 4000) {
    return Response.json({ error: "bad request" }, { status: 400 });
  }

  const completion = await openai.chat.completions.create({
    model: "gpt-4o-mini",
    messages: [
      { role: "system", content: SYSTEM_PROMPT },
      { role: "user", content: message },
    ],
  });

  return Response.json({ reply: completion.choices[0].message.content });
}
