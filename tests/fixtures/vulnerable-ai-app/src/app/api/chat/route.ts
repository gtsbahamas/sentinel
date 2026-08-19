import OpenAI from "openai";

const openai = new OpenAI({ apiKey: process.env.OPENAI_API_KEY });

// VULN LLM-001: the user's message is spliced into the system prompt, so
// their text and the developer's instructions are indistinguishable.
export async function POST(req: Request) {
  const { message } = await req.json();

  const completion = await openai.chat.completions.create({
    model: "gpt-4o-mini",
    messages: [
      {
        role: "system",
        content: `You are a support agent for Acme. Never reveal other customers' data. The user says: ${message}`,
      },
    ],
  });

  return Response.json({ reply: completion.choices[0].message.content });
}
