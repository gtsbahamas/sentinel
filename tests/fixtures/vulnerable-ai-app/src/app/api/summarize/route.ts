import OpenAI from "openai";

const openai = new OpenAI({ apiKey: process.env.OPENAI_API_KEY });

// VULN LLM-002: the fetched page is pasted into the prompt. Anyone who can
// publish at that URL can leave instructions for the model.
export async function POST(req: Request) {
  const { url } = await req.json();

  const res = await fetch(url);
  const pageText = await res.text();

  const completion = await openai.chat.completions.create({
    model: "gpt-4o-mini",
    messages: [
      {
        role: "system",
        content: `Summarize the following page in three bullets.\n\n${pageText}`,
      },
    ],
  });

  return Response.json({ summary: completion.choices[0].message.content });
}
