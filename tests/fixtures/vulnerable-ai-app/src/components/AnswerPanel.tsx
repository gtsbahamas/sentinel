import OpenAI from "openai";

const openai = new OpenAI({ apiKey: process.env.OPENAI_API_KEY });

// VULN LLM-003: whatever the model writes is rendered as live HTML.
export async function AnswerPanel({ question }: { question: string }) {
  const completion = await openai.chat.completions.create({
    model: "gpt-4o-mini",
    messages: [{ role: "user", content: question }],
  });
  const answer = completion.choices[0].message.content ?? "";

  return <div className="answer" dangerouslySetInnerHTML={{ __html: answer }} />;
}
