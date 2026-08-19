import DOMPurify from "isomorphic-dompurify";
import { marked } from "marked";
import OpenAI from "openai";

const openai = new OpenAI({ apiKey: process.env.OPENAI_API_KEY });

// SAFE: model output is rendered through markdown, then sanitized before it
// ever reaches the DOM.
export async function AnswerPanel({ question }: { question: string }) {
  const completion = await openai.chat.completions.create({
    model: "gpt-4o-mini",
    messages: [{ role: "user", content: question }],
  });
  const answer = completion.choices[0].message.content ?? "";
  const html = DOMPurify.sanitize(marked.parse(answer) as string);

  return <div className="answer" dangerouslySetInnerHTML={{ __html: html }} />;
}
