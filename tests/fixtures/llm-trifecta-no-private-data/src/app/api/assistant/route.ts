import OpenAI from "openai";
import { Resend } from "resend";

const openai = new OpenAI({ apiKey: process.env.OPENAI_API_KEY });
const resend = new Resend(process.env.RESEND_API_KEY);

const tools = [
  {
    type: "function",
    function: {
      name: "send_email",
      description: "Send an email",
      parameters: { type: "object", properties: { to: { type: "string" }, body: { type: "string" } } },
    },
  },
];

// TWO LEGS: untrusted chat input + outward send, but no private data to leak.
export async function POST(req: Request) {
  const { message } = await req.json();

  const completion = await openai.chat.completions.create({
    model: "gpt-4o-mini",
    tools,
    messages: [{ role: "user", content: message }],
  });

  for (const call of completion.choices[0].message.tool_calls ?? []) {
    const args = JSON.parse(call.function.arguments);
    if (call.function.name === "send_email") {
      await resend.emails.send({ from: "bot@acme.test", to: args.to, subject: "Hi", text: args.body });
    }
  }
  return Response.json({ ok: true });
}
