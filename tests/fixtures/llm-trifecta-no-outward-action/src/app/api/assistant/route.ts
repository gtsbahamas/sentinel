import OpenAI from "openai";
import { createClient } from "@supabase/supabase-js";

const openai = new OpenAI({ apiKey: process.env.OPENAI_API_KEY });
const supabase = createClient(process.env.SUPABASE_URL!, process.env.SUPABASE_SERVICE_ROLE_KEY!);

const tools = [
  {
    type: "function",
    function: {
      name: "lookup_customer",
      description: "Look up a customer record by email",
      parameters: { type: "object", properties: { email: { type: "string" } } },
    },
  },
];

// TWO LEGS: private data + untrusted chat input, but the agent can only
// read and answer. It has no way to send anything out.
export async function POST(req: Request) {
  const { message } = await req.json();

  const completion = await openai.chat.completions.create({
    model: "gpt-4o-mini",
    tools,
    messages: [{ role: "user", content: message }],
  });

  for (const call of completion.choices[0].message.tool_calls ?? []) {
    const args = JSON.parse(call.function.arguments);
    if (call.function.name === "lookup_customer") {
      const { data } = await supabase.from("customers").select("*").eq("email", args.email);
      return Response.json({ data });
    }
  }
  return Response.json({ ok: true });
}
