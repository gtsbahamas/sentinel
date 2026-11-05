import OpenAI from "openai";
import { createClient } from "@supabase/supabase-js";
import { Resend } from "resend";
import { requestApproval } from "@/lib/action-gate";

const openai = new OpenAI({ apiKey: process.env.OPENAI_API_KEY });
const resend = new Resend(process.env.RESEND_API_KEY);
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
  {
    type: "function",
    function: {
      name: "send_email",
      description: "Send an email",
      parameters: { type: "object", properties: { to: { type: "string" }, body: { type: "string" } } },
    },
  },
];

// VULN LLM-006: an approval helper is defined but never called. Private data (customer rows via the service role) + untrusted
// input (the end user's chat message) + an outward action (send_email), and
// nothing stands between the model's choice and the send.
export async function POST(req: Request) {
  const { message } = await req.json();
  // Defined, never called: guards nothing.
  const askFirst = (args: unknown) => requestApproval({ action: "send_email", args });

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
    if (call.function.name === "send_email") {
      await resend.emails.send({ from: "bot@acme.test", to: args.to, subject: "Hi", text: args.body });
    }
  }
  return Response.json({ ok: true });
}
