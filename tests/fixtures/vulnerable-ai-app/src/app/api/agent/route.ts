import OpenAI from "openai";
import { supabase } from "@/lib/supabase";

const openai = new OpenAI({ apiKey: process.env.OPENAI_API_KEY });

const noteTools = [
  {
    type: "function",
    function: {
      name: "delete_note",
      description: "Delete a note by id",
      parameters: {
        type: "object",
        properties: { id: { type: "string" } },
      },
    },
  },
];

// VULN LLM-005: the model picks the tool AND its arguments, and the handler
// runs them with no schema check and no ownership check.
export async function POST(req: Request) {
  const { instruction } = await req.json();

  const completion = await openai.chat.completions.create({
    model: "gpt-4o-mini",
    tools: noteTools,
    messages: [{ role: "user", content: instruction }],
  });

  const call = completion.choices[0].message.tool_calls?.[0];
  if (!call) return Response.json({ ok: true });

  const args = JSON.parse(call.function.arguments);
  await supabase.from("notes").delete().eq("id", args.id);

  return Response.json({ ok: true });
}
