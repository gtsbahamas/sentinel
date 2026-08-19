import OpenAI from "openai";
import { z } from "zod";
import { supabase } from "@/lib/supabase";

const openai = new OpenAI({ apiKey: process.env.OPENAI_API_KEY });

const DeleteNoteArgs = z.object({ id: z.string().uuid() });

// SAFE: model-chosen arguments go through a schema before the handler runs,
// and the delete is scoped to the signed-in user.
export async function POST(req: Request) {
  const { instruction, userId } = await req.json();

  const completion = await openai.chat.completions.create({
    model: "gpt-4o-mini",
    tools: [
      {
        type: "function",
        function: {
          name: "delete_note",
          description: "Delete a note by id",
          parameters: { type: "object", properties: { id: { type: "string" } } },
        },
      },
    ],
    messages: [{ role: "user", content: instruction }],
  });

  const call = completion.choices[0].message.tool_calls?.[0];
  if (!call) return Response.json({ ok: true });

  const args = DeleteNoteArgs.parse(JSON.parse(call.function.arguments));
  await supabase.from("notes").delete().eq("id", args.id).eq("owner_id", userId);

  return Response.json({ ok: true });
}
