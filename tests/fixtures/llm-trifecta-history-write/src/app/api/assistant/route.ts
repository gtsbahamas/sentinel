import { generateText, tool } from "ai";
import { openai } from "@ai-sdk/openai";
import { z } from "zod";
import { prisma } from "@/lib/prisma";

// TWO LEGS: the agent reads private data and takes the user's chat, and its
// only tool is read-only. The app saves the conversation afterwards, but the
// model cannot reach that write, so nothing can be sent out.
export async function POST(req: Request) {
  const { chatId, message } = await req.json();
  const history = await prisma.chatMessage.findMany({ where: { chatId } });

  const result = await generateText({
    model: openai("gpt-4o-mini"),
    messages: [...history, { role: "user", content: message }],
    tools: {
      lookupOrder: tool({
        description: "Look up an order",
        parameters: z.object({ orderId: z.string() }),
        execute: async ({ orderId }) => {
          return prisma.order.findUnique({ where: { id: orderId } });
        },
      }),
    },
  });

  await prisma.chatMessage.create({ data: { chatId, role: "assistant", content: result.text } });
  return Response.json({ text: result.text });
}
