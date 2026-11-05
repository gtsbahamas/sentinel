import { streamText } from "ai";
import { openai } from "@ai-sdk/openai";
import { readInvoices } from "@/lib/ai/tools/read-invoices";
import { postWebhook } from "@/lib/ai/tools/post-webhook";
import { actionGate } from "@/lib/action-gate";

// SAFE: the route hands the model the webhook tool only through Seatrial
// Action Gate, which holds each call until a person approves it.
export async function POST(req: Request) {
  const { messages } = await req.json();
  const result = streamText({
    model: openai("gpt-4o-mini"),
    messages,
    tools: { readInvoices, postWebhook: actionGate.wrap(postWebhook) },
  });
  return result.toDataStreamResponse();
}
