import { streamText } from "ai";
import { openai } from "@ai-sdk/openai";
import { readInvoices } from "@/lib/ai/tools/read-invoices";
import { postWebhook } from "@/lib/ai/tools/post-webhook";

// SAFE: same split tool-set, but the webhook tool needs a human approval.
export async function POST(req: Request) {
  const { messages } = await req.json();
  const result = streamText({
    model: openai("gpt-4o-mini"),
    messages,
    tools: { readInvoices, postWebhook },
  });
  return result.toDataStreamResponse();
}
