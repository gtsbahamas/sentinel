import { streamText } from "ai";
import { openai } from "@ai-sdk/openai";
import { readInvoices } from "@/lib/ai/tools/read-invoices";
import { postWebhook } from "@/lib/ai/tools/post-webhook";

// VULN LLM-006: the invoice read needs approval, but the webhook POST does
// not, so a planted instruction can still send invoices to any URL.
export async function POST(req: Request) {
  const { messages } = await req.json();
  const result = streamText({
    model: openai("gpt-4o-mini"),
    messages,
    tools: { readInvoices, postWebhook },
  });
  return result.toDataStreamResponse();
}
