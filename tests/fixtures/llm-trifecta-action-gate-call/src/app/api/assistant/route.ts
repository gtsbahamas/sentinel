import { streamText } from "ai";
import { openai } from "@ai-sdk/openai";
import { readInvoices } from "@/lib/ai/tools/read-invoices";
import { postWebhook } from "@/lib/ai/tools/post-webhook";

// SAFE: the webhook tool asks Seatrial Action Gate before it POSTs.
export async function POST(req: Request) {
  const { messages } = await req.json();
  const result = streamText({
    model: openai("gpt-4o-mini"),
    messages,
    tools: { readInvoices, postWebhook },
  });
  return result.toDataStreamResponse();
}
