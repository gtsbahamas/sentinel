import { streamText } from "ai";
import { openai } from "@ai-sdk/openai";
import { readInvoices } from "@/lib/ai/tools/read-invoices";
import { postWebhook } from "@/lib/ai/tools/post-webhook";

// VULN LLM-006: the three legs are spread across the agent's tool modules.
// The route takes the end user's chat; one tool reads invoices, another
// POSTs to any URL the model picks.
export async function POST(req: Request) {
  const { messages } = await req.json();
  const result = streamText({
    model: openai("gpt-4o-mini"),
    messages,
    tools: { readInvoices, postWebhook },
  });
  return result.toDataStreamResponse();
}
