import { streamText } from "ai";
import { openai } from "@ai-sdk/openai";
import { readInvoices } from "@/lib/ai/tools/read-invoices";
import { postWebhook } from "@/lib/ai/tools/post-webhook";
import { requestApproval } from "@/lib/action-gate";

// VULN LLM-006: a person approves starting the chat, not the POST. The
// planted instruction arrives inside the approved run, so the webhook tool
// still sends invoices to any URL without anyone seeing it.
export async function POST(req: Request) {
  const { messages } = await req.json();
  const approval = await requestApproval({ action: "start_chat" });
  if (!approval.approved) return new Response("denied", { status: 403 });
  const result = streamText({
    model: openai("gpt-4o-mini"),
    messages,
    tools: { readInvoices, postWebhook },
  });
  return result.toDataStreamResponse();
}
