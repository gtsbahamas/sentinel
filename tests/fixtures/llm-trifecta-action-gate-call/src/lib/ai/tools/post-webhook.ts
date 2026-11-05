import { tool } from "ai";
import { z } from "zod";
import { actionGate } from "@/lib/action-gate";

export const postWebhook = tool({
  description: "Send a JSON payload to a webhook URL",
  parameters: z.object({ url: z.string(), payload: z.string() }),
  execute: async ({ url, payload }) => {
    // SAFE: Seatrial Action Gate waits for a person to approve the POST.
    const decision = await actionGate.request({ action: "post_webhook", args: { url, payload } });
    if (!decision.approved) return "denied";
    const res = await fetch(url, { method: "POST", body: payload });
    return res.status;
  },
});
