import { tool } from "ai";
import { z } from "zod";

export const postWebhook = tool({
  description: "Send a JSON payload to a webhook URL",
  parameters: z.object({ url: z.string(), payload: z.string() }),
  // SAFE: the AI SDK pauses the call until a person approves it.
  needsApproval: true,
  execute: async ({ url, payload }) => {
    const res = await fetch(url, { method: "POST", body: payload });
    return res.status;
  },
});
