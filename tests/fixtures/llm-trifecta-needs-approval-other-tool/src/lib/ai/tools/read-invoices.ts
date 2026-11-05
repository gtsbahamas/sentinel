import { tool } from "ai";
import { z } from "zod";
import { createClient } from "@supabase/supabase-js";

const supabase = createClient(process.env.SUPABASE_URL!, process.env.SUPABASE_SERVICE_ROLE_KEY!);

export const readInvoices = tool({
  description: "Read invoices for a customer",
  parameters: z.object({ customerId: z.string() }),
  needsApproval: true,
  execute: async ({ customerId }) => {
    const { data } = await supabase.from("invoices").select("*").eq("customer_id", customerId);
    return data;
  },
});
