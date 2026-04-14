import { z } from "zod";

const SeveritySchema = z.enum(["critical", "high", "medium", "low", "info"]);

const BaseVerdictSchema = z.object({
  findingId: z.string().min(1),
  reason: z.string().min(1),
});

export const VerdictSchema = z.discriminatedUnion("decision", [
  BaseVerdictSchema.extend({
    decision: z.literal("confirm"),
    newSeverity: SeveritySchema.optional(),
  }),
  BaseVerdictSchema.extend({
    decision: z.literal("dismiss"),
    newSeverity: SeveritySchema.optional(),
  }),
  BaseVerdictSchema.extend({
    decision: z.literal("downgrade"),
    // downgrade must include the new severity
    newSeverity: SeveritySchema,
  }),
]);

export const VerdictListSchema = z.object({
  verdicts: z.array(VerdictSchema),
});

export type VerdictInput = z.input<typeof VerdictSchema>;
export type VerdictParsed = z.infer<typeof VerdictSchema>;
