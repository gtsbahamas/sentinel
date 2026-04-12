import { z } from "zod";
export const updateUserSchema = z.object({ name: z.string() });
