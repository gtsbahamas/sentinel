import pino from "pino";

export const logger = pino({
  level: process.env.SENTINEL_LOG_LEVEL ?? "info",
  transport: {
    target: "pino-pretty",
    options: { colorize: true, translateTime: "HH:MM:ss" },
  },
});
