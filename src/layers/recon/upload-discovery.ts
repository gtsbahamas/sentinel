import { safeReadFile } from "../../utils/fs.js";
import type { UploadHandler } from "../../model/types.js";

const UPLOAD_SIGNALS = [
  /formData\s*\(\s*\)/,
  /\.formData\s*\(\s*\)/,
  /multer/,
  /multipart/,
  /\.upload\s*\(/,
];

export async function discoverUploadHandlers(files: string[]): Promise<UploadHandler[]> {
  const handlers: UploadHandler[] = [];

  for (const file of files) {
    if (!/\.(ts|tsx|js|jsx)$/.test(file)) continue;

    const source = await safeReadFile(file);
    const acceptsMultipart = UPLOAD_SIGNALS.some((rx) => rx.test(source));
    if (!acceptsMultipart) continue;

    const hasMimeValidation = /content-?type|mimetype|\.type\s*===|\.type\s*==\s*/i.test(source);
    const hasSizeLimit = /\.size\s*[<>=]|MAX_|SIZE_LIMIT|maxSize/i.test(source);
    const usesUserFilename = /formData\.get\(\s*["']filename["']|\.name\s*\|\|\s*["']|userFilename/.test(source);

    let storageDestination: UploadHandler["storageDestination"] = null;
    if (/supabase\.storage/.test(source)) storageDestination = "supabase";
    else if (/S3Client|aws-sdk\/client-s3|\.putObject/.test(source)) storageDestination = "s3";
    else if (/fs\.writeFile|fs\.createWriteStream/.test(source)) storageDestination = "local";

    const uploadLine = source.split("\n").findIndex((l) => UPLOAD_SIGNALS.some((rx) => rx.test(l)));

    handlers.push({
      file,
      line: uploadLine + 1,
      acceptsMultipart,
      hasMimeValidation,
      hasSizeLimit,
      usesUserFilename,
      storageDestination,
    });
  }

  return handlers;
}
