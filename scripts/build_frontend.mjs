import { cp, mkdir, rm, writeFile } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";

const projectRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const sourceDirectory = path.join(projectRoot, "frontend");
const outputDirectory = path.join(projectRoot, "dist");
const configuredApiUrl = (process.env.THREATLENS_API_BASE_URL || "").trim().replace(/\/+$/, "");

if (process.env.VERCEL === "1" && !configuredApiUrl) {
  throw new Error("Set THREATLENS_API_BASE_URL to the deployed HTTPS API origin in Vercel.");
}

if (configuredApiUrl) {
  let apiUrl;
  try {
    apiUrl = new URL(configuredApiUrl);
  } catch {
    throw new Error("THREATLENS_API_BASE_URL must be an absolute API origin.");
  }
  if (
    !["http:", "https:"].includes(apiUrl.protocol) ||
    apiUrl.username ||
    apiUrl.password ||
    apiUrl.pathname !== "/" ||
    apiUrl.search ||
    apiUrl.hash ||
    (process.env.VERCEL === "1" && apiUrl.protocol !== "https:")
  ) {
    throw new Error("THREATLENS_API_BASE_URL must be an HTTPS origin without a path in Vercel.");
  }
}

await rm(outputDirectory, { recursive: true, force: true });
await mkdir(outputDirectory, { recursive: true });
await cp(sourceDirectory, outputDirectory, { recursive: true });
await writeFile(
  path.join(outputDirectory, "deployment-config.js"),
  `window.THREATLENS_API_BASE_URL = ${JSON.stringify(configuredApiUrl)};\n`,
  "utf8",
);
console.log(`Built frontend in ${path.relative(projectRoot, outputDirectory)}.`);
