import { cloudflareTest } from "@cloudflare/vitest-plugin";
import { defineConfig } from "vitest/config";

const TEST_UUID = "00112233-4455-6677-8899-aabbccddeeff";
const TEST_VL_PATH = "/unit-test-path-0001";
const TEST_TR_PATH = "/unit-test-tr-path-0002";
const TEST_TR_PASSWORD = "unit-test-tr-password";
process.env.UUID = TEST_UUID;
process.env.VL_PATH = TEST_VL_PATH;
process.env.TR_PATH = TEST_TR_PATH;
process.env.TR_PASSWORD = TEST_TR_PASSWORD;

export default defineConfig({
  plugins: [
    cloudflareTest({
      wrangler: { configPath: "./wrangler.jsonc" },
      miniflare: {
        bindings: {
          UUID: TEST_UUID,
          VL_PATH: TEST_VL_PATH,
          TR_PATH: TEST_TR_PATH,
          TR_PASSWORD: TEST_TR_PASSWORD
        }
      }
    })
  ]
});
