
import test from "node:test";
import assert from "node:assert/strict";
import { findServerPII } from "../src/routes/analyze.js";

test("detects email addresses", () => {
  assert.ok(findServerPII("Contact: testuser@example.com").includes("EMAIL"));
});

test("detects contextual passwords", () => {
  assert.ok(findServerPII("Password: DemoPass123!").includes("PASSWORD"));
});

test("detects API keys", () => {
  assert.ok(findServerPII("api_key: sk_test_example123").includes("API_KEY"));
});

test("detects verification codes", () => {
  assert.ok(findServerPII("verification code: 123456").includes("OTP"));
});

test("detects CVV values", () => {
  assert.ok(findServerPII("CVV: 123").includes("CVV"));
});

test("detects IPv4 addresses", () => {
  assert.ok(findServerPII("Server IP: 192.168.1.10").includes("IP_ADDRESS"));
});

test("allows ordinary page text", () => {
  assert.deepEqual(
    findServerPII("Welcome to the PrivacyLens homepage."),
    []
  );
});

test("handles empty and invalid input", () => {
  assert.deepEqual(findServerPII(""), []);
  assert.deepEqual(findServerPII(null), []);
  assert.deepEqual(findServerPII(undefined), []);
});
