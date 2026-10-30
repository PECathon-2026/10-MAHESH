
import test from "node:test";
import assert from "node:assert/strict";
import { detectDeterministicPII } from "../src/dom_vision-paddle/pii-detector.js";

const detectedTypes = (text) =>
  detectDeterministicPII(text).map((item) => item.entity);

test("detects email addresses", () => {
  assert.ok(detectedTypes("Contact: testuser@example.com").includes("EMAIL"));
});

test("detects phone numbers", () => {
  assert.ok(detectedTypes("Call: +91 9876543210").includes("PHONE"));
});

test("detects contextual passwords", () => {
  assert.ok(detectedTypes("Password: DemoPass123!").includes("PASSWORD"));
});

test("detects contextual card numbers", () => {
  assert.ok(detectedTypes("Card number: 4111111111111111").includes("CARD_NUMBER"));
});

test("detects contextual API keys", () => {
  assert.ok(detectedTypes("api_key: sk_test_example123").includes("API_KEY"));
});

test("detects IPv4 addresses", () => {
  assert.ok(detectedTypes("Server IP: 192.168.1.10").includes("IP_ADDRESS"));
});

test("detects contextual OTPs", () => {
  assert.ok(detectedTypes("OTP: 482916").includes("OTP"));
});

test("detects contextual CVVs", () => {
  assert.ok(detectedTypes("CVV: 123").includes("CVV"));
});

test("detects postal PIN codes", () => {
  assert.ok(detectedTypes("Postal code: 160001").includes("PINCODE"));
});

test("handles empty and invalid inputs", () => {
  assert.deepEqual(detectDeterministicPII(""), []);
  assert.deepEqual(detectDeterministicPII(null), []);
});
