
import test from "node:test";
import assert from "node:assert/strict";

import {
  sanitizeOcrText,
} from "../src/dom_vision-paddle/buildPrivateContext.js";

test("redacts a detected email line", () => {
  const email = "testuser@example.com";

  const result = sanitizeOcrText(
    [{ text: `Email: ${email}`, box: "line-1" }],
    [{ box: "line-1" }]
  );

  assert.equal(result, "[REDACTED]");
  assert.equal(result.includes(email), false);
});

test("redacts a detected password line", () => {
  const password = "DemoPass123!";

  const result = sanitizeOcrText(
    [{ text: `Password: ${password}`, box: "line-2" }],
    [{ box: "line-2" }]
  );

  assert.equal(result, "[REDACTED]");
  assert.equal(result.includes(password), false);
});

test("preserves a line with no detected sensitive information", () => {
  const result = sanitizeOcrText(
    [{ text: "Welcome to PrivacyLens", box: "line-3" }],
    []
  );

  assert.equal(result, "Welcome to PrivacyLens");
});

test("redacts multiple detected lines", () => {
  const email = "testuser@example.com";
  const password = "DemoPass123!";

  const result = sanitizeOcrText(
    [
      { text: `Email: ${email}`, box: "line-1" },
      { text: `Password: ${password}`, box: "line-2" },
      { text: "Welcome to PrivacyLens", box: "line-3" },
    ],
    [
      { box: "line-1" },
      { box: "line-2" },
    ]
  );

  assert.equal(result.includes(email), false);
  assert.equal(result.includes(password), false);
  assert.ok(result.includes("[REDACTED]"));
  assert.ok(result.includes("Welcome to PrivacyLens"));
});
