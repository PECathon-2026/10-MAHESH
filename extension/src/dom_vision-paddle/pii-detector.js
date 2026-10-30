import { getPIIModel } from "./pii-ner.js";
import { aggregatePIIEntities } from "./aggregateEntities.js";

const NER_THRESHOLD = 0.9;
// Additional deterministic privacy detection rules
const EMAIL_REGEX =
  /\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b/i;

const PHONE_REGEX =
  /(?:\+?\d{1,3}[-.\s]?)?(?:\(?\d{3,5}\)?[-.\s]?)\d{3,5}[-.\s]?\d{3,5}\b/;

const PASSWORD_CONTEXT_REGEX =
  /\b(?:password|passwd|passphrase|secret)\s*[:=]\s*\S+/i;

const CARD_CONTEXT_REGEX =
  /\b(?:card(?:\s*number)?|credit\s*card|debit\s*card)\s*[:=]?\s*(?:\d[ -]?){13,19}\b/i;

const API_KEY_REGEX =
  /\b(?:api[_-]?key|access[_-]?token|auth[_-]?token|secret[_-]?key)\s*[:=]\s*\S+/i;

const IPV4_REGEX =
  /\b(?:\d{1,3}\.){3}\d{1,3}\b/;

const PIN_REGEX = /\b[1-9][0-9]{5}\b/;

const CONTEXTUAL_NAME_REGEX =
  /\b(?:hello|welcome|deliver\s+to|ship\s+to)(?:\s*[,:]\s*|\s+)[a-zA-Z]+(?:['’–-][a-zA-Z]+)*(?:\s+[a-zA-Z]+(?:['’–-][a-zA-Z]+)*){0,3}\b/i;

const CONTEXTUAL_PIN_REGEX =
  /\b(?:(?:pin|passcode)[\s:\-–—]+\d{4,6}|\d{4,6}[\s:\-–—]+(?:pin|passcode))\b/i;

const CONTEXTUAL_OTP_REGEX =
  /\b(?:(?:otp|one[- ]?time[- ]?code|verification[- ]?code)[\s:\-–—]+\d{4,8}|\d{4,8}[\s:\-–—]+(?:otp|one[- ]?time[- ]?code|verification[- ]?code))\b/i;

const CONTEXTUAL_CVV_REGEX =
  /\b(?:(?:cvv|cvc|cid|security[- ]?code)[\s:\-–—]+\d{3,4}|\d{3,4}[\s:\-–—]+(?:cvv|cvc|cid|security[- ]?code))\b/i;

export function detectDeterministicPII(text) {
  if (typeof text !== "string" || !text.trim()) {
    return [];
  }

  const entities = [];
    if (EMAIL_REGEX.test(text)) {
    entities.push({ entity: "EMAIL", score: 1.0 });
  }

  if (PHONE_REGEX.test(text)) {
    entities.push({ entity: "PHONE", score: 1.0 });
  }

  if (PASSWORD_CONTEXT_REGEX.test(text)) {
    entities.push({ entity: "PASSWORD", score: 1.0 });
  }

  if (CARD_CONTEXT_REGEX.test(text)) {
    entities.push({ entity: "CARD_NUMBER", score: 1.0 });
  }

  if (API_KEY_REGEX.test(text)) {
    entities.push({ entity: "API_KEY", score: 1.0 });
  }

  if (IPV4_REGEX.test(text)) {
    entities.push({ entity: "IP_ADDRESS", score: 1.0 });
  }

  if (PIN_REGEX.test(text)) {
    entities.push({
      entity: "PINCODE",
      score: 1.0,
    });
  }

  if (CONTEXTUAL_PIN_REGEX.test(text)) {
    entities.push({
      entity: "PIN",
      score: 1.0,
    });
  }

  if (CONTEXTUAL_OTP_REGEX.test(text)) {
    entities.push({
      entity: "OTP",
      score: 1.0,
    });
  }

  if (CONTEXTUAL_CVV_REGEX.test(text)) {
    entities.push({
      entity: "CVV",
      score: 1.0,
    });
  }

  if (CONTEXTUAL_NAME_REGEX.test(text)) {
    entities.push({
      entity: "NAME",
      score: 1.0,
    });
  }

  return entities;
}


export async function detectPII(items) {
  let model = null;

  try {
    model = await getPIIModel();
  } catch (err) {
    console.warn(
      "PII model unavailable; using deterministic detection."
    );
  }

  const results = [];

  for (const item of items) {
    if (!item || typeof item.text !== "string") {
      continue;
    }

    // Start with deterministic detections.
    // These run even when the AI model succeeds.
    const deterministicEntities =
      detectDeterministicPII(item.text);

    let modelEntities = [];

    if (model) {
      try {
        const tokens = await model(item.text);
        modelEntities =
          aggregatePIIEntities(tokens, NER_THRESHOLD);
      } catch (err) {
        console.warn("NER detection failed for an item.");
      }
    }

    // Merge both detection methods.
    const combinedEntities = [
      ...modelEntities,
      ...deterministicEntities,
    ];

    // Remove duplicate entity types.
    const uniqueEntities = [
      ...new Map(
        combinedEntities.map((entity) => [
          entity.entity,
          entity,
        ])
      ).values(),
    ];

    if (uniqueEntities.length === 0) {
      continue;
    }

    results.push({
      text: item.text,
      ocrConfidence: item.confidence,
      box: item.box,
      pii: uniqueEntities,
    });
  }

  return results;
}

