
import { getFaceDetector } from "../mediapipe/face-detector.js";

export async function drawRedactBox(dataUrl, resultArr = []) {
  let bitmap;

  try {
    if (typeof dataUrl !== "string" || !dataUrl.startsWith("data:image/")) {
      throw new Error("Invalid screenshot input");
    }

    const response = await fetch(dataUrl);

    if (!response.ok) {
      throw new Error("Could not read screenshot");
    }

    const blob = await response.blob();
    bitmap = await createImageBitmap(blob);

    const canvas = document.createElement("canvas");
    canvas.width = bitmap.width;
    canvas.height = bitmap.height;

    const ctx = canvas.getContext("2d");

    if (!ctx) {
      throw new Error("Canvas context unavailable");
    }

    // Draw the original screenshot onto a private working canvas.
    ctx.drawImage(bitmap, 0, 0);

    // Face detection must complete before the image can be returned.
    const faceDetector = await getFaceDetector();

    if (!faceDetector || typeof faceDetector.detect !== "function") {
      throw new Error("Face detector unavailable");
    }

    const faceResults = faceDetector.detect(canvas);
    const detections = faceResults?.detections;

    if (!Array.isArray(detections)) {
      throw new Error("Invalid face detection result");
    }

    // Redact detected text/PII regions.
    ctx.filter = "none";
    ctx.fillStyle = "#181818";

    for (const result of resultArr) {
      const box = result?.box;

      if (!box) continue;

      const x = Math.max(0, box.x);
      const y = Math.max(0, box.y);
      const width = Math.min(canvas.width - x, box.width);
      const height = Math.min(canvas.height - y, box.height);

      if (width <= 0 || height <= 0) continue;

      const vTrim = Math.round(height * 0.18);

      ctx.fillRect(
        x,
        y + vTrim,
        width,
        Math.max(2, height - vTrim * 2)
      );
    }

    // Blur every detected face.
    for (const detection of detections) {
      const box = detection?.boundingBox;

      if (!box) {
        throw new Error("Invalid face bounding box");
      }

      const padX = box.width * 0.15;
      const padY = box.height * 0.2;

      const x = Math.max(0, Math.floor(box.originX - padX));
      const y = Math.max(0, Math.floor(box.originY - padY));

      const right = Math.min(
        canvas.width,
        Math.ceil(box.originX + box.width + padX)
      );

      const bottom = Math.min(
        canvas.height,
        Math.ceil(box.originY + box.height + padY)
      );

      const width = right - x;
      const height = bottom - y;

      if (width <= 0 || height <= 0) {
        throw new Error("Invalid face region");
      }

      ctx.save();
      ctx.beginPath();
      ctx.rect(x, y, width, height);
      ctx.clip();
      ctx.filter = "blur(22px)";
      ctx.drawImage(bitmap, 0, 0);
      ctx.restore();
    }

    // Export only the sanitized canvas.
    return canvas.toDataURL("image/png");

  } catch (error) {
    console.error("Privacy redaction failed:", error);

    // Never return the original screenshot on failure.
    throw new Error(
      "Screenshot sanitization failed. Original image must not be transmitted."
    );

  } finally {
    if (bitmap) {
      bitmap.close();
    }
  }
}
