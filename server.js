const express = require("express");
const app = express();
app.use(express.json());

const PORT = process.env.PORT || 3000;

const RATE_PER_MIN = 31;
const BURST = 10;
const REFILL_PER_MS = RATE_PER_MIN / 60000;

const buckets = new Map();

function getKey(req) {
  return req.body.userId || req.ip;
}

function getBucket(key) {
  if (!buckets.has(key)) {
    buckets.set(key, {
      tokens: BURST,
      lastRefill: Date.now()
    });
  }
  return buckets.get(key);
}

function refill(bucket) {
  const now = Date.now();
  const elapsed = now - bucket.lastRefill;
  const refillAmount = elapsed * REFILL_PER_MS;
  bucket.tokens = Math.min(BURST, bucket.tokens + refillAmount);
  bucket.lastRefill = now;
}

function rateLimit(req, res, next) {
  try {
    const key = getKey(req);
    const bucket = getBucket(key);
    refill(bucket);

    if (bucket.tokens < 1) {
      const waitSeconds = Math.ceil((1 - bucket.tokens) / REFILL_PER_MS / 1000);

      console.log("SECURITY EVENT:", {
        type: "RATE_LIMIT_BLOCK",
        key,
        time: new Date().toISOString()
      });

      return res.status(429)
        .set("Retry-After", waitSeconds)
        .json({
          blocked: true,
          reason: "Rate limit exceeded",
          sanitizedOutput: null,
          confidence: 0.99
        });
    }

    bucket.tokens -= 1;
    next();

  } catch {
    return res.status(400).json({
      blocked: true,
      reason: "Validation error",
      sanitizedOutput: null,
      confidence: 0.8
    });
  }
}

app.post("/security", rateLimit, (req, res) => {
  const { userId, input, category } = req.body;

  if (!userId || !input || !category) {
    return res.status(400).json({
      blocked: true,
      reason: "Missing required fields",
      sanitizedOutput: null,
      confidence: 0.9
    });
  }

  const sanitized = input.replace(/<script.*?>.*?<\/script>/gi, "");

  res.json({
    blocked: false,
    reason: "Input passed all security checks",
    sanitizedOutput: sanitized,
    confidence: 0.95
  });
});

app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
