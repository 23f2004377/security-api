const express = require("express");
const app = express();

app.use(express.json());

// =================================
// CORS SUPPORT
// =================================
app.use((req, res, next) => {
  res.header("Access-Control-Allow-Origin", "*");
  res.header("Access-Control-Allow-Headers", "Origin, X-Requested-With, Content-Type, Accept");
  res.header("Access-Control-Allow-Methods", "GET, POST, OPTIONS");
  next();
});

// EXPRESS v5 SAFE OPTIONS HANDLER
app.use((req, res, next) => {
  if (req.method === "OPTIONS") {
    return res.sendStatus(200);
  }
  next();
});

// =================================
// HEALTH CHECK
// =================================
app.get("/", (req, res) => {
  res.status(200).send("Service running");
});

// =================================
// RATE LIMIT CONFIG
// =================================
const PORT = process.env.PORT || 3000;
const RATE_PER_MIN = 31;
const BURST = 10;
const REFILL_PER_MS = RATE_PER_MIN / 60000;

const buckets = new Map();

// =================================
// HELPERS
// =================================
function getKey(req) {
  return (req.body && req.body.userId) || req.ip;
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

// =================================
// RATE LIMIT MIDDLEWARE
// =================================
function rateLimit(req, res, next) {
  try {
    const key = getKey(req);
    const bucket = getBucket(key);

    refill(bucket);

    if (bucket.tokens < 1) {
      const waitSeconds = Math.ceil(
        (1 - bucket.tokens) / REFILL_PER_MS / 1000
      );

      console.log("SECURITY EVENT:", {
        type: "RATE_LIMIT_BLOCK",
        key,
        time: new Date().toISOString()
      });

      return res
        .status(429)
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
  } catch (err) {
    console.error("Validation error:", err);

    return res.status(400).json({
      blocked: true,
      reason: "Validation error",
      sanitizedOutput: null,
      confidence: 0.8
    });
  }
}

// =================================
// SECURITY ENDPOINT
// =================================
app.post("/security", rateLimit, (req, res) => {
  try {
    const { userId, input, category } = req.body || {};

    if (!userId || !input || !category) {
      return res.status(400).json({
        blocked: true,
        reason: "Missing required fields",
        sanitizedOutput: null,
        confidence: 0.9
      });
    }

    // basic output sanitization
    const sanitized = String(input).replace(
      /<script.*?>.*?<\/script>/gi,
      ""
    );

    return res.json({
      blocked: false,
      reason: "Input passed all security checks",
      sanitizedOutput: sanitized,
      confidence: 0.95
    });

  } catch (err) {
    console.error("Processing error:", err);

    return res.status(400).json({
      blocked: true,
      reason: "Processing error",
      sanitizedOutput: null,
      confidence: 0.7
    });
  }
});

// =================================
// START SERVER
// =================================
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
