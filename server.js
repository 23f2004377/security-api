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
// RATE LIMITING (CORRECT LOGIC)
// =================================
const PORT = process.env.PORT || 3000;

const rateStore = new Map();

const MAX_PER_MINUTE = 31;
const MAX_BURST = 10;
const MINUTE_WINDOW = 60 * 1000;
const BURST_WINDOW = 1000;

function rateLimit(req, res, next) {
  try {
    const key = (req.body && req.body.userId) || req.ip;
    const now = Date.now();

    if (!rateStore.has(key)) {
      rateStore.set(key, []);
    }

    const timestamps = rateStore.get(key);

    // remove old timestamps
    const lastMinute = timestamps.filter(t => now - t < MINUTE_WINDOW);
    const lastSecond = lastMinute.filter(t => now - t < BURST_WINDOW);

    // minute limit
    if (lastMinute.length >= MAX_PER_MINUTE) {
      const retry = Math.ceil((MINUTE_WINDOW - (now - lastMinute[0])) / 1000);

      console.log("SECURITY EVENT:", {
        type: "RATE_LIMIT_BLOCK_MINUTE",
        key,
        time: new Date().toISOString()
      });

      return res.status(429)
        .set("Retry-After", retry)
        .json({
          blocked: true,
          reason: "Rate limit exceeded (per minute)",
          sanitizedOutput: null,
          confidence: 0.99
        });
    }

    // burst limit
    if (lastSecond.length >= MAX_BURST) {
      const retry = Math.ceil((BURST_WINDOW - (now - lastSecond[0])) / 1000);

      console.log("SECURITY EVENT:", {
        type: "RATE_LIMIT_BLOCK_BURST",
        key,
        time: new Date().toISOString()
      });

      return res.status(429)
        .set("Retry-After", retry)
        .json({
          blocked: true,
          reason: "Rate limit exceeded (burst)",
          sanitizedOutput: null,
          confidence: 0.99
        });
    }

    // record request
    lastMinute.push(now);
    rateStore.set(key, lastMinute);

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
