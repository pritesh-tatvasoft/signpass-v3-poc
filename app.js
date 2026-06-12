const express = require("express");
const config = require("./config.json");
const { readFileSync } = require("node:fs");
const path = require("node:path");
const NodeCache = require("node-cache");
const assert = require("node:assert");

// jose v6 is ESM-only, so we use dynamic import() for Vercel compatibility
let _jose;
const getJose = async () => {
  if (!_jose) _jose = await import("jose");
  return _jose;
};

const axios = require("axios").create({ baseURL: config.SIGN_BASE_URL });
const cache = new NodeCache({ stdTTL: 5400 });
const app = express();

app.use(express.json());

const createJwt = async (payload) => {
  const { SignJWT, importJWK } = await getJose();
  return new SignJWT(payload)
    .setIssuedAt()
    .setProtectedHeader({
      alg: "ES256",
      kid: config.CLIENT_PRIVATE_KEY.kid,
    })
    .setJti(crypto.randomUUID())
    .setExpirationTime("120s")
    .sign(await importJWK(config.CLIENT_PRIVATE_KEY));
};

app.use(express.static("frontend"));

app.get("/sign", async (req, res) => {
  try {
    const payload = {
      x: 0.5,
      y: 0.5,
      page: 1,
      doc_name: "dummy.pdf",
      client_id: config.CLIENT_ID,
    };

    const createSignRequestResponse = await axios.post(
      "/sign-requests",
      readFileSync(path.join(__dirname, "dummy.pdf")),
      {
        headers: {
          "Content-Type": "application/octet-stream",
          Authorization: await createJwt(payload),
        },
      },
    );

    const { signing_url, request_id, exchange_code } =
      createSignRequestResponse.data;

    cache.set(`exchange_code::${request_id}`, exchange_code);

    return res.redirect(signing_url);
  } catch (error) {
    console.error("Sign request failed:", error.response?.data || error.message);
    return res.status(500).json({
      error: "Failed to create sign request",
      details: error.response?.data || error.message,
    });
  }
});

app.get("/sign-requests/:request_id", async (req, res) => {
  try {
    const { request_id } = req.params;

    const exchange_code = cache.get(`exchange_code::${request_id}`);
    if (!exchange_code) {
      return res.status(400).json({
        error: "Exchange code not found or expired",
        details: "The signing session may have expired. Please try again.",
      });
    }

    const {
      data: { signed_doc_url },
    } = await axios.get(`/sign-requests/${request_id}/signed_doc`, {
      headers: { Authorization: await createJwt({ exchange_code }) },
    });

    const file = await axios.get(signed_doc_url, {
      responseType: "arraybuffer",
    });

    res.setHeader(
      "Content-Disposition",
      `attachment; filename="signed_${request_id}.pdf"`,
    );
    res.setHeader("Content-Type", "application/pdf");
    return res.send(Buffer.from(file.data));
  } catch (error) {
    console.error(
      "Get signed doc failed:",
      error.response?.data || error.message,
    );
    return res.status(500).json({
      error: "Failed to get signed document",
      details: error.response?.data || error.message,
    });
  }
});

app.get("/jwks", (req, res) => {
  const { d, ...publicJwk } = { ...config.CLIENT_PRIVATE_KEY };
  return res.status(200).json({ keys: [publicJwk] });
});

app.post("/webhook", async (req, res) => {
  const token = req.body.token;
  assert(token);

  const { jwtVerify, createRemoteJWKSet } = await getJose();
  const { payload } = await jwtVerify(
    token,
    createRemoteJWKSet(new URL(config.SIGN_JWKS_URL)),
  );
  console.log("Webhook received:", payload);
  return res.status(200).send("OK");
});

if (require.main === module) {
  app.listen(config.PORT, () => {
    console.log(`App started, go to http://localhost:${config.PORT}`);
  });
}

module.exports = app;
