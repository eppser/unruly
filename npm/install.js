#!/usr/bin/env node
// Fetch the unruly binary for this platform from the matching GitHub release.
//
// The binary is NOT vendored into the package. Five platform builds are ~62MB
// and npm would carry all of them to every install; the release already hosts
// them, so this downloads the one that runs here.
//
// The download is verified against a checksum published in the same release
// and pinned into this package at publish time. A scanner that installs
// whatever bytes the network returned would be an odd thing to trust with your
// database, so a mismatch fails the install rather than warning about it.
"use strict";

const fs = require("fs");
const path = require("path");
const https = require("https");
const crypto = require("crypto");
const { version, unrulyChecksums } = require("./package.json");

const TARGETS = {
  "darwin-x64": "unruly_darwin_amd64",
  "darwin-arm64": "unruly_darwin_arm64",
  "linux-x64": "unruly_linux_amd64",
  "linux-arm64": "unruly_linux_arm64",
  "win32-x64": "unruly_windows_amd64.exe",
};

const key = `${process.platform}-${process.arch}`;
const asset = TARGETS[key];

if (!asset) {
  console.error(
    `unruly: no prebuilt binary for ${key}.\n` +
      `Supported: ${Object.keys(TARGETS).join(", ")}\n` +
      `Build from source instead:  go install github.com/eppser/unruly/cmd/unruly@latest`
  );
  process.exit(1);
}

const tag = `v${version}`;
const url = `https://github.com/eppser/unruly/releases/download/${tag}/${asset}`;
const outDir = path.join(__dirname, "bin");
const outFile = path.join(outDir, process.platform === "win32" ? "unruly.exe" : "unruly");

function get(u, redirects = 0) {
  return new Promise((resolve, reject) => {
    if (redirects > 5) return reject(new Error("too many redirects"));
    https
      .get(u, { headers: { "User-Agent": "unruly-npm-installer" } }, (res) => {
        if ([301, 302, 307, 308].includes(res.statusCode)) {
          res.resume();
          return resolve(get(res.headers.location, redirects + 1));
        }
        if (res.statusCode !== 200) {
          res.resume();
          return reject(new Error(`HTTP ${res.statusCode} for ${u}`));
        }
        const chunks = [];
        res.on("data", (c) => chunks.push(c));
        res.on("end", () => resolve(Buffer.concat(chunks)));
        res.on("error", reject);
      })
      .on("error", reject);
  });
}

(async () => {
  try {
    process.stdout.write(`unruly: downloading ${asset} (${tag})… `);
    const body = await get(url);

    const want = (unrulyChecksums || {})[asset];
    const got = crypto.createHash("sha256").update(body).digest("hex");
    if (!want) {
      throw new Error(
        `no checksum published for ${asset}; refusing to install an unverified binary`
      );
    }
    if (want !== got) {
      throw new Error(
        `checksum mismatch for ${asset}\n  expected ${want}\n  received ${got}\n` +
          `Refusing to install. Report this: https://github.com/eppser/unruly/security`
      );
    }

    fs.mkdirSync(outDir, { recursive: true });
    fs.writeFileSync(outFile, body, { mode: 0o755 });
    console.log("ok");
  } catch (err) {
    console.error(
      `\nunruly: install failed — ${err.message}\n` +
        `You can always build from source:\n` +
        `  go install github.com/eppser/unruly/cmd/unruly@latest`
    );
    process.exit(1);
  }
})();
