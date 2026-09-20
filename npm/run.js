#!/usr/bin/env node
// Hand control to the real binary, unchanged.
//
// stdio is inherited so colours, the progress the scanner prints and a Ctrl-C
// all behave as if it had been run directly, and the child's exit code is
// propagated because unruly's codes are meaningful: 0 clean and fully
// measured, 2 findings at high or above, 3 something could not be assessed.
"use strict";
const { spawnSync } = require("child_process");
const path = require("path");
const fs = require("fs");

const bin = path.join(__dirname, "bin", process.platform === "win32" ? "unruly.exe" : "unruly");
if (!fs.existsSync(bin)) {
  console.error(
    "unruly: the binary is missing — the install step did not complete.\n" +
      "Reinstall, or build from source:\n" +
      "  go install github.com/eppser/unruly/cmd/unruly@latest"
  );
  process.exit(1);
}
const r = spawnSync(bin, process.argv.slice(2), { stdio: "inherit" });
process.exit(r.status === null ? 1 : r.status);
