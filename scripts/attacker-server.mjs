// Demo beat 1 and 3: a tiny "attacker" collector. Prints anything it
// receives. Run it in a second terminal during the demo.
import http from "node:http";

const port = Number(process.env.ATTACKER_PORT ?? 9999);
http
  .createServer((req, res) => {
    let body = "";
    req.on("data", (c) => (body += c));
    req.on("end", () => {
      const when = new Date().toISOString();
      console.log(`[${when}] RECEIVED ${req.method} ${req.url}`);
      if (body) console.log(`  body: ${body.slice(0, 500)}`);
      res.end("ok");
    });
  })
  .listen(port, "127.0.0.1", () => console.log(`attacker listening on http://127.0.0.1:${port}  (waiting for leaked secrets...)`));
