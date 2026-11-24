import * as readline from "node:readline";

const rl = readline.createInterface({
  input: process.stdin,
  terminal: false,
});

rl.on("line", (line) => {
  const trimmed = line.trim();
  if (!trimmed) return;

  try {
    const req = JSON.parse(trimmed);

    // If request has an id, return a response frame
    if (req.id !== undefined && req.id !== null) {
      const resp = {
        jsonrpc: "2.0",
        id: req.id,
        result: {
          status: "MOCK_SUCCESS",
          echoMethod: req.method,
          echoParams: req.params,
        },
      };
      process.stdout.write(JSON.stringify(resp) + "\n");
    }
  } catch (err) {
    process.stderr.write(`Mock error: ${err.message}\n`);
  }
});
