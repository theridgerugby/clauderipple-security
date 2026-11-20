// A disposable, real two-process diagnostic fixture. Both processes expire independently even
// if a cleanup regression is under test; no broad PID/name-based cleanup is ever necessary.
const fs = require("node:fs");

const descendant = `
  process.send({ ready: process.pid });
  setTimeout(() => process.exit(0), 30000);
`;
const diagnosticTreeScript = `
  const child = require("node:child_process").spawn(process.execPath, ["-e", ${JSON.stringify(descendant)}], {
    stdio: ["ignore", "inherit", "inherit", "ipc"], windowsHide: true
  });
  child.once("message", message => {
    if (message && message.ready === child.pid) process.stdout.write(JSON.stringify({ root: process.pid, descendant: child.pid }) + "\\n");
  });
  child.once("error", () => process.exit(2));
  setTimeout(() => process.exit(0), 30000);
`;

function processIsRunning(pid) {
  if (!Number.isSafeInteger(pid) || pid <= 0) throw new Error("Invalid fixture PID");
  try {
    process.kill(pid, 0);
    if (process.platform === "linux") {
      // A minimal container init can leave a terminated orphan as a zombie. It has no running
      // code or open pipes and must not be confused with an outstanding diagnostic process.
      const state = fs.readFileSync(`/proc/${pid}/stat`, "utf8").match(/\)\s+([A-Z])/);
      return state?.[1] !== "Z" && state?.[1] !== "X";
    }
    return true;
  } catch (error) {
    if (error.code === "ESRCH" || error.code === "ENOENT") return false;
    if (error.code === "EPERM") return true;
    throw error;
  }
}

module.exports = { diagnosticTreeScript, processIsRunning };
