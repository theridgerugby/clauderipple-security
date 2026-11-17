import fs from "node:fs";
import path from "node:path";

/** Read-only preflight for an existing system helper. Never installs or changes permissions. */
export function verifySystemSandboxHelper(helper, filesystem = fs) {
  if (!path.posix.isAbsolute(helper) || filesystem.realpathSync(helper) !== helper) {
    throw new Error("Sandbox helper must be an absolute, unaliased system file");
  }
  const info = filesystem.lstatSync(helper);
  if (!info.isFile() || info.isSymbolicLink() || info.uid !== 0 || info.nlink !== 1 || (info.mode & 0o7777) !== 0o4755) {
    // Report only non-secret metadata so a runner administrator can distinguish a
    // missing setuid bit from wrong ownership without weakening this preflight.
    const observed = JSON.stringify({
      uid: info.uid,
      links: info.nlink,
      mode: (info.mode & 0o7777).toString(8),
      regular: info.isFile(),
      symlink: info.isSymbolicLink(),
    });
    throw new Error(`Sandbox helper must already be root-owned with mode 4755; observed ${observed}`);
  }
  for (let parent = path.posix.dirname(helper); ; parent = path.posix.dirname(parent)) {
    const stat = filesystem.lstatSync(parent);
    if (!stat.isDirectory() || stat.isSymbolicLink() || stat.uid !== 0 || (stat.mode & 0o022) !== 0) {
      throw new Error("Sandbox helper ancestors must be root-owned and not writable by other users");
    }
    if (parent === path.posix.dirname(parent)) break;
  }
}
