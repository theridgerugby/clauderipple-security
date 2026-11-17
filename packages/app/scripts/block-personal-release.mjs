// This personal Windows fork is installed from pinned source. Packaging is deliberately
// unavailable: the unsigned Electron packager pulls in an unpatched ReDoS dependency
// and would also invite distributing an artifact without a verified release signature.
console.error("This Windows personal security fork is source-only. Use docs/personal-windows-install.md at a reviewed commit; native packaging and release are disabled.");
process.exitCode = 1;
