export const REMOTE_USAGE = `Usage: clauderipple remote [install|uninstall|status|pair|refresh] [options]
       clauderipple remote add <ssh-host> [--port N] [--force]
       clauderipple remote remove <ssh-host>
       clauderipple remote hosts

Options:
  --bind 127.0.0.1|tailscale|lan|0.0.0.0|<ip>
  --port 8797
  --relay <https-url>|off
  --print                     install: print the service definition only
  --help, -h

Phone access requires an HTTPS relay and a fresh pairing QR. Direct HTTP/LAN phone connections are disabled.
Rotate phone pairing keys through the running host's authenticated Phone settings. The old --new-token option is disabled.
`;
