// Test-only preload. Block TCP outside numeric loopback before DNS or connect,
// including global fetch, undici, redirects and child Node processes.
import { Socket } from "node:net";

const connect = Socket.prototype.connect;
Socket.prototype.connect = function (this: Socket, ...args: any[]) {
  const normalized = Array.isArray(args[0]) ? args[0] : args;
  const first = normalized[0];
  const options = typeof first === "object" && first !== null ? first : null;
  const host = options ? options.host : typeof normalized[1] === "string" ? normalized[1] : undefined;
  if (options?.path || typeof first === "string" || (host !== "127.0.0.1" && host !== "::1")) {
    throw new Error("Test network isolation: only numeric loopback TCP is allowed");
  }
  return Reflect.apply(connect, this, args);
} as typeof connect;

// spawn() does not inherit execArgv. Propagate the same preload without enabling
// model calls or adding credentials in the child.
const preload = `--import=${import.meta.url}`;
if (!(process.env.NODE_OPTIONS ?? "").includes(preload)) {
  process.env.NODE_OPTIONS = `${process.env.NODE_OPTIONS ?? ""} ${preload}`.trim();
}
