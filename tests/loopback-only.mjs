// Optional regression-test preload: keep outer safety valves off while existing model fixtures
// use local stubs. No non-loopback TCP connection can be made, including by child processes.
// NODE_OPTIONS='--import=./tests/loopback-only.mjs' MODEL_CALLS_ENABLED=false COLLECT_ENABLED=false npm test
import net from 'node:net';
const connect = net.Socket.prototype.connect;
net.Socket.prototype.connect = function (...args) {
  const [opts] = net._normalizeArgs(args);
  const host = String(opts.host ?? 'localhost').replace(/^\[|\]$/g, '');
  if (!opts.path && host !== 'localhost' && host !== '::1' && !(net.isIP(host) === 4 && host.startsWith('127.'))) {
    throw new Error(`Test guard refused non-loopback TCP: ${host}`);
  }
  return connect.apply(this, args);
};
// Modify the in-memory config only after its ordinary imports/environment setup.
// Loading config early would invalidate suites that set local URLs before dynamic imports.
import { registerHooks } from 'node:module';
registerHooks({
  load(url, context, nextLoad) {
    const result = nextLoad(url, context);
    if (url.endsWith('/packages/backend/src/config.ts')) {
      const keepClosed = /(?:collect-only|editorial-review|media-performance)\.test\.ts$/.test(process.argv[1] ?? '');
      if (!keepClosed) {
        return { ...result, source: String(result.source) + '\nif (process.env.NODE_ENV === \"test\") config.modelCallsEnabled = true;\n' };
      }
    }
    return result;
  }
});
