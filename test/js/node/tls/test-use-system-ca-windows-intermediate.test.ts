import { afterAll, beforeAll, describe, expect, test } from "bun:test";
import { bunEnv, bunExe, isWindows } from "harness";
import { spawnSync } from "node:child_process";
import { readFileSync } from "node:fs";
import { join } from "node:path";

// Verifies that --use-system-ca on Windows reads the "CA" (Intermediate
// Certification Authorities) store for chain building, so that a server
// presenting only a leaf certificate still verifies when the intermediate and
// root are in the Windows stores. Also verifies that CA-store intermediates do
// NOT appear in tls.getCACertificates("system") — they are path-building
// material only, not trust anchors.

const fixtures = join(import.meta.dir, "fixtures", "system-ca-windows");

// SHA-1 thumbprints of the fixture certs (see fixtures/system-ca-windows/README.md).
// Used for certutil -delstore cleanup.
const ROOT_THUMBPRINT = "61A6E82FDCE2F8770B50071A75E203BBF8E4DBF4";
const INTERMEDIATE_THUMBPRINT = "BFDECBB563CBE2019192DB5A4A9BDAA00D6FBFEE";
const INTERMEDIATE_CN = "Bun Test System CA Intermediate";

function certutil(args: string[]) {
  return spawnSync("certutil", args, { encoding: "utf8" });
}

describe.skipIf(!isWindows)("--use-system-ca loads Windows intermediate (CA) store", () => {
  let server: ReturnType<typeof Bun.serve>;
  let url: string;

  beforeAll(() => {
    // Best-effort pre-clean in case a previous run was killed before afterAll.
    certutil(["-user", "-delstore", "Root", ROOT_THUMBPRINT]);
    certutil(["-user", "-delstore", "CA", INTERMEDIATE_THUMBPRINT]);

    const addRoot = certutil(["-user", "-f", "-addstore", "Root", join(fixtures, "root-cert.pem")]);
    if (addRoot.status !== 0) {
      throw new Error(`certutil -addstore Root failed: ${addRoot.stdout}${addRoot.stderr}`);
    }
    const addIntermediate = certutil(["-user", "-f", "-addstore", "CA", join(fixtures, "int-cert.pem")]);
    if (addIntermediate.status !== 0) {
      throw new Error(`certutil -addstore CA failed: ${addIntermediate.stdout}${addIntermediate.stderr}`);
    }

    // Server presents ONLY the leaf — no intermediate in the handshake. This
    // mirrors enterprise TLS-inspection proxies that rely on the client having
    // the intermediate installed locally.
    server = Bun.serve({
      port: 0,
      tls: {
        cert: readFileSync(join(fixtures, "leaf-cert.pem"), "utf8"),
        key: readFileSync(join(fixtures, "leaf-key.pem"), "utf8"),
      },
      fetch() {
        return new Response("ok");
      },
    });
    url = `https://localhost:${server.port}/`;
  });

  afterAll(() => {
    server?.stop(true);
    certutil(["-user", "-delstore", "Root", ROOT_THUMBPRINT]);
    certutil(["-user", "-delstore", "CA", INTERMEDIATE_THUMBPRINT]);
  });

  test("builds chain via CA-store intermediate when server omits it", async () => {
    await using proc = Bun.spawn({
      cmd: [
        bunExe(),
        "--use-system-ca",
        "-e",
        `const res = await fetch(${JSON.stringify(url)}); console.log(res.status, await res.text());`,
      ],
      env: bunEnv,
      stdout: "pipe",
      stderr: "pipe",
    });
    const [stdout, stderr, exitCode] = await Promise.all([proc.stdout.text(), proc.stderr.text(), proc.exited]);

    expect(stderr).not.toContain("UNABLE_TO_VERIFY_LEAF_SIGNATURE");
    expect(stderr).not.toContain("unable to get local issuer certificate");
    expect(stdout.trim()).toBe("200 ok");
    expect(exitCode).toBe(0);
  });

  test("tls.getCACertificates('system') does not include CA-store intermediates", async () => {
    await using proc = Bun.spawn({
      cmd: [
        bunExe(),
        "--use-system-ca",
        "-e",
        `const tls = require("node:tls");
         const certs = tls.getCACertificates("system");
         let found = false;
         for (const pem of certs) {
           const x = new (require("node:crypto").X509Certificate)(pem);
           if (x.subject.includes(${JSON.stringify(INTERMEDIATE_CN)})) found = true;
         }
         console.log(JSON.stringify({ count: certs.length, intermediateFound: found }));`,
      ],
      env: bunEnv,
      stdout: "pipe",
      stderr: "pipe",
    });
    const [stdout, stderr, exitCode] = await Promise.all([proc.stdout.text(), proc.stderr.text(), proc.exited]);

    expect(stderr).toBe("");
    const result = JSON.parse(stdout.trim());
    expect(result.count).toBeGreaterThan(0);
    expect(result.intermediateFound).toBe(false);
    expect(exitCode).toBe(0);
  });

  test("self-issued certs in CA store are not treated as trust anchors", async () => {
    // Install the (self-signed) root into the CA store as well, then remove it
    // from Root. The leaf should now FAIL to verify: the root is present only
    // in the intermediate set, and self-issued entries are filtered out so they
    // can never terminate a chain.
    certutil(["-user", "-delstore", "Root", ROOT_THUMBPRINT]);
    const addRootAsCA = certutil(["-user", "-f", "-addstore", "CA", join(fixtures, "root-cert.pem")]);
    expect(addRootAsCA.status).toBe(0);
    try {
      await using proc = Bun.spawn({
        cmd: [
          bunExe(),
          "--use-system-ca",
          "-e",
          `try { await fetch(${JSON.stringify(url)}); console.log("verified"); } catch (e) { console.log("rejected:" + e.code); }`,
        ],
        env: bunEnv,
        stdout: "pipe",
        stderr: "pipe",
      });
      const [stdout, , exitCode] = await Promise.all([proc.stdout.text(), proc.stderr.text(), proc.exited]);

      expect(stdout.trim()).toStartWith("rejected:");
      expect(stdout).not.toContain("verified");
      expect(exitCode).toBe(0);
    } finally {
      certutil(["-user", "-delstore", "CA", ROOT_THUMBPRINT]);
      certutil(["-user", "-f", "-addstore", "Root", join(fixtures, "root-cert.pem")]);
    }
  });
});
