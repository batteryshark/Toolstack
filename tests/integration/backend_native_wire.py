"""Finite real HTTP seam proof; run with the existing offline admin dependencies."""
import os
import socket
import subprocess
import tempfile
import threading
import time
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[2]
SWIFT = r'''
import Foundation
@main struct Wire {
 static func main() async throws {
  let a = CommandLine.arguments
  let client = ApiClient(baseURL: URL(string: a[1])!)
  do { _ = try await client.listTools(); fatalError("anonymous accepted") }
  catch ApiError.unauthorized {}
  try await client.login(password: "FAKE-wire-password")
  if a[2] == "delete" {
   let r = try await client.removeToolReceipt(id: a[3])
   precondition(r.removed == a[3] && r.deleted == (a[4] == "true"))
  } else {
   let tools = a[4] == "malformed" ? [] : try await client.listTools()
   let c = try await client.catalogObservation()
   precondition(c.verified == (a[2] == "verified"))
   precondition(c.toolIDs.sorted() == a[3].split(separator: ",").map(String.init).sorted())
   if a[4] == "initial" { precondition(Set(tools.map { $0.id }) == Set(c.toolIDs)) }
   if a[4] == "rejectA" { precondition(!c.toolIDs.contains("a")) }
  }
  print("PASS native HTTP " + a[2] + " " + a[3])
 }
}
'''


def main():
    with tempfile.TemporaryDirectory(prefix="toolstack-wire-") as temp:
        root = Path(temp).resolve()
        os.environ.update(HOME=str(root), XDG_CONFIG_HOME=str(root/'config'),
                          XDG_STATE_HOME=str(root/'state'), TOOLSTACK_SPS_SKIP='1',
                          TOOLSTACK_SPS_ENV=str(root/'absent.env'))
        from admin import auth, settings, broker_config
        from admin.broker_config import BrokerRunConfig
        from admin.server import create_app
        from broker.server import build_server
        import uvicorn
        source = root/'Wire.swift'
        source.write_text(SWIFT)
        binary = root/'wire'
        subprocess.run(['xcrun', 'swiftc', '-j', '2', '-module-cache-path', str(root/'modules'),
                        '-o', str(binary), *map(str, sorted((ROOT/'macapp/Sources/ToolstackKit').glob('*.swift'))),
                        str(source)], check=True, timeout=120,
                       env={**os.environ, 'DEVELOPER_DIR': '/Applications/Xcode.app/Contents/Developer'})
        tools = root/'tools'
        folder = tools/'a'
        folder.mkdir(parents=True)
        manifest = folder/'toolyard.toml'
        text = 'id="a"\ntype="api"\n[entrypoint]\nport=43210\n'
        manifest.write_text(text)  # intentionally zero operations
        broker = build_server(port=0, host='127.0.0.1', db_path=str(root/'broker.db'), tools_root=str(tools))
        bt = threading.Thread(target=broker.serve_forever)
        bt.start()
        config = BrokerRunConfig(db_path=str(root/'broker.db'), tools_root=str(tools), port=broker.server_address[1])
        broker_config.save(config)
        settings.write_password_hash(auth.hash_password('FAKE-wire-password'))
        sock = socket.socket()
        sock.bind(('127.0.0.1', 0))
        url = f'http://127.0.0.1:{sock.getsockname()[1]}'
        server = None
        at = None
        def phase(status, ids='', extra='rejectA'):
            subprocess.run([str(binary), url, status, ids, extra], check=True, timeout=15)
        try:
            with mock.patch('admin.server.start_reconciler_thread', return_value=None):
                app = create_app()
            server = uvicorn.Server(uvicorn.Config(app, log_level='error'))
            at = threading.Thread(target=lambda: server.run(sockets=[sock]))
            at.start()
            deadline = time.monotonic() + 5
            while not server.started:
                if time.monotonic() > deadline: raise RuntimeError('admin startup timed out')
                time.sleep(.01)
            print(f'PID {os.getpid()} broker/admin threads; real loopback HTTP', flush=True)
            phase('verified', 'a', 'initial')
            manifest.unlink()
            broker.reload_registry()
            phase('verified')
            manifest.write_text(text.replace('id="a"', 'id="b"'))
            broker.reload_registry()
            phase('verified', 'b')
            receipt = broker.ctx.store.catalog_receipt()
            broker.ctx.store.set_catalog_receipt(None)
            phase('unknown')
            broker.ctx.store.set_catalog_receipt(receipt)
            manifest.write_text('invalid = [')
            phase('unknown', '', 'malformed')
            manifest.write_text(text)
            broker.reload_registry()
            old = broker.ctx.store.catalog_receipt()
            broker.reload_registry()
            broker.ctx.store.set_catalog_receipt(old)
            phase('unknown')
            second = build_server(port=0, host='127.0.0.1', db_path=config.db_path,
                                  tools_root=str(tools))
            second_thread = threading.Thread(target=second.serve_forever)
            second_thread.start()
            try:
                # Admin still probes the first live listener; second owns the receipt.
                phase('unknown')
            finally:
                second.shutdown()
                second_thread.join(5)
                second.server_close()
                second.ctx.store.close()
                assert not second_thread.is_alive()
            external = root/'external'
            external.mkdir()
            external_manifest = external/'toolyard.toml'
            external_text = text.replace('id="a"', 'id="external"')
            external_manifest.write_text(external_text)
            config.tool_dirs = [str(external)]
            broker_config.save(config)
            phase('delete', 'external', 'false')
            assert external_manifest.read_text() == external_text
            assert broker_config.load().tool_dirs == []
            phase('delete', 'a', 'true')
            assert not folder.exists()
        finally:
            if server: server.should_exit = True
            if at: at.join(5)
            sock.close()
            broker.shutdown()
            bt.join(5)
            broker.server_close()
            broker.ctx.store.close()
            assert not bt.is_alive() and (at is None or not at.is_alive())
            print('CLEANUP: both server threads stopped; sockets/store closed', flush=True)


if __name__ == '__main__':
    main()
