# Crowfell

A local server emulator for the Crowfall game client.
It fakes the central HTTP API and a minimal zone server so the client can log in, list and create characters, and load into a scenario.

## Contents

| Path | What it is |
| --- | --- |
| `api_server.py` | Mock central API (login, servers, characters, factions, campaigns, zone transfer) on `127.0.0.1:8080`. |
| `zone_server.py` | Minimal TCP zone server on `0.0.0.0:8900` that performs the physics connection handshake. |
| `proxy_dll/` | `version.dll` proxy that patches `GameAssembly.dll` at runtime to work around broken IL2CPP `Deserialize<T>` paths. |
| `CROWFALL NOTES.md` | Launcher arguments, Ghidra addresses, and reverse engineering notes. |

## Requirements

- Python 3 (standard library only)
- Wine, to run the Windows client on Linux
- MinGW-w64 (`x86_64-w64-mingw32-gcc`), only if rebuilding the proxy DLL

## Usage

Start both servers:

```sh
python3 api_server.py
python3 zone_server.py
```

Copy `proxy_dll/version.dll` into the game directory next to `CrowfallClient.exe`, then launch the client pointed at the mock API:

```sh
WINEDEBUG=-all WINEDLLOVERRIDES="version=n,b" wine CrowfallClient.exe \
  -loginurl http://127.0.0.1:8080 \
  -username <name> \
  -token devtoken
```

The `version=n,b` override makes Wine load the native proxy DLL instead of its builtin one.

## Rebuilding the proxy DLL

```sh
proxy_dll/build.sh
```

`build.sh` assumes the game lives at `/mnt/Storage/Crowfall/Client/Download`, so edit `GAME_DIR` if yours is elsewhere.
The proxy writes `crowfall_proxy.log` to the game directory.

## Runtime files

- `characters.json`: characters created through the client, persisted by `api_server.py`.
- `requests.log`: every request the API server receives, with full details.

Both are gitignored.
