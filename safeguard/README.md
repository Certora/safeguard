# Safeguard Detector Plugins

Welcome to the Safeguard plugin folder! This README describes how the folder is laid out, the conventions used, and how to activate and use safeguard plugins.

## Folder structure

Each detector for a specific client (morpho, uniswap, etc.) is expected to live in a subfolder of the same name (e.g., the detector for Uniswap lives in the subfolder `uniswap`).
The `etherapi` subfolder is a common package that the main `geth` implementation uses to communicate with the detectors (which are implemented as go plugins).

### Plugin structure and conventions

Within each detector folder, **all** logic and global state **must** be included in the `main` package. If you spread your logic across multiple packages, dynamic reloading **will not work**.
You may use any APIs in geth, however you **must not** include any references to the detector in the geth source code. All interactions between the main `geth` process and the plugin
**must** go through the etherapi and the `InvariantChecker` interface.

Within the `main` package you **must** export a symbol called `Detector` which must implement the `InvariantCheck` interface.

When the detector is loaded, the module `init()` function is run, and all global variables in the plugin's `main` package are initialized. After loading, the `InvariantChecks` function is called on each
block, in order, as they are received from the beacon chain. `InvariantChecks` is never called by multiple threads, and the plugin may thus access its own state without locks (unless, of course, it uses 
concurrency internally). The plugin **must not** panic unless there is a truly fatal error. Instead, return an error, and the plugin will be disabled.

Through the external admin interfaces, checking may be temporarily paused. When this occurs, the `Detector`'s `OnPause()` function is invoked. This function may be invoked multiple times without any intervening
calls to `InvariantChecks`. Thus, `OnPause` is expected to be idempotent. When the detector is unpaused, there is
no explicit notification, but `InvariantChecks` is simply called again on each block. Finally, via dynamic reloading, a detector plugin may be discarded for a new version. When this occurs, `OnDispose` is 
called. It is guaranteed that after `OnDispose` completes, no further functions are called on `Detector`.

## Building a Plugin

Due to idiosyncracies in how the plugin loading system works, plugins must be built in a *very* specific way. These idiosyncracies are mostly handled by the `build_plugin.sh` script. Simply invoke the script 
with the folder name of the detector plugin, e.g., `uniswap` (without any other file path information) to build the `uniswap` plugin. The script will compile a version of the detector with a unique "plugin 
path" to enable dynamic reloading. In addition, if the environment variables are setup to support dynamic reloading (see below) then the script makes a best effort to reload the newly built plugin. Do not rely 
on this in production.

The result of the plugin compilation is a shared object file which lives within the newly generated plugin build folder. If you need a stable output name, set the environment variable `SAFEGUARD_OBJ_PATH`, and
the compiled shared object will be output to that path (this is most useful with `STATIC` mode, see below).

**IMPORTANT**: Do not make any git commits between building the main `geth` binary and the plugin. The hash and date of the HEAD commit is embedded into the binaries, and if there is a mismatch, go will refuse
to load the plugin.

## Loading and Using Plugins

Each geth instance can run exactly one detector; multiplexed checking is not supported currently. There are four loading/admin
modes, which control how the dynamic reloading/admin of the plugin works.

The mode used by the geth instance is determined by the SAFEGUARD_MODE environment variable, which can take one of four values: `STATIC`, `SOCKET`, `NET`, or `SIGNAL`. 
Any other value is ignored and no plugin loading will be done. The behavior and configuration of these four modes is described below.

### STATIC mode

In this mode, the plugin is loaded immediately at startup, and cannot be reloaded or paused/unpaused; i.e., it behaves as if we statically linked in the plugin.

If this mode is selected, the environment variable `SAFEGUARD_PLUGIN_PATH` must be set. This environment variable must hold the filepath of the plugin shared object produced by the `build_plugin.sh` script
(it is thus recommended you set `SAFEGUARD_OBJ_PATH` to the same path as `SAFEGUARD_PLUGIN_PATH`). The plugin is immediately loaded, validated, and enabled. If there is an error in loading the plugin,
the geth server will need to be restarted.

### SIGNAL mode

In this mode, plugin loading and pausing is controlled by posix signals. The geth process listens for `SIGUSR1` and `SIGUSR2`. Upon receiving `SIGUSR1`, the geth process immediately loads the plugin from the
file indicated by the `SAFEGUARD_PLUGIN_PATH`, validates, and enables the plugin.

*NOTE*: `SAFEGUARD_PLUGIN_PATH` must be set at the time the process is launched, even if there is no plugin at that path at that point. The plugin is only loaded from that path on delivery of the `SIGUSR1`
signal.

**IMPORTANT**: For dynamic loading to work, the `SAFEGUARD_PLUGIN_PATH` *must* be a symbolic link to the actual shared object. If not, only one plugin can ever be loaded (due to an
idiosyncracy of the go plugin system.)

`SIGUSR1` may be delivered multiple times; on each such delivery the geth process will reload the plugin. However, the plugin **must** be different (details below), otherwise plugin loading will fail, and
detecting will be disabled.

**IMPORTANT**: It bears repeating: SIGUSR1 is *not* idempotent. If you deliver SIGUSR1 over and over again without changing the plugin pointed to by the `SAFEGUARD_PLUGIN_PATH` symlink, then reloading
will fail, and detecting will be disabled.

Upon receiving `SIGUSR2`, the detector will be flipped from unpaused to paused, or vice versa. Each delivery will toggle the enabled state. There is currently no way to query the pause state except
for looking at the console output of the geth process. If `SIGUSR2` is delivered before `SIGUSR1`, the request is ignored.

### SOCKET mode

In this mode, plugin loading and administration is controlled via an IPC socket. At startup time, geth creates a named socket at the path indicated by the environment variable `SAFEGUARD_SOCKET_PATH`.
If this environment variable is not set, or no socket can be created at that path, no loading or administration is possible and geth will have to be restarted.

The socket listens for JSON formatted messages. The JSON messages must conform to the admin message schema (see below):
the actions taken for each message is defined along with the schema.

### NET mode

In this mode, plugin loading and administration is controlled via TCP connections on a specific port. At startup time, 
geth will read the `SAFEGUARD_ADMIN_PORT` environment variable and parses it as an integer, to be used
as the port to listen on. If the parsing fails, the admin server is not started. If `SAFEGUARD_ADMIN_PORT` is not
present, then the default port, 6969 is used.

Geth will then start listening for TCP connections on the specific (or default) port. This port is used to accept **raw**
TCP connections: do **not** send HTTP requests, the admin serverwill not know what to do with them.
Like the socket admin server,
the payloads of these TCP messages are expected to be a json encoded string conforming to the admin message schema (see 
below).

### Build script and dynamic reloading

The `build_plugin.sh` script looks at the `SAFEGUARD_MODE` environment variable to try to automatically reload the plugin (assuming the build succeeded). If `SAFEGUARD_MODE` is unset or `STATIC`,
it will not try to dynamically reload. Otherwise, it will try to use signals/sockets/tcp connections
to communicate that the plugin should be reloaded. For this process to work, `SAFEGUARD_MODE` and other
variables (like `SAFEGUARD_SOCKET_PATH`) must be set to the same values used for launching geth. If you change the values 
of these variables, reloading will not work, and in fact, if you change
to `SIGNAL` mode, geth will take the default action on `SIGUSR1/2`, which is to shut down. Use caution, and only rely on this for development.

### Initial loading

By default, the `SIGNAL`, `NET`, and `SOCKET` administration modes do not load the plugin at startup time, but wait for
the reload message. If, however, the environment variable `SAFEGUARD_LOAD_INITIAL` is set (to any value, it just needs 
to be set) then the plugin indicated by the `SAFEGUARD_PLUGIN_PATH` environment variable is loaded. If 
`SAFEGUARD_PLUGIN_PATH` is not set, then the `SAFEGUARD_LOAD_INITIAL` is ignored. NB that in static linking mode, 
`SAFEGUARD_LOAD_INITIAL` is ignored: the management mode indicates that the load *must* occur.

If this initial plugin loading fails (because the object file is not correct, or `SAFEGUARD_PLUGIN_PATH` is not set),
new implementations can still be loaded according to the administration method selected (signals, sockets, etc.)

## Different Plugins

Go determines that a plugin is distinct from any existing plugins using two checks. Both of these must be satisfied for the plugin to be reloaded.

1. The *real path* of the plugin must be different from any previously loaded plugin. This is why `SAFEGUARD_PLUGIN_PATH` can be statically set but must be a symlink:
   when doing this check, the symlink is first resolved.
   Thus, by updating the symlink to a new, unique path, this check can be satisfied.
2. The plugin must have a unique "plugin path" from any previously loaded plugin. This "plugin path" is *not* the same thing as the file path. Rather, it is an internally generated
   identifier for the package/module holding the plugin name (analogous to the fully qualified package name of a class on the JVM). The plugin path is automatically inferred from the folder
   in which the plugin is built, the `build_plugin` script automatically sets up folder paths to ensure this path is unique for each build.

If either of these checks are unsatisfied, then the plugin loading will fail with the message "plugin already loaded".

## Admin Message Schema

Each admin message is a JSON dictionary that must at least include the key "type".
The action taken by the geth process is determined by the value of `type`. 

If `type`'s value is the string `PAUSE`, then the message has the effect of delivering `SIGUSR2` in `SIGNAL` mode: the detector's paused status is toggled, or the message is ignored if no plugin has been loaded.

If the value is the string `RELOAD`, then the dictionary must also include a key `data`.
The value associated with this key must be a string, which is expected to be the filepath of the plugin to load.
The plugin at this path is loaded, validated, and then enabled.
If any validation steps fail (including because the plugin wasn't actually new) detecting is automatically paused.
Note that the same caveats as `SIGUSR1` apply here: this request is *not* idempotent, and sending two duplicate reload
messages without changing the plugin object will cause a load failure and detecting to be paused.

If the value is the string `LOG`, then the dictionary must also include a key `data`. The associated value is expected to be a string
indicating a log level, one of: `DEBUG`, `INFO`, `WARN`, or `ERROR`. If string is not one of these, the message
is rejected. If the log level is valid, then the currently loaded plugin is requested to set its log output level
to the indicated level. This choice does *not* persist across dynamic reloads. The plugin may, or may not, respect
this request.

If the message was successfully processed, then the server will return (either on the TCP connection or the socket)
to the client the string `{"success": true}`. If the message was rejected for any reason, it will return
`{"success":false, "message": ...}`, where `"message"` indicates some reason for why the message was rejected.


## Runtime Environment Variables

- `CERT_HTTP_API_URL` - HTTPS endpoint for the Python server (example: `https://676im49e3m.execute-api.us-west-2.amazonaws.com/prod/`). If not configured, defaults to `localhost:5000`
- `CERT_CLIENT_ID` - string ID that should be included either in the `X-Correlation-ID` header or inside the message body while communicating with the server. 
- `SAFEGUARD_MODE` - controls the administration mode used for safeguard, and loading strategy
- `SAFEGUARD_LOAD_INITIAL` - If set, dynamic admin strategies will immediately load the plugin
- `SAFEGUARD_PLUGIN_PATH` - Used to statically set the plugin path for loading. Used in `SIGNAL` and `STATIC` modes, and if `SAFEGUARD_LOAD_INITIAL` is set
- `SAFEGUARD_ADMIN_PORT` - In net mode, used to set the port used for accepting admin messages
- `SAFEGUARD_SOCKET_PATH` - In socket mode, used to set the path of the unix socket for accepting admin messages

## Build Environment Variables

- `GO_BIN` - if set, used to override the compiler used to build a plugin
- `SAFEGUARD_OBJ_PATH` - if set, used to specify the full path for the output of the plugin compilation