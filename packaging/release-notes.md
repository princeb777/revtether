Reverse tethering over USB: share your PC's internet with an Android phone through adb. No root needed on either side.

### Downloads

| File | For |
|---|---|
| `revtether-*-linux-x86_64.zip` | Linux x86_64 (static binary, any distro) |
| `revtether-*-windows-x86_64.zip` | Windows 10/11 x86_64 |

Each zip contains:
- `revtether`: the relay, with the phone app embedded
- `adb`: Google's official Android platform-tools
- `gnirehtet.apk`: the phone app, also as a separate file for manual install
- the license files

The Windows zip also has `revtether-run.cmd`.

### Quick start

1. On the phone, enable **USB debugging** in Developer options. Connect the phone by USB and accept the "Allow USB debugging?" prompt.
2. Start revtether:
   - **Windows:** extract the zip and double-click `revtether-run.cmd`.
   - **Linux:** extract the zip and run `./revtether`.
3. The first time, accept the VPN request on the phone. A key icon in the status bar means the phone is online through the PC.

To stop, press Ctrl+C or close the window.

revtether checks whether the phone app is installed and installs it if needed, sets up `adb reverse`, starts the VPN, and runs the relay. The phone uses the PC's DNS servers by default. Verify downloads against `SHA256SUMS.txt`.
