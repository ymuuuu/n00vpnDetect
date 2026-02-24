# n00vpnDetect

Frida script that does the same job as the [noVPNdetect](https://bitbucket.org/yuri-project/novpndetect/src/main/) LSPosed module — for those who don't want to use LSPosed.

Hooks the same Android APIs to prevent apps from detecting an active VPN connection:
- `ConnectivityManager.getNetworkInfo`
- `NetworkCapabilities` (hasTransport, hasCapability, getCapabilities)
- `NetworkInfo` (getType, getSubtype, getTypeName, getSubtypeName)
- `NetworkInterface` (isVirtual, getName)

## Usage

```bash
frida -U -f <target.package.name> -l n00vpndetect.js
```

## Credits

All credit goes to the original author of [noVPNdetect](https://bitbucket.org/yuri-project/novpndetect/src/main/). This repo is just a Frida port of their work.

`Compatiable with Frida 17 API Changes`