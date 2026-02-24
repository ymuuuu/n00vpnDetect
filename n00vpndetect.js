/*
 * n00vpndetect.js
 * Frida script to bypass VPN detection on Android.
 *
 * Mirrors the NoVPNDetect LSPosed module by hooking the same APIs:
 *   1. ConnectivityManager.getNetworkInfo(int)
 *   2. NetworkCapabilities.hasTransport(int)
 *   3. NetworkCapabilities.getCapabilities()  (hidden/internal, hooked if available)
 *   4. NetworkCapabilities.hasCapability(int)
 *   5. NetworkInfo.getType()
 *   6. NetworkInfo.getSubtype()
 *   7. NetworkInfo.getTypeName()
 *   8. NetworkInfo.getSubtypeName()
 *   9. NetworkInterface.isVirtual()
 *  10. NetworkInterface.getName()
 *
 * Usage:
 *   frida -U -f <package_name> -l n00vpndetect.js --no-pause
 *   frida -U -n <process_name> -l n00vpndetect.js
 */

"use strict";

// Android constants
var TYPE_VPN = 17;
var TYPE_WIFI = 1;
var TRANSPORT_VPN = 4;
var NET_CAPABILITY_NOT_VPN = 15;

var TAG = "n00bVPNDetect";

function log(msg) {
    console.log("[" + TAG + "] " + msg);
}

function getRandomString(length) {
    var chars = "abcdefghijklmnopqrstuvwxyz0123456789";
    var result = "";
    for (var i = 0; i < length; i++) {
        result += chars.charAt(Math.floor(Math.random() * chars.length));
    }
    return result;
}

Java.perform(function () {
    log("Initializing VPN detection bypass hooks...");

    // =========================================================================
    // Hook 1: ConnectivityManager.getNetworkInfo(int)
    // If the caller asks for TYPE_VPN (17), return null.
    // =========================================================================
    try {
        var ConnectivityManager = Java.use("android.net.ConnectivityManager");

        ConnectivityManager.getNetworkInfo.overload("int").implementation = function (networkType) {
            log("ConnectivityManager.getNetworkInfo(" + networkType + ")");
            if (networkType === TYPE_VPN) {
                log("  -> Blocked TYPE_VPN request, returning null");
                return null;
            }
            return this.getNetworkInfo(networkType);
        };

        log("[+] Hooked ConnectivityManager.getNetworkInfo(int)");
    } catch (e) {
        log("[-] Failed to hook ConnectivityManager.getNetworkInfo: " + e);
    }

    // =========================================================================
    // Hook 2: NetworkCapabilities.hasTransport(int)
    // If checking for TRANSPORT_VPN (4), return false.
    // =========================================================================
    try {
        var NetworkCapabilities = Java.use("android.net.NetworkCapabilities");

        NetworkCapabilities.hasTransport.implementation = function (transportType) {
            log("NetworkCapabilities.hasTransport(" + transportType + ")");
            if (transportType === TRANSPORT_VPN) {
                log("  -> Spoofed TRANSPORT_VPN to false");
                return false;
            }
            return this.hasTransport(transportType);
        };

        log("[+] Hooked NetworkCapabilities.hasTransport(int)");
    } catch (e) {
        log("[-] Failed to hook NetworkCapabilities.hasTransport: " + e);
    }

    // =========================================================================
    // Hook 3: NetworkCapabilities.getCapabilities()
    // Ensure NET_CAPABILITY_NOT_VPN (15) is present in the returned int[].
    // Note: This is a hidden/internal method. It may not exist on all ROMs.
    // =========================================================================
    try {
        var NetworkCapabilities = Java.use("android.net.NetworkCapabilities");

        NetworkCapabilities.getCapabilities.implementation = function () {
            var result = this.getCapabilities();
            log("NetworkCapabilities.getCapabilities()");

            if (result === null) return result;

            // Check if NET_CAPABILITY_NOT_VPN is already present
            var found = false;
            for (var i = 0; i < result.length; i++) {
                if (result[i] === NET_CAPABILITY_NOT_VPN) {
                    found = true;
                    break;
                }
            }

            if (!found) {
                // Build a new array with NET_CAPABILITY_NOT_VPN appended
                var IntArray = Java.array("int", []);
                var newArr = new Array(result.length + 1);
                for (var j = 0; j < result.length; j++) {
                    newArr[j] = result[j];
                }
                newArr[result.length] = NET_CAPABILITY_NOT_VPN;
                log("  -> Injected NET_CAPABILITY_NOT_VPN into capabilities array");
                return Java.array("int", newArr);
            }

            return result;
        };

        log("[+] Hooked NetworkCapabilities.getCapabilities()");
    } catch (e) {
        log("[-] Failed to hook NetworkCapabilities.getCapabilities (may not exist on this ROM): " + e);
    }

    // =========================================================================
    // Hook 4: NetworkCapabilities.hasCapability(int)
    // If checking for NET_CAPABILITY_NOT_VPN (15), return true.
    // =========================================================================
    try {
        var NetworkCapabilities = Java.use("android.net.NetworkCapabilities");

        NetworkCapabilities.hasCapability.implementation = function (capability) {
            log("NetworkCapabilities.hasCapability(" + capability + ")");
            if (capability === NET_CAPABILITY_NOT_VPN) {
                log("  -> Spoofed NET_CAPABILITY_NOT_VPN to true");
                return true;
            }
            return this.hasCapability(capability);
        };

        log("[+] Hooked NetworkCapabilities.hasCapability(int)");
    } catch (e) {
        log("[-] Failed to hook NetworkCapabilities.hasCapability: " + e);
    }

    // =========================================================================
    // Hook 5 & 6: NetworkInfo.getType() and NetworkInfo.getSubtype()
    // If the result is TYPE_VPN (17), replace with TYPE_WIFI (1).
    // =========================================================================
    try {
        var NetworkInfo = Java.use("android.net.NetworkInfo");

        NetworkInfo.getType.implementation = function () {
            var result = this.getType();
            log("NetworkInfo.getType() -> " + result);
            if (result === TYPE_VPN) {
                log("  -> Spoofed to TYPE_WIFI");
                return TYPE_WIFI;
            }
            return result;
        };

        log("[+] Hooked NetworkInfo.getType()");
    } catch (e) {
        log("[-] Failed to hook NetworkInfo.getType: " + e);
    }

    try {
        var NetworkInfo = Java.use("android.net.NetworkInfo");

        NetworkInfo.getSubtype.implementation = function () {
            var result = this.getSubtype();
            log("NetworkInfo.getSubtype() -> " + result);
            if (result === TYPE_VPN) {
                log("  -> Spoofed to TYPE_WIFI");
                return TYPE_WIFI;
            }
            return result;
        };

        log("[+] Hooked NetworkInfo.getSubtype()");
    } catch (e) {
        log("[-] Failed to hook NetworkInfo.getSubtype: " + e);
    }

    // =========================================================================
    // Hook 7 & 8: NetworkInfo.getTypeName() and NetworkInfo.getSubtypeName()
    // If the result contains "VPN" (case-insensitive), replace with "WIFI".
    // =========================================================================
    try {
        var NetworkInfo = Java.use("android.net.NetworkInfo");

        NetworkInfo.getTypeName.implementation = function () {
            var result = this.getTypeName();
            log("NetworkInfo.getTypeName() -> " + result);
            if (result !== null && result.toLowerCase().indexOf("vpn") !== -1) {
                log("  -> Spoofed to WIFI");
                return "WIFI";
            }
            return result;
        };

        log("[+] Hooked NetworkInfo.getTypeName()");
    } catch (e) {
        log("[-] Failed to hook NetworkInfo.getTypeName: " + e);
    }

    try {
        var NetworkInfo = Java.use("android.net.NetworkInfo");

        NetworkInfo.getSubtypeName.implementation = function () {
            var result = this.getSubtypeName();
            log("NetworkInfo.getSubtypeName() -> " + result);
            if (result !== null && result.toLowerCase().indexOf("vpn") !== -1) {
                log("  -> Spoofed to WIFI");
                return "WIFI";
            }
            return result;
        };

        log("[+] Hooked NetworkInfo.getSubtypeName()");
    } catch (e) {
        log("[-] Failed to hook NetworkInfo.getSubtypeName: " + e);
    }

    // =========================================================================
    // Hook 9: NetworkInterface.isVirtual()
    // Always return false (VPN interfaces are virtual).
    // =========================================================================
    try {
        var NetworkInterface = Java.use("java.net.NetworkInterface");

        NetworkInterface.isVirtual.implementation = function () {
            log("NetworkInterface.isVirtual() -> forced false");
            return false;
        };

        log("[+] Hooked NetworkInterface.isVirtual()");
    } catch (e) {
        log("[-] Failed to hook NetworkInterface.isVirtual: " + e);
    }

    // =========================================================================
    // Hook 10: NetworkInterface.getName()
    // If the name starts with typical VPN prefixes (tun, ppp, pptp),
    // replace it with a random alphanumeric string of the same length.
    // =========================================================================
    try {
        var NetworkInterface = Java.use("java.net.NetworkInterface");

        NetworkInterface.getName.implementation = function () {
            var result = this.getName();
            log("NetworkInterface.getName() -> " + result);
            if (result !== null) {
                if (result.startsWith("tun") || result.startsWith("ppp") || result.startsWith("pptp")) {
                    var spoofed = getRandomString(result.length);
                    log("  -> Spoofed VPN interface name to: " + spoofed);
                    return spoofed;
                }
            }
            return result;
        };

        log("[+] Hooked NetworkInterface.getName()");
    } catch (e) {
        log("[-] Failed to hook NetworkInterface.getName: " + e);
    }

    log("==============================================");
    log("All VPN detection bypass hooks installed!");
    log("==============================================");
});
