Java.perform(function () {
    console.log('\n[+] [FRIDA ENGINE] Java Property Proxy Hook Active!');
    console.log('[+] Target Tunnel Pipeline Route: {protocol}://{ip}:{port}\n');

    var System = Java.use('java.lang.System');

    var proxy_host = "{ip}";
    var proxy_port = "{port}";
    var proxy_type_raw = "{protocol}";
    var proxy_type = String(proxy_type_raw || "http").toLowerCase().trim();

    // Normalize protocol values from manual_proxies.json
    var is_socks = (
        proxy_type === "socks" ||
        proxy_type === "socks4" ||
        proxy_type === "socks5"
    );

    var is_http = (
        proxy_type === "http" ||
        proxy_type === "https" ||
        proxy_type === ""
    );

    console.log("[+] Proxy type detected: " + proxy_type + " | socks=" + is_socks + " | http=" + is_http);

    function shouldReplaceHost(prop) {
        if (is_socks) {
            return prop === "socksProxyHost";
        }

        return (
            prop === "http.proxyHost" ||
            prop === "https.proxyHost"
        );
    }

    function shouldReplacePort(prop) {
        if (is_socks) {
            return prop === "socksProxyPort";
        }

        return (
            prop === "http.proxyPort" ||
            prop === "https.proxyPort"
        );
    }

    function replacementValueFor(prop) {
        if (shouldReplaceHost(prop)) {
            console.log("[~] Intercepted getProperty(" + prop + ") -> " + proxy_host);
            return proxy_host;
        }

        if (shouldReplacePort(prop)) {
            console.log("[~] Intercepted getProperty(" + prop + ") -> " + proxy_port);
            return proxy_port;
        }

        // If SOCKS mode is active, clear HTTP/HTTPS proxy properties.
        if (is_socks && (
            prop === "http.proxyHost" ||
            prop === "https.proxyHost" ||
            prop === "http.proxyPort" ||
            prop === "https.proxyPort"
        )) {
            console.log("[~] Intercepted getProperty(" + prop + ") -> cleared because SOCKS mode is active");
            return null;
        }

        // If HTTP/HTTPS mode is active, clear SOCKS proxy properties.
        if (is_http && (
            prop === "socksProxyHost" ||
            prop === "socksProxyPort"
        )) {
            console.log("[~] Intercepted getProperty(" + prop + ") -> cleared because HTTP/HTTPS mode is active");
            return null;
        }

        return undefined;
    }

    // Hook System.getProperty(String)
    System.getProperty.overload('java.lang.String').implementation = function (prop) {
        var replacement = replacementValueFor(String(prop));

        if (replacement !== undefined) {
            return replacement;
        }

        return this.getProperty(prop);
    };

    // Hook System.getProperty(String, String)
    System.getProperty.overload('java.lang.String', 'java.lang.String').implementation = function (prop, defValue) {
        var replacement = replacementValueFor(String(prop));

        if (replacement !== undefined) {
            return replacement;
        }

        return this.getProperty(prop, defValue);
    };

    // Hook System.setProperty(String, String) so app code cannot overwrite our route.
    System.setProperty.overload('java.lang.String', 'java.lang.String').implementation = function (prop, value) {
        prop = String(prop);

        if (shouldReplaceHost(prop)) {
            console.log("[~] Blocked setProperty(" + prop + ", " + value + ") -> forcing " + proxy_host);
            return this.setProperty(prop, proxy_host);
        }

        if (shouldReplacePort(prop)) {
            console.log("[~] Blocked setProperty(" + prop + ", " + value + ") -> forcing " + proxy_port);
            return this.setProperty(prop, proxy_port);
        }

        return this.setProperty(prop, value);
    };

    // Seed properties immediately.
    try {
        if (is_socks) {
            System.setProperty("socksProxyHost", proxy_host);
            System.setProperty("socksProxyPort", proxy_port);

            System.clearProperty("http.proxyHost");
            System.clearProperty("http.proxyPort");
            System.clearProperty("https.proxyHost");
            System.clearProperty("https.proxyPort");

            console.log("[+] Seeded SOCKS Java properties: socksProxyHost/socksProxyPort");
        } else {
            System.setProperty("http.proxyHost", proxy_host);
            System.setProperty("http.proxyPort", proxy_port);
            System.setProperty("https.proxyHost", proxy_host);
            System.setProperty("https.proxyPort", proxy_port);

            System.clearProperty("socksProxyHost");
            System.clearProperty("socksProxyPort");

            console.log("[+] Seeded HTTP/HTTPS Java properties: http.proxyHost/http.proxyPort/https.proxyHost/https.proxyPort");
        }
    } catch (e) {
        console.log("[!] Failed to seed Java proxy properties: " + e);
    }

    console.log("[+] Java property proxy hook is installed.");
});
