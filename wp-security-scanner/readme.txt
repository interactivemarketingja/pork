=== WP Security Scanner ===
Contributors: wp-security-scanner-team
Tags: security, scanner, hardening, wordpress
Requires at least: 6.0
Tested up to: 6.6
Requires PHP: 7.4
Stable tag: 1.0.0
License: GPLv2 or later
License URI: https://www.gnu.org/licenses/gpl-2.0.html

A lightweight security scanner for WordPress that checks HTTPS, security headers, XML-RPC exposure, debug mode, and update posture.

== Description ==
WP Security Scanner adds an admin page under **Tools > WP Security Scanner** and allows administrators to run a quick site security scan.

Checks included:
- HTTPS/SSL enabled check
- HTTP security headers (CSP, X-Frame-Options, X-XSS-Protection, HSTS)
- XML-RPC endpoint exposure
- WP_DEBUG status
- Installed plugin/theme update and auto-update posture

The plugin stores each scan result in a custom database table and exposes the latest report through the shortcode `[wp_security_report]`.

== Installation ==
1. Upload the `wp-security-scanner` folder to `/wp-content/plugins/`.
2. Activate the plugin through the **Plugins** menu in WordPress.
3. Go to **Tools > WP Security Scanner**.
4. Enter a URL (or keep the current site URL) and click **Run Scan**.

== Usage ==
- Run scans from **Tools > WP Security Scanner**.
- Review statuses: Passed, Warning, Failed.
- Follow recommendations shown for any warning/failure.
- Add shortcode `[wp_security_report]` to a page/post to show the latest report for the current site.

== Notes ==
- On activation, the plugin creates table `{prefix}security_scan_results` (default name: `wp_security_scan_results`).
- On deactivation, the plugin drops this table per plugin behavior requirement.
