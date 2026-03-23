<?php
/**
 * Plugin Name: WP Security Scanner
 * Plugin URI: https://example.com/wp-security-scanner
 * Description: Runs a basic WordPress security scan and stores scan history.
 * Version: 1.0.0
 * Author: WP Security Scanner Team
 * Text Domain: wp-security-scanner
 * Requires at least: 6.0
 * Requires PHP: 7.4
 */

if (! defined('ABSPATH')) {
    exit;
}

/**
 * Main plugin class.
 */
class Wpss_Security_Scanner {
    /**
     * DB table suffix (prefix is added dynamically by $wpdb).
     */
    const TABLE_SUFFIX = 'security_scan_results';

    /**
     * Boot plugin hooks.
     */
    public static function init() {
        add_action('admin_menu', array(__CLASS__, 'wpss_register_admin_menu'));
        add_action('admin_enqueue_scripts', array(__CLASS__, 'wpss_enqueue_admin_assets'));
        add_shortcode('wp_security_report', array(__CLASS__, 'wpss_render_security_report_shortcode'));
    }

    /**
     * Activation callback: create scan results table.
     */
    public static function wpss_activate() {
        global $wpdb;

        $table_name      = $wpdb->prefix . self::TABLE_SUFFIX;
        $charset_collate = $wpdb->get_charset_collate();

        require_once ABSPATH . 'wp-admin/includes/upgrade.php';

        $sql = "CREATE TABLE {$table_name} (
            id bigint(20) unsigned NOT NULL AUTO_INCREMENT,
            scan_url varchar(255) NOT NULL,
            scan_data longtext NOT NULL,
            scan_date datetime NOT NULL DEFAULT CURRENT_TIMESTAMP,
            PRIMARY KEY  (id),
            KEY scan_url (scan_url)
        ) {$charset_collate};";

        dbDelta($sql);
    }

    /**
     * Deactivation callback: drop table per plugin requirement.
     */
    public static function wpss_deactivate() {
        global $wpdb;

        $table_name = $wpdb->prefix . self::TABLE_SUFFIX;
        $wpdb->query('DROP TABLE IF EXISTS `' . esc_sql($table_name) . '`');
    }

    /**
     * Add Tools > WP Security Scanner page.
     */
    public static function wpss_register_admin_menu() {
        add_management_page(
            __('WP Security Scanner', 'wp-security-scanner'),
            __('WP Security Scanner', 'wp-security-scanner'),
            'manage_options',
            'wpss-security-scanner',
            array(__CLASS__, 'wpss_render_admin_page')
        );
    }

    /**
     * Load admin CSS/JS only on plugin screen.
     */
    public static function wpss_enqueue_admin_assets($hook_suffix) {
        if ($hook_suffix !== 'tools_page_wpss-security-scanner') {
            return;
        }

        wp_enqueue_style(
            'wpss-admin-style',
            plugin_dir_url(__FILE__) . 'assets/css/admin.css',
            array(),
            '1.0.0'
        );

        wp_enqueue_script(
            'wpss-admin-script',
            plugin_dir_url(__FILE__) . 'assets/js/admin.js',
            array('jquery'),
            '1.0.0',
            true
        );
    }

    /**
     * Render scanner UI and scan output.
     */
    public static function wpss_render_admin_page() {
        if (! current_user_can('manage_options')) {
            wp_die(esc_html__('You are not allowed to run this scan.', 'wp-security-scanner'));
        }

        $default_url = home_url('/');
        $scan_url    = $default_url;
        $results     = array();

        if (
            isset($_POST['wpss_run_scan'])
            && isset($_POST['wpss_scan_nonce'])
            && wp_verify_nonce(sanitize_text_field(wp_unslash($_POST['wpss_scan_nonce'])), 'wpss_run_scan_action')
        ) {
            $scan_url = isset($_POST['wpss_scan_url']) ? esc_url_raw(wp_unslash($_POST['wpss_scan_url'])) : $default_url;
            $scan_url = self::wpss_normalize_url($scan_url);

            if (empty($scan_url)) {
                $scan_url = $default_url;
            }

            $results = self::wpss_run_scan($scan_url);
            self::wpss_store_scan_results($scan_url, $results);
        }

        echo '<div class="wrap wpss-wrap">';
        echo '<h1>' . esc_html__('WP Security Scanner', 'wp-security-scanner') . '</h1>';
        echo '<form method="post" class="wpss-form">';
        wp_nonce_field('wpss_run_scan_action', 'wpss_scan_nonce');
        echo '<label for="wpss_scan_url"><strong>' . esc_html__('Site URL', 'wp-security-scanner') . '</strong></label>';
        echo '<input type="url" id="wpss_scan_url" name="wpss_scan_url" value="' . esc_attr($scan_url) . '" class="regular-text" required />';
        echo '<p><button type="submit" name="wpss_run_scan" class="button button-primary">' . esc_html__('Run Scan', 'wp-security-scanner') . '</button></p>';
        echo '</form>';

        if (! empty($results)) {
            self::wpss_render_scan_results($results);
        }

        echo '</div>';
    }

    /**
     * Run full scanner checks and return structured results.
     */
    public static function wpss_run_scan($scan_url) {
        $results = array();

        // Remote request used for checking headers.
        $response = wp_remote_head($scan_url, array('timeout' => 12, 'redirection' => 5));
        if (is_wp_error($response)) {
            $response = wp_remote_get($scan_url, array('timeout' => 12, 'redirection' => 5));
        }

        $headers = is_wp_error($response) ? array() : wp_remote_retrieve_headers($response);

        $results['https_enabled'] = self::wpss_get_status_item(
            self::wpss_url_uses_https($scan_url) ? 'passed' : 'failed',
            __('HTTPS/SSL enabled', 'wp-security-scanner'),
            self::wpss_url_uses_https($scan_url)
                ? __('The scanned URL uses HTTPS.', 'wp-security-scanner')
                : __('Use an SSL certificate and force HTTPS in WordPress settings and server config.', 'wp-security-scanner')
        );

        $security_headers = array(
            'content-security-policy'  => __('Content-Security-Policy', 'wp-security-scanner'),
            'x-frame-options'          => __('X-Frame-Options', 'wp-security-scanner'),
            'x-xss-protection'         => __('X-XSS-Protection', 'wp-security-scanner'),
            'strict-transport-security' => __('Strict-Transport-Security', 'wp-security-scanner'),
        );

        foreach ($security_headers as $header_key => $header_label) {
            $has_header                                = self::wpss_has_header($headers, $header_key);
            $results['header_' . $header_key] = self::wpss_get_status_item(
                $has_header ? 'passed' : 'warning',
                sprintf(__('Security header: %s', 'wp-security-scanner'), $header_label),
                $has_header
                    ? __('Header detected in server response.', 'wp-security-scanner')
                    : __('Add this header in your server or CDN configuration.', 'wp-security-scanner')
            );
        }

        $xmlrpc_url      = trailingslashit($scan_url) . 'xmlrpc.php';
        $xmlrpc_response = wp_remote_get($xmlrpc_url, array('timeout' => 10, 'redirection' => 3));
        $xmlrpc_enabled  = false;

        if (! is_wp_error($xmlrpc_response)) {
            $xmlrpc_status  = (int) wp_remote_retrieve_response_code($xmlrpc_response);
            $xmlrpc_enabled = in_array($xmlrpc_status, array(200, 401, 403, 405), true);
        }

        $results['xmlrpc_enabled'] = self::wpss_get_status_item(
            $xmlrpc_enabled ? 'warning' : 'passed',
            __('XML-RPC endpoint status', 'wp-security-scanner'),
            $xmlrpc_enabled
                ? __('XML-RPC appears enabled. Disable it if not needed to reduce attack surface.', 'wp-security-scanner')
                : __('XML-RPC endpoint appears inaccessible.', 'wp-security-scanner')
        );

        $debug_mode = defined('WP_DEBUG') && WP_DEBUG;
        $results['wp_debug_mode'] = self::wpss_get_status_item(
            $debug_mode ? 'warning' : 'passed',
            __('WordPress debug mode', 'wp-security-scanner'),
            $debug_mode
                ? __('WP_DEBUG is enabled. Disable in production environments.', 'wp-security-scanner')
                : __('WP_DEBUG is disabled.', 'wp-security-scanner')
        );

        $results['plugin_updates'] = self::wpss_check_plugin_updates();
        $results['theme_updates']  = self::wpss_check_theme_updates();

        return $results;
    }

    /**
     * Plugin update + auto-update check.
     */
    private static function wpss_check_plugin_updates() {
        if (! function_exists('get_plugins')) {
            require_once ABSPATH . 'wp-admin/includes/plugin.php';
        }

        wp_update_plugins();

        $plugins               = get_plugins();
        $updates               = get_site_transient('update_plugins');
        $auto_update_enabled   = (array) get_site_option('auto_update_plugins', array());
        $outdated_plugins      = array();
        $disabled_auto_updates = array();

        foreach ($plugins as $plugin_file => $plugin_data) {
            $plugin_name = isset($plugin_data['Name']) ? $plugin_data['Name'] : $plugin_file;

            if (empty($auto_update_enabled) || ! in_array($plugin_file, $auto_update_enabled, true)) {
                $disabled_auto_updates[] = $plugin_name;
            }

            if (isset($updates->response[$plugin_file])) {
                $outdated_plugins[] = $plugin_name;
            }
        }

        $status = (empty($outdated_plugins) && empty($disabled_auto_updates)) ? 'passed' : 'warning';

        return self::wpss_get_status_item(
            $status,
            __('Plugin update posture', 'wp-security-scanner'),
            empty($outdated_plugins) && empty($disabled_auto_updates)
                ? __('All installed plugins are current and auto-updates are enabled.', 'wp-security-scanner')
                : sprintf(
                    /* translators: 1: outdated plugin list, 2: auto-update disabled plugin list */
                    __('Outdated plugins: %1$s. Auto-updates disabled: %2$s. Enable updates and patch quickly.', 'wp-security-scanner'),
                    empty($outdated_plugins) ? __('None', 'wp-security-scanner') : implode(', ', $outdated_plugins),
                    empty($disabled_auto_updates) ? __('None', 'wp-security-scanner') : implode(', ', $disabled_auto_updates)
                )
        );
    }

    /**
     * Theme update + auto-update check.
     */
    private static function wpss_check_theme_updates() {
        wp_update_themes();

        $themes                = wp_get_themes();
        $updates               = get_site_transient('update_themes');
        $auto_update_enabled   = (array) get_site_option('auto_update_themes', array());
        $outdated_themes       = array();
        $disabled_auto_updates = array();

        foreach ($themes as $stylesheet => $theme_obj) {
            $theme_name = $theme_obj->get('Name');

            if (empty($auto_update_enabled) || ! in_array($stylesheet, $auto_update_enabled, true)) {
                $disabled_auto_updates[] = $theme_name;
            }

            if (isset($updates->response[$stylesheet])) {
                $outdated_themes[] = $theme_name;
            }
        }

        $status = (empty($outdated_themes) && empty($disabled_auto_updates)) ? 'passed' : 'warning';

        return self::wpss_get_status_item(
            $status,
            __('Theme update posture', 'wp-security-scanner'),
            empty($outdated_themes) && empty($disabled_auto_updates)
                ? __('All installed themes are current and auto-updates are enabled.', 'wp-security-scanner')
                : sprintf(
                    /* translators: 1: outdated theme list, 2: auto-update disabled theme list */
                    __('Outdated themes: %1$s. Auto-updates disabled: %2$s. Enable updates and patch quickly.', 'wp-security-scanner'),
                    empty($outdated_themes) ? __('None', 'wp-security-scanner') : implode(', ', $outdated_themes),
                    empty($disabled_auto_updates) ? __('None', 'wp-security-scanner') : implode(', ', $disabled_auto_updates)
                )
        );
    }

    /**
     * Save result payload in DB table.
     */
    private static function wpss_store_scan_results($scan_url, $scan_data) {
        global $wpdb;

        $wpdb->insert(
            $wpdb->prefix . self::TABLE_SUFFIX,
            array(
                'scan_url'  => $scan_url,
                'scan_data' => wp_json_encode($scan_data),
                'scan_date' => current_time('mysql'),
            ),
            array('%s', '%s', '%s')
        );
    }

    /**
     * Render latest results table.
     */
    private static function wpss_render_scan_results($results) {
        echo '<h2>' . esc_html__('Scan Results', 'wp-security-scanner') . '</h2>';
        echo '<table class="widefat striped wpss-results-table">';
        echo '<thead><tr><th>' . esc_html__('Check', 'wp-security-scanner') . '</th><th>' . esc_html__('Status', 'wp-security-scanner') . '</th><th>' . esc_html__('Recommendation', 'wp-security-scanner') . '</th></tr></thead><tbody>';

        foreach ($results as $result) {
            $status_class = 'wpss-status-' . sanitize_html_class($result['status']);
            echo '<tr>';
            echo '<td>' . esc_html($result['title']) . '</td>';
            echo '<td><span class="wpss-status-pill ' . esc_attr($status_class) . '">' . esc_html(ucfirst($result['status'])) . '</span></td>';
            echo '<td>' . esc_html($result['recommendation']) . '</td>';
            echo '</tr>';
        }

        echo '</tbody></table>';
    }

    /**
     * Shortcode: output latest report for current site URL.
     */
    public static function wpss_render_security_report_shortcode() {
        global $wpdb;

        $scan_url   = self::wpss_normalize_url(home_url('/'));
        $table_name = $wpdb->prefix . self::TABLE_SUFFIX;

        $row = $wpdb->get_row(
            $wpdb->prepare(
                "SELECT scan_data, scan_date FROM {$table_name} WHERE scan_url = %s ORDER BY id DESC LIMIT 1",
                $scan_url
            ),
            ARRAY_A
        );

        if (empty($row)) {
            return '<p>' . esc_html__('No scan report found yet for this site.', 'wp-security-scanner') . '</p>';
        }

        $scan_data = json_decode($row['scan_data'], true);
        if (! is_array($scan_data)) {
            return '<p>' . esc_html__('Latest scan data is not readable.', 'wp-security-scanner') . '</p>';
        }

        ob_start();
        echo '<div class="wpss-shortcode-report">';
        echo '<h3>' . esc_html__('Latest Security Report', 'wp-security-scanner') . '</h3>';
        echo '<p><em>' . sprintf(esc_html__('Scan date: %s', 'wp-security-scanner'), esc_html($row['scan_date'])) . '</em></p>';
        echo '<ul>';

        foreach ($scan_data as $item) {
            echo '<li><strong>' . esc_html($item['title']) . ':</strong> ' . esc_html(ucfirst($item['status'])) . ' - ' . esc_html($item['recommendation']) . '</li>';
        }

        echo '</ul>';
        echo '</div>';

        return ob_get_clean();
    }

    /**
     * Normalize URL for consistent storage.
     */
    private static function wpss_normalize_url($url) {
        $url = esc_url_raw($url);
        return untrailingslashit($url);
    }

    /**
     * Utility: return status payload.
     */
    private static function wpss_get_status_item($status, $title, $recommendation) {
        return array(
            'status'         => $status,
            'title'          => $title,
            'recommendation' => $recommendation,
        );
    }

    /**
     * Utility: detect if URL is https.
     */
    private static function wpss_url_uses_https($url) {
        return 'https' === wp_parse_url($url, PHP_URL_SCHEME);
    }

    /**
     * Utility: case-insensitive header match.
     */
    private static function wpss_has_header($headers, $header_key) {
        if (empty($headers)) {
            return false;
        }

        foreach ($headers as $key => $value) {
            if (strtolower($key) === strtolower($header_key) && ! empty($value)) {
                return true;
            }
        }

        return false;
    }
}

register_activation_hook(__FILE__, array('Wpss_Security_Scanner', 'wpss_activate'));
register_deactivation_hook(__FILE__, array('Wpss_Security_Scanner', 'wpss_deactivate'));
Wpss_Security_Scanner::init();
