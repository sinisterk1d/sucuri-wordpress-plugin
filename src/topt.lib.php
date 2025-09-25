<?php
// Abort if the file is loaded out of context.
if (!defined('SUCURISCAN_INIT') || SUCURISCAN_INIT !== true) {
    if (!headers_sent()) {
        /* Report invalid access if possible. */
        header('HTTP/1.1 403 Forbidden');
    }
    exit(1);
}

/**
 * This class implements Two-Factor Authentication (2FA) using TOTP (Time-based One-Time Password).
 */
class SucuriScanTwoFactor extends SucuriScan
{
    const OPTION_PREFIX = 'sucuriscan_totp_';
    const SECRET_META_KEY = 'sucuriscan_topt_secret_key';
    const LAST_SUCCESS_META_KEY = 'sucuriscan_topt_last_success';
    const LOGIN_TOKEN_TTL = 600;
    const LOGIN_TOKEN_MAX_ATTEMPTS = 5;

    public static function add_hooks()
    {
        add_filter('authenticate', array(__CLASS__, 'authenticate'), 30, 3);
        add_action('login_form_sucuri-2fa', array(__CLASS__, 'login_form_2fa'));
        add_action('login_form_sucuri-2fa-setup', array(__CLASS__, 'login_form_2fa_setup'));
        add_action('login_head', array(__CLASS__, 'brand_login_logo'));
        add_action('show_user_profile', array(__CLASS__, 'render_user_profile_section'));
        add_action('edit_user_profile', array(__CLASS__, 'render_user_profile_section'));
        add_action('personal_options_update', array(__CLASS__, 'save_user_profile_section'));
        add_action('edit_user_profile_update', array(__CLASS__, 'save_user_profile_section'));
        add_action('admin_enqueue_scripts', array(__CLASS__, 'enqueue_profile_assets'));
        add_action('wp_ajax_sucuri_profile_2fa_enable', array(__CLASS__, 'ajax_profile_enable'));
        add_action('wp_ajax_sucuri_profile_2fa_reset', array(__CLASS__, 'ajax_profile_reset'));
    }

    protected static $profile_error_queue = array();
    protected static $profile_error_hook_registered = false;

    protected static function add_profile_error($code, $message)
    {
        self::$profile_error_queue[] = array('code' => (string) $code, 'message' => (string) $message);

        if (!self::$profile_error_hook_registered) {
            add_action('user_profile_update_errors', array(__CLASS__, 'on_profile_update_errors'));

            self::$profile_error_hook_registered = true;
        }
    }

    public static function on_profile_update_errors($errors)
    {
        if (!is_array(self::$profile_error_queue)) {
            return;
        }

        foreach (self::$profile_error_queue as $item) {
            if (isset($item['code']) && isset($item['message'])) {
                $errors->add($item['code'], $item['message']);
            }
        }

        self::$profile_error_queue = array();
    }


    protected static function is_enforced_for_user($user_id)
    {
        $user_id = (int) $user_id;

        if ($user_id <= 0) {
            return false;
        }

        $mode = SucuriScanOption::getOption(':twofactor_mode');

        if (!$mode) {
            $mode = 'current_user';
        }

        if ($mode === 'disabled') {
            return false;
        }

        if ($mode === 'all_users') {
            return true;
        }

        // TODO: Get rid of this current user and let's re-use twofactor_users option.
        if ($mode === 'current_user') {
            $configured_user = (int) SucuriScanOption::getOption(':twofactor_user');
            return ($configured_user > 0) ? ($configured_user === $user_id) : true;
        }

        if ($mode === 'selected_users') {
            $list = SucuriScanOption::getOption(':twofactor_users');

            if (is_array($list)) {
                return in_array($user_id, array_map('intval', $list), true);
            }
        }

        return false;
    }


    public static function enqueue_profile_assets($hook)
    {
        if (!is_admin()) {
            return;
        }

        if ($hook !== 'profile.php' && $hook !== 'user-edit.php') {
            return;
        }

        $target_user = 0;

        if ($hook === 'profile.php') {
            $target_user = get_current_user_id();
        } elseif ($hook === 'user-edit.php') {
            $req_user = SucuriScanRequest::get('user_id', '[0-9]+');

            if ($req_user !== false) {
                $target_user = (int) $req_user;
            }
        }

        if (!self::is_enforced_for_user($target_user)) {
            return;
        }

        // TODO: Let's clarify whether we want this here or in interface library.
        if (!wp_script_is('sucuriscan-qrcode', 'registered')) {
            wp_register_script(
                'sucuriscan-qrcode',
                trailingslashit(SUCURISCAN_URL) . 'inc/js/qr.js',
                array(),
                method_exists('SucuriScan', 'fileVersion') ? SucuriScan::fileVersion('inc/js/qr.js') : false
            );
        }

        wp_enqueue_script('sucuriscan-qrcode');
    }

    protected static function create_login_token($user_id, $remember, $redirect_to, $secret_for_setup = '')
    {
        $token = wp_generate_password(64, false, false);

        $data = array(
            'user_id' => (int) $user_id,
            'remember' => (bool) $remember,
            'redirect' => (string) $redirect_to,
            'secret' => (string) $secret_for_setup,
            'created' => time(),
            'attempts' => 0,
            'ua' => isset($_SERVER['HTTP_USER_AGENT']) ? (string) $_SERVER['HTTP_USER_AGENT'] : '',
        );

        set_transient('sucuri_2fa_' . $token, $data, self::LOGIN_TOKEN_TTL);

        return $token;
    }

    protected static function get_login_session($token)
    {
        if (!$token) {
            return false;
        }

        $data = get_transient('sucuri_2fa_' . $token);

        return is_array($data) ? $data : false;
    }

    protected static function clear_login_session($token)
    {
        if ($token) {
            delete_transient('sucuri_2fa_' . $token);
        }
    }

    protected static function update_login_session($token, $data)
    {
        if (!$token || !is_array($data)) {
            return;
        }

        $created = isset($data['created']) ? (int) $data['created'] : time();
        $elapsed = max(0, time() - $created);
        $ttl = max(60, self::LOGIN_TOKEN_TTL - $elapsed);
        set_transient('sucuri_2fa_' . $token, $data, $ttl);
    }


    public static function authenticate($user, $username, $password)
    {
        if ($user instanceof WP_Error || empty($username)) {
            return $user;
        }

        if (!$user instanceof WP_User) {
            return $user;
        }

        $user_id = (int) $user->ID;

        if ($user_id <= 0) {
            return $user;
        }

        $mode = SucuriScanOption::getOption(':twofactor_mode');

        if (!$mode) {
            $mode = 'current_user';
        }

        if ($mode === 'disabled') {
            return $user;
        }

        $enforce = false;

        if ($mode === 'all_users') {
            $enforce = true;
        } elseif ($mode === 'current_user') {
            $configured_user = (int) SucuriScanOption::getOption(':twofactor_user');
            $enforce = ($configured_user > 0) ? ($configured_user === $user_id) : true;
        } elseif ($mode === 'selected_users') {
            $list = SucuriScanOption::getOption(':twofactor_users');

            if (is_array($list)) {
                $enforce = in_array($user_id, array_map('intval', $list), true);
            }
        }

        if (!$enforce) {
            return $user;
        }

        $secret_key = self::get_user_totp_key($user_id);

        $remember = (SucuriScanRequest::post('rememberme') !== false);
        $redirect_to_raw = SucuriScanRequest::getOrPost('redirect_to');
        $redirect_to = $redirect_to_raw !== false ? (string) $redirect_to_raw : admin_url();

        $redirect_to = wp_validate_redirect($redirect_to, admin_url());
        if (empty($secret_key)) {
            try {
                $setup_secret = SucuriScanTOTP::generate_key();
            } catch (Exception $e) {
                $setup_secret = '';
            }

            if (empty($setup_secret)) {
                return new WP_Error('sucuriscan_2fa_error', esc_html__('Unable to initialize two-factor setup.', 'sucuri-scanner'));
            }

            $token = self::create_login_token($user_id, $remember, $redirect_to, $setup_secret);
            $url = wp_login_url();
            $url = add_query_arg(array('action' => 'sucuri-2fa-setup', 'token' => rawurlencode($token)), $url);

            wp_safe_redirect($url);
            exit;
        }

        $token = self::create_login_token($user_id, $remember, $redirect_to, '');
        $url = wp_login_url();
        $url = add_query_arg(array('action' => 'sucuri-2fa', 'token' => rawurlencode($token)), $url);
        wp_safe_redirect($url);
        exit;
    }

    public static function login_form_2fa()
    {
        $token_raw = SucuriScanRequest::getOrPost('token', '[A-Za-z0-9]{10,128}');
        $token = $token_raw !== false ? (string) $token_raw : '';
        $session = self::get_login_session($token);

        if (!$session || empty($session['user_id'])) {
            wp_safe_redirect(wp_login_url());
            exit;
        }

        $user_id = (int) $session['user_id'];
        $redirect_to = (string) (isset($session['redirect']) ? $session['redirect'] : admin_url());
        $remember = (bool) (isset($session['remember']) ? $session['remember'] : false);

        $ua = isset($_SERVER['HTTP_USER_AGENT']) ? (string) $_SERVER['HTTP_USER_AGENT'] : '';
        if (!empty($session['ua']) && $session['ua'] !== $ua) {
            self::clear_login_session($token);
            wp_safe_redirect(wp_login_url());
            exit;
        }

        if ('POST' === $_SERVER['REQUEST_METHOD']) {
            check_admin_referer('sucuri_2fa_verify');
            $code_raw = SucuriScanRequest::post('sucuriscan_totp_code', '[0-9 ]+');
            $code = $code_raw !== false ? preg_replace('/\D+/', '', (string) $code_raw) : '';

            if (strlen($code) !== SucuriScanTOTP::DEFAULT_DIGIT_COUNT) {
                $session['attempts'] = isset($session['attempts']) ? ((int) $session['attempts'] + 1) : 1;

                if ($session['attempts'] >= self::LOGIN_TOKEN_MAX_ATTEMPTS) {
                    self::clear_login_session($token);
                    wp_safe_redirect(wp_login_url());
                    exit;
                }

                self::update_login_session($token, $session);
                $error = esc_html__('Invalid two-factor authentication code.', 'sucuri-scanner');
            } else {
                $secret_key = self::get_user_totp_key($user_id);

                if (empty($secret_key)) {
                    self::clear_login_session($token);
                    wp_safe_redirect(add_query_arg(array('action' => 'sucuri-2fa-setup'), wp_login_url()));
                    exit;
                }

                $valid_ts = false;

                try {
                    $valid_ts = (strlen($code) === SucuriScanTOTP::DEFAULT_DIGIT_COUNT) ? SucuriScanTOTP::get_authcode_valid_ticktime($secret_key, $code) : false;
                } catch (Exception $e) {
                    $valid_ts = false;
                }

                if ($valid_ts) {
                    $last = (int) get_user_meta($user_id, self::LAST_SUCCESS_META_KEY, true);

                    if ($last && $last >= $valid_ts) {
                        $valid_ts = false;
                    }
                }

                if ($valid_ts) {
                    update_user_meta($user_id, self::LAST_SUCCESS_META_KEY, $valid_ts);
                    self::clear_login_session($token);
                    wp_set_current_user($user_id);
                    wp_set_auth_cookie($user_id, $remember);
                    wp_safe_redirect($redirect_to);
                    exit;
                }

                $session['attempts'] = isset($session['attempts']) ? ((int) $session['attempts'] + 1) : 1;

                if ($session['attempts'] >= self::LOGIN_TOKEN_MAX_ATTEMPTS) {
                    self::clear_login_session($token);
                    wp_safe_redirect(wp_login_url());
                    exit;
                }

                self::update_login_session($token, $session);

                $error = esc_html__('Invalid two-factor authentication code.', 'sucuri-scanner');
            }
        }

        $message_html = SucuriScanTemplate::getSnippet('login-message', array(
            'Message' => esc_html__('Enter the 6-digit code from your authenticator app to continue.', 'sucuri-scanner'),
        ));

        if (!empty($error)) {
            $message_html = SucuriScanTemplate::getSnippet('login-error', array(
                'Error' => esc_html($error),
            )) . $message_html;
        }

        login_header(esc_html__('Two-Factor Authentication', 'sucuri-scanner'), $message_html);

        $params = array(
            'ActionURL' => add_query_arg(array('action' => 'sucuri-2fa', 'token' => rawurlencode($token)), wp_login_url()),
            'NonceField' => wp_nonce_field('sucuri_2fa_verify', '_wpnonce', true, false),
        );

        echo SucuriScanTemplate::getSection('login-2fa', $params);

        login_footer();
        exit;
    }

    public static function login_form_2fa_setup()
    {
        $token_raw = SucuriScanRequest::getOrPost('token', '[A-Za-z0-9]{10,128}');
        $token = $token_raw !== false ? (string) $token_raw : '';
        $session = self::get_login_session($token);

        if (!$session || empty($session['user_id']) || empty($session['secret'])) {
            wp_safe_redirect(wp_login_url());
            exit;
        }

        $user_id = (int) $session['user_id'];
        $redirect_to = (string) (isset($session['redirect']) ? $session['redirect'] : admin_url());
        $remember = (bool) (isset($session['remember']) ? $session['remember'] : false);
        $secret_key = (string) $session['secret'];

        $ua = isset($_SERVER['HTTP_USER_AGENT']) ? (string) $_SERVER['HTTP_USER_AGENT'] : '';
        if (!empty($session['ua']) && $session['ua'] !== $ua) {
            self::clear_login_session($token);
            wp_safe_redirect(wp_login_url());
            exit;
        }

        $user = get_user_by('id', $user_id);
        $otpauth = SucuriScanTOTP::generate_qr_code_url($user, $secret_key);

        if ('POST' === $_SERVER['REQUEST_METHOD']) {
            check_admin_referer('sucuri_2fa_setup');
            $code_raw = SucuriScanRequest::post('sucuriscan_totp_code', '[0-9 ]+');
            $code = $code_raw !== false ? preg_replace('/\D+/', '', (string) $code_raw) : '';

            if (strlen($code) !== SucuriScanTOTP::DEFAULT_DIGIT_COUNT) {
                $session['attempts'] = isset($session['attempts']) ? ((int) $session['attempts'] + 1) : 1;

                if ($session['attempts'] >= self::LOGIN_TOKEN_MAX_ATTEMPTS) {
                    self::clear_login_session($token);
                    wp_safe_redirect(wp_login_url());
                    exit;
                }

                self::update_login_session($token, $session);
                $error = esc_html__('Invalid code. Make sure you scanned the QR and your device time is correct.', 'sucuri-scanner');
            } else {
                $valid_ts = false;

                try {
                    $valid_ts = (strlen($code) === SucuriScanTOTP::DEFAULT_DIGIT_COUNT) ? SucuriScanTOTP::get_authcode_valid_ticktime($secret_key, $code) : false;
                } catch (Exception $e) {
                    $valid_ts = false;
                }

                if ($valid_ts) {
                    self::store_user_totp_key($user_id, $secret_key);
                    update_user_meta($user_id, self::LAST_SUCCESS_META_KEY, $valid_ts);

                    $current_mode = SucuriScanOption::getOption(':twofactor_mode');

                    if (!$current_mode) {
                        $current_mode = 'current_user';
                    }

                    if ($current_mode !== 'all_users') {
                        SucuriScanOption::updateOption(':twofactor_mode', 'current_user');
                        SucuriScanOption::updateOption(':twofactor_user', (int) $user_id);
                    }

                    self::clear_login_session($token);
                    wp_set_current_user($user_id);
                    wp_set_auth_cookie($user_id, $remember);
                    wp_safe_redirect($redirect_to);
                    exit;
                }

                $session['attempts'] = isset($session['attempts']) ? ((int) $session['attempts'] + 1) : 1;

                if ($session['attempts'] >= self::LOGIN_TOKEN_MAX_ATTEMPTS) {
                    self::clear_login_session($token);
                    wp_safe_redirect(wp_login_url());
                    exit;
                }

                self::update_login_session($token, $session);
                $error = esc_html__('Invalid code. Make sure you scanned the QR and your device time is correct.', 'sucuri-scanner');
            }
        }

        $message_html = SucuriScanTemplate::getSnippet('login-message', array(
            'Message' => esc_html__('Set up two-factor authentication. Scan the QR code with your authenticator app, then enter the 6-digit code to continue.', 'sucuri-scanner'),
        ));

        if (!empty($error)) {
            $message_html = SucuriScanTemplate::getSnippet('login-error', array(
                'Error' => esc_html($error),
            )) . $message_html;
        }

        login_header(esc_html__('Set up Two-Factor Authentication', 'sucuri-scanner'), $message_html);

        $params = array(
            'ActionURL' => add_query_arg(array('action' => 'sucuri-2fa-setup', 'token' => rawurlencode($token)), wp_login_url()),
            'NonceField' => wp_nonce_field('sucuri_2fa_setup', '_wpnonce', true, false),
            'SecretManual' => $secret_key,
            'OtpauthURI' => $otpauth,
        );

        echo SucuriScanTemplate::getSection('login-2fa-setup', $params);

        login_footer();
        exit;
    }


    public static function brand_login_logo()
    {
        $action_raw = SucuriScanRequest::getOrPost('action', '[a-z0-9\-_]+');
        $action = $action_raw !== false ? (string) $action_raw : '';

        if ($action !== 'sucuri-2fa' && $action !== 'sucuri-2fa-setup') {
            return;
        }

        $logo = trailingslashit(SUCURISCAN_URL) . 'inc/images/pluginlogo.png';

        echo SucuriScanTemplate::getSnippet('login-brand', array(
            'LogoURL' => esc_url($logo),
        ));
    }

    public static function get_user_totp_key($user_id)
    {
        return (string) get_user_meta($user_id, self::SECRET_META_KEY, true);
    }

    public static function store_user_totp_key($user_id, $key)
    {
        $existingKey = self::get_user_totp_key($user_id);

        if (empty($existingKey)) {
            return (bool) add_user_meta($user_id, self::SECRET_META_KEY, $key);
        }

        return (bool) update_user_meta($user_id, self::SECRET_META_KEY, $key);
    }


    public static function render_user_profile_section($user)
    {
        if (!($user instanceof WP_User)) {
            return;
        }

        $current_id = get_current_user_id();
        $is_self = ((int) $user->ID === (int) $current_id);
        $can_manage_users = current_user_can('edit_users');

        if (!self::is_enforced_for_user((int) $user->ID)) {
            return;
        }

        $existing = self::get_user_totp_key((int) $user->ID);
        $enabled = !empty($existing);

        $setup_secret = '';
        $otpauth = '';

        if (!$enabled && $is_self) {
            try {
                $setup_secret = SucuriScanTOTP::generate_key();
            } catch (Exception $e) {
                $setup_secret = '';
            }
            if (!empty($setup_secret)) {
                $otpauth = SucuriScanTOTP::generate_qr_code_url($user, $setup_secret);
            }
        }

        $status_html = $enabled
            ? '<span class="dashicons dashicons-yes" style="color:#46b450"></span> ' . esc_html__('Enabled', 'sucuri-scanner')
            : '<span class="dashicons dashicons-dismiss" style="color:#dc3232"></span> ' . esc_html__('Disabled', 'sucuri-scanner');

        wp_nonce_field('sucuri_2fa_profile_action', 'sucuri_2fa_profile_nonce');
        $ajax_url = admin_url('admin-ajax.php');
        $ajax_nonce = wp_create_nonce('sucuri_profile_2fa');
        $uid = (int) $user->ID;

        $actions_html = '';

        if ($enabled) {
            $actions_html = SucuriScanTemplate::getSnippet('profile-2fa-status', array(
                'ajax_url' => $ajax_url,
                'ajax_nonce' => $ajax_nonce,
                'user_id' => $uid,
            ));
        } else {
            if ($is_self && !empty($setup_secret)) {
                $actions_html = SucuriScanTemplate::getSnippet('profile-2fa-setup', array(
                    'totp_key' => $setup_secret,
                    'topt_url' => $otpauth,
                    'ajax_url' => $ajax_url,
                    'ajax_nonce' => $ajax_nonce,
                    'user_id' => $uid,
                ));
            } elseif ($can_manage_users) {
                $actions_html = '<p class="description">' . esc_html__('Two-Factor is not enabled for this user. Ask the user to enable it from their own Profile page.', 'sucuri-scanner') . '</p>';
            }
        }

        echo SucuriScanTemplate::getSection('profile-2fa-section', array(
            'StatusHTML' => $status_html,
            'ActionsHTML' => $actions_html,
        ));
    }

    public static function ajax_profile_enable()
    {
        if (!is_user_logged_in()) {
            wp_send_json_error(array('message' => 'Forbidden'), 403);
        }

        check_ajax_referer('sucuri_profile_2fa', 'nonce');
        $current = get_current_user_id();
        $user_id = (int) SucuriScanRequest::post('user_id', '[0-9]+');
        $code = SucuriScanRequest::post('code', '[0-9 ]+');
        $secret = (string) SucuriScanRequest::post('secret', '[A-Za-z0-9=]+');

        if ($code !== false) {
            $code = preg_replace('/\D+/', '', $code);
        } else {
            $code = '';
        }

        if ($user_id <= 0) {
            $user_id = $current;
        }

        $is_self = ($current === $user_id);

        if (!$is_self && !current_user_can('edit_users')) {
            wp_send_json_error(array('message' => 'Not allowed'), 403);
        }

        if (!self::is_enforced_for_user($user_id)) {
            wp_send_json_error(array('message' => 'Two-Factor not enforced for this user'), 400);
        }

        if (strlen($code) !== SucuriScanTOTP::DEFAULT_DIGIT_COUNT) {
            wp_send_json_error(array('message' => __('Please enter the 6-digit verification code.', 'sucuri-scanner')));
        }

        if (empty($secret) || !SucuriScanTOTP::is_valid_key($secret)) {
            wp_send_json_error(array('message' => __('Invalid secret.', 'sucuri-scanner')));
        }

        $valid_ts = false;

        try {
            $valid_ts = SucuriScanTOTP::get_authcode_valid_ticktime($secret, $code);

            if ($valid_ts) {
                $last = (int) get_user_meta($user_id, self::LAST_SUCCESS_META_KEY, true);

                if ($last && $last >= $valid_ts) {
                    $valid_ts = false;
                }
            }

            if (!$valid_ts) {
                wp_send_json_error(array('message' => __('Incorrect code. Check your authenticator app and device time.', 'sucuri-scanner')));
            }
        } catch (Exception $e) {
            wp_send_json_error(array('message' => __('Verification failed.', 'sucuri-scanner')));
        }

        self::store_user_totp_key($user_id, $secret);

        if (!empty($valid_ts)) {
            update_user_meta($user_id, self::LAST_SUCCESS_META_KEY, $valid_ts);
        }

        if (class_exists('SucuriScanEvent')) {
            SucuriScanEvent::reportInfoEvent('Two-factor authentication enabled for user ID ' . (int) $user_id);
        }

        $html = SucuriScanTemplate::getSnippet('profile-2fa-status', array(
            'ajax_url' => admin_url('admin-ajax.php'),
            'ajax_nonce' => wp_create_nonce('sucuri_profile_2fa'),
            'user_id' => (int) $user_id,
        ));

        wp_send_json_success(array('html' => $html));
    }


    public static function ajax_profile_reset()
    {
        if (!is_user_logged_in()) {
            wp_send_json_error(array('message' => 'Forbidden'), 403);
        }

        check_ajax_referer('sucuri_profile_2fa', 'nonce');

        $current = get_current_user_id();
        $user_id = (int) SucuriScanRequest::post('user_id', '[0-9]+');

        if ($user_id <= 0) {
            $user_id = $current;
        }

        $is_self = ($current === $user_id);

        if (!$is_self && !current_user_can('edit_users')) {
            wp_send_json_error(array('message' => 'Not allowed'), 403);
        }

        if (!self::is_enforced_for_user($user_id)) {
            wp_send_json_error(array('message' => 'Two-Factor not enforced for this user'), 400);
        }

        delete_user_meta($user_id, self::SECRET_META_KEY);
        delete_user_meta($user_id, self::LAST_SUCCESS_META_KEY);

        if (class_exists('SucuriScanEvent')) {
            SucuriScanEvent::reportInfoEvent('Two-factor authentication reset for user ID ' . (int) $user_id);
        }

        $html = '';

        if ($is_self) {
            $key = '';

            try {
                $key = SucuriScanTOTP::generate_key();
            } catch (Exception $e) {
                $key = '';
            }

            if ($key !== '') {
                $user = get_user_by('id', $user_id);
                $otpauth = SucuriScanTOTP::generate_qr_code_url($user, $key);
                $html = SucuriScanTemplate::getSnippet('profile-2fa-setup', array(
                    'totp_key' => $key,
                    'topt_url' => $otpauth,
                    'ajax_url' => admin_url('admin-ajax.php'),
                    'ajax_nonce' => wp_create_nonce('sucuri_profile_2fa'),
                    'user_id' => (int) $user_id,
                ));
            }
        }

        if ($html === '') {
            $html = SucuriScanTemplate::getSnippet('profile-2fa-disabled', array());
        }

        wp_send_json_success(array('html' => $html));
    }


    public static function save_user_profile_section($user_id)
    {
        $user_id = (int) $user_id;

        if ($user_id <= 0) {
            return;
        }

        $profile_nonce = SucuriScanRequest::post('sucuri_2fa_profile_nonce', '_nonce');

        if (!$profile_nonce || !wp_verify_nonce($profile_nonce, 'sucuri_2fa_profile_action')) {
            return;
        }

        $action_raw = SucuriScanRequest::post('sucuri_2fa_action', '[a-z_]+');
        $action = $action_raw !== false ? sanitize_text_field((string) $action_raw) : '';

        if ($action !== 'enable' && $action !== 'reset') {
            return;
        }

        $current_id = get_current_user_id();
        $is_self = ($current_id && (int) $current_id === $user_id);

        if ($action === 'enable') {
            if (!$is_self) {
                return;
            }

            $code = SucuriScanRequest::post('sucuriscan_totp_code', '[0-9 ]+');
            $secret = SucuriScanRequest::post('sucuri_2fa_secret', '[A-Za-z0-9=]+');
            $code = $code ? preg_replace('/\D+/', '', $code) : '';
            $secret = $secret ? (string) $secret : '';

            if (strlen($code) !== SucuriScanTOTP::DEFAULT_DIGIT_COUNT) {
                self::add_profile_error('sucuri_2fa_code', esc_html__('Please enter the 6-digit verification code.', 'sucuri-scanner'));
                return;
            }

            if (empty($secret) || !SucuriScanTOTP::is_valid_key($secret)) {
                self::add_profile_error('sucuri_2fa_secret', esc_html__('Invalid secret. Reload the page and try again.', 'sucuri-scanner'));
                return;
            }

            $ok_ts = false;

            try {
                $ok_ts = SucuriScanTOTP::get_authcode_valid_ticktime($secret, $code);
            } catch (Exception $e) {
                $ok_ts = false;
            }

            if (!$ok_ts) {
                self::add_profile_error('sucuri_2fa_code', esc_html__('Incorrect code. Check your authenticator app and device time.', 'sucuri-scanner'));
                return;
            }

            self::store_user_totp_key($user_id, $secret);
            update_user_meta($user_id, self::LAST_SUCCESS_META_KEY, $ok_ts);

            if (class_exists('SucuriScanEvent')) {
                SucuriScanEvent::reportInfoEvent('Two-factor authentication enabled for user ID ' . (int) $user_id);
            }

            return;
        }

        if ($action === 'reset') {
            if (!$is_self && !current_user_can('edit_users')) {
                return;
            }

            delete_user_meta($user_id, self::SECRET_META_KEY);
            delete_user_meta($user_id, self::LAST_SUCCESS_META_KEY);

            if (class_exists('SucuriScanEvent')) {
                SucuriScanEvent::reportInfoEvent('Two-factor authentication reset for user ID ' . (int) $user_id);
            }

            return;
        }
    }

    public static function topt()
    {
        if (!SucuriScanInterface::checkNonce()) {
            return SucuriScanInterface::error(__('Incorrect nonce.', 'sucuri-scanner'));
        }

        $user = wp_get_current_user();

        if (!$user->ID) {
            return SucuriScanInterface::error(__('Incorrect user.', 'sucuri-scanner'));
        }

        $key = SucuriScanTOTP::generate_key();
        $topt_url = SucuriScanTOTP::generate_qr_code_url($user, $key);

        $params = array('totp_key' => $key, 'topt_url' => $topt_url, '2FA.Status' => empty($key), 'SecretManual' => $key);

        if (empty($key)) {
            return SucuriScanTemplate::getSnippet('2fa-setup', $params);
        }

        return SucuriScanTemplate::getSnippet('2fa-setup', $params);
    }


    public static function current_user_block()
    {
        $user = wp_get_current_user();

        if (!$user || !$user->ID) {
            return SucuriScanInterface::error(__('Incorrect user.', 'sucuri-scanner'));
        }

        $existing = self::get_user_totp_key((int) $user->ID);

        if (!empty($existing)) {
            return SucuriScanTemplate::getSnippet('2fa-current-user-status', array(
                'Message' => __('Two-Factor Authentication is enabled for your account.', 'sucuri-scanner'),
            ));
        }

        $key = SucuriScanTOTP::generate_key();
        $topt_url = SucuriScanTOTP::generate_qr_code_url($user, $key);

        return SucuriScanTemplate::getSnippet('2fa-setup', array(
            'totp_key' => $key,
            'topt_url' => $topt_url,
            'SecretManual' => $key
        ));
    }

    public static function users_admin_section()
    {
        $rows = '';
        $users = get_users(array('fields' => array('ID', 'user_login', 'user_email', 'roles')));
        $total_users = is_array($users) ? count($users) : 0;
        $activated_count = 0;

        foreach ($users as $user) {
            $uid = (int) $user->ID;
            $secret = self::get_user_totp_key($uid);
            $status = empty($secret) ? __('Deactivated', 'sucuri-scanner') : __('Activated', 'sucuri-scanner');

            if (!empty($secret)) {
                $activated_count++;
            }

            $rows .= SucuriScanTemplate::getSnippet('2fa-user-row', array(
                'ID' => $uid,
                'Login' => $user->user_login,
                'Email' => $user->user_email,
                'Status' => $status,
            ));
        }

        $bulkOptions = '';

        $bulkMap = array(
            'activate_all' => __('Enforce two factor for all users', 'sucuri-scanner'),
            'activate_selected' => __('Enforce two factor for selected users', 'sucuri-scanner'),
            'deactivate_all' => __('Deactivate two factor for all users', 'sucuri-scanner'),
            'deactivate_selected' => __('Deactivate two factor for selected users', 'sucuri-scanner'),
            'reset_selected' => __('Reset two factor for selected users', 'sucuri-scanner'),
            'reset_all' => __('Reset two factor for all users', 'sucuri-scanner'),
        );

        foreach ($bulkMap as $val => $label) {
            $bulkOptions .= sprintf('<option value="%s">%s</option>', esc_attr($val), esc_html($label));
        }

        $status_id = 0;
        $status_text = __('Deactivated', 'sucuri-scanner');

        if ($activated_count > 0) {
            if ($total_users > 0 && $activated_count >= $total_users) {
                $status_id = 1;
                $status_text = __('Activated for all users', 'sucuri-scanner');
            } else {
                $status_id = 2;
                $status_text = __('Activated for some users', 'sucuri-scanner');
            }
        }

        return SucuriScanTemplate::getSection('2fa-users', array(
            'Rows' => $rows,
            'BulkOptions' => $bulkOptions,
            'TwoFactor.Status' => (string) $status_id,
            'TwoFactor.StatusText' => $status_text,
        ));
    }

    public static function is_two_factor_active_for_any_user()
    {
        $users = get_users(array('fields' => array('ID')));

        foreach ($users as $user) {
            $uid = (int) $user->ID;
            $secret = self::get_user_totp_key($uid);

            if (!empty($secret)) {
                return true;
            }
        }

        return false;
    }


    public static function totp_verify()
    {
        if (!SucuriScanInterface::checkNonce()) {
            return SucuriScanInterface::error(__('Incorrect nonce.', 'sucuri-scanner'));
        }

        if (SucuriScanRequest::post('form_action') !== 'totp_verify') {
            return;
        }

        $user = wp_get_current_user();
        $user_id = $user->ID;

        if (!$user) {
            return SucuriScanInterface::error(__('Incorrect user.', 'sucuri-scanner'));
        }

        $existingKey = self::get_user_totp_key($user_id);

        $topt_code = SucuriScanRequest::post('topt_code', '[0-9 ]+');
        $topt_code = $topt_code ? preg_replace('/\D+/', '', $topt_code) : '';

        $key = SucuriScanRequest::post('topt_key', '[A-Za-z0-9=]+');

        if (!empty($existingKey)) {
            $key = $existingKey;
        }

        if (strlen($topt_code) !== SucuriScanTOTP::DEFAULT_DIGIT_COUNT) {
            wp_send_json(array('data' => '', 'error' => __('Code is not valid.', 'sucuri-scanner')), 200);
        }

        if (!SucuriScanTOTP::is_valid_key($key)) {
            wp_send_json(array('data' => '', 'error' => __('Code is not valid.', 'sucuri-scanner')), 200);
        }

        $valid_ts = SucuriScanTOTP::get_authcode_valid_ticktime($key, $topt_code);

        if ($valid_ts) {
            $last = (int) get_user_meta($user_id, self::LAST_SUCCESS_META_KEY, true);
            if ($last && $last >= $valid_ts) {
                $valid_ts = false;
            }
        }

        if (!$valid_ts) {
            wp_send_json(array('data' => '', 'error' => __('Code is not valid.', 'sucuri-scanner')), 200);
        }

        self::store_user_totp_key($user_id, $key);

        if ($valid_ts) {
            update_user_meta($user_id, self::LAST_SUCCESS_META_KEY, $valid_ts);
        }

        $current_mode = SucuriScanOption::getOption(':twofactor_mode');

        $enforce_all_raw = SucuriScanRequest::post('enforce_all', '[01]');
        $enforce_all = ($enforce_all_raw !== false) && ((string) $enforce_all_raw === '1');

        if ($enforce_all) {
            SucuriScanOption::updateOption(':twofactor_mode', 'all_users');
            SucuriScanOption::updateOption(':twofactor_user', 0);
        } else {
            if ($current_mode !== 'all_users') {
                SucuriScanOption::updateOption(':twofactor_mode', 'current_user');
                SucuriScanOption::updateOption(':twofactor_user', (int) $user_id);
            }
        }

        wp_send_json(array('data' => 'activated', 'error' => ''), 200);
    }
}
