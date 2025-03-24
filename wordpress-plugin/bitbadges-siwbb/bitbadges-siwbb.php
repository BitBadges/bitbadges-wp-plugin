<?php
/**
 * Plugin Name: Sign In With BitBadges
 * Plugin URI: https://bitbadges.io
 * Description: Allows users to sign in to WordPress using their BitBadges account and gated claims
 * Version: 1.0.0
 * Author: BitBadges
 * Author URI: https://bitbadges.io
 * License: GPL v2 or later
 * License URI: https://www.gnu.org/licenses/gpl-2.0.html
 */

if (!defined('ABSPATH')) {
    exit;
}

class BitBadges_SIWBB {
    private $client_id;
    private $client_secret;
    private $api_key;
    private $redirect_uri;
    private $auth_url = 'https://bitbadges.io/siwbb/authorize';
    private $token_url = 'https://api.bitbadges.io/api/v0/siwbb/token';
    private $revoke_url = 'https://api.bitbadges.io/api/v0/siwbb/token/revoke';

    public function __construct() {
        // Add this line at the start of the constructor
        if (!headers_sent() && session_status() === PHP_SESSION_NONE) {
            session_start();
        }
        
        // Initialize plugin
        add_action('init', array($this, 'init'));
        add_action('admin_menu', array($this, 'add_admin_menu'));
        add_action('admin_init', array($this, 'register_settings'));
        
        // Handle OAuth callback
        add_action('init', array($this, 'handle_oauth_callback'));

        if (get_option('bitbadges_siwbb_exclusive_auth') === 'yes') {
            // Replace the entire login page
            add_action('login_init', array($this, 'custom_login_page'), 1);
            add_filter('authenticate', array($this, 'disable_default_auth'), 30, 3);
        } else {
            // Add login button to normal WordPress login form
            add_action('login_footer', array($this, 'add_login_button'));
            add_action('login_enqueue_scripts', array($this, 'add_login_styles'));
        }

        // Set up custom error logging
        if (!defined('BITBADGES_LOG')) {
            define('BITBADGES_LOG', WP_CONTENT_DIR . '/bitbadges-debug.log');
        }

        // Handle admin address update
        add_action('admin_init', array($this, 'handle_admin_address_update'));

        // Add action to register plugin assets
        add_action('init', array($this, 'register_plugin_assets'));
    }

    public function init() {
        $this->client_id = get_option('bitbadges_siwbb_client_id');
        $this->client_secret = get_option('bitbadges_siwbb_client_secret');
        $this->api_key = get_option('bitbadges_siwbb_api_key');
        $this->redirect_uri = site_url('/wp-login.php?action=bitbadges-callback');
    }

    public function add_admin_menu() {
        add_options_page(
            'BitBadges SIWBB Settings',
            'BitBadges SIWBB',
            'manage_options',
            'bitbadges-siwbb',
            array($this, 'settings_page')
        );
    }

    public function register_settings() {
        // Text field settings
        $text_field_args = array(
            'type' => 'string',
            'sanitize_callback' => 'sanitize_text_field',
            'default' => ''
        );

        // Checkbox field settings
        $checkbox_field_args = array(
            'type' => 'string',
            'sanitize_callback' => 'sanitize_text_field',
            'default' => 'no'
        );

        register_setting(
            'bitbadges_siwbb_settings',
            'bitbadges_siwbb_client_id',
            $text_field_args
        );
        
        register_setting(
            'bitbadges_siwbb_settings',
            'bitbadges_siwbb_client_secret',
            $text_field_args
        );
        
        register_setting(
            'bitbadges_siwbb_settings',
            'bitbadges_siwbb_api_key',
            $text_field_args
        );
        
        register_setting(
            'bitbadges_siwbb_settings',
            'bitbadges_siwbb_claim_id',
            $text_field_args
        );
        
        register_setting(
            'bitbadges_siwbb_settings',
            'bitbadges_siwbb_exclusive_auth',
            $checkbox_field_args
        );
        
        register_setting(
            'bitbadges_siwbb_settings',
            'bitbadges_siwbb_show_claim_on_auth',
            $checkbox_field_args
        );
    }

    // Add this helper method for checkbox sanitization
    public function sanitize_checkbox($input) {
        return ($input === 'yes') ? 'yes' : 'no';
    }

    public function settings_page() {
        // Verify user has proper permissions
        if (!current_user_can('manage_options')) {
            wp_die(esc_html__('You do not have sufficient permissions to access this page.', 'bitbadges-siwbb'));
        }

        // Add nonce field for the entire settings form
        if (isset($_GET['first_login'])) {
            check_admin_referer('bitbadges_first_login');
            $is_first_login = sanitize_text_field(wp_unslash($_GET['first_login'])) === '1';
        } else {
            $is_first_login = false;
        }


        ?>
        <div class="wrap">
            <h2>BitBadges Sign In Settings</h2>

            <?php 
            // Add nonce field for the entire settings form
            wp_nonce_field('bitbadges_settings_action', 'bitbadges_settings_nonce'); 
            ?>

            <?php if ($is_first_login): ?>
                <div class="notice notice-success">
                    <p><strong>Welcome!</strong> You've been automatically set as the administrator because you're the first user to sign in.</p>
                    <p>Your BitBadges address (<code><?php echo esc_html($admin_address); ?></code>) has been recorded as the admin address.</p>
                    <p>Please configure your BitBadges Sign In settings below:</p>
                </div>
            <?php endif; ?>
            
            <form method="post" action="options.php">
                <?php settings_fields('bitbadges_siwbb_settings'); ?>
                <table class="form-table">
                    <tr>
                        <th scope="row">Client ID</th>
                        <td>
                            <input type="text" name="bitbadges_siwbb_client_id" 
                                value="<?php echo esc_attr(get_option('bitbadges_siwbb_client_id')); ?>" class="regular-text">
                            <p class="description">Follow the setup instructions to set up your OAuth App in the <a href="https://bitbadges.io/developer" target="_blank">BitBadges Developer Portal</a>.</p>
                          </td>
                    </tr>
                    <tr>
                        <th scope="row">Client Secret</th>
                        <td>
                            <input type="password" name="bitbadges_siwbb_client_secret" 
                                value="<?php echo esc_attr(get_option('bitbadges_siwbb_client_secret')); ?>" class="regular-text">
                            <p class="description">Follow the setup instructions to set up your OAuth App in the <a href="https://bitbadges.io/developer" target="_blank">BitBadges Developer Portal</a>.</p>
                        </td>
                    </tr>
                    <tr>
                        <th scope="row">API Key</th>
                        <td>
                            <input type="password" name="bitbadges_siwbb_api_key" 
                                value="<?php echo esc_attr(get_option('bitbadges_siwbb_api_key')); ?>" class="regular-text">
                            <p class="description">Get your API key from the <a href="https://bitbadges.io/developer" target="_blank">BitBadges Developer Portal</a></p>
                        </td>
                    </tr>
                    <tr>
                        <th scope="row">Claim ID (Optional)</th>
                        <td>
                            <input type="text" name="bitbadges_siwbb_claim_id" 
                                value="<?php echo esc_attr(get_option('bitbadges_siwbb_claim_id')); ?>" class="regular-text">
                            <p class="description">Optional: Require users to successfully meet this claim criteria. The claim ID can be found in the URL of the claim page (/claims/claimId).
                              Claims can be created for anything like checking badge ownership, Discord membership, anything! On-demand claims are checked
                              automatically with no user action required. Standard claims require users to manually complete the claim (min 1 time). Both are supported.
                            </p>
                        </td>
                    </tr>
                    <tr>
                        <th scope="row">Show Claim on Authorization</th>
                        <td>
                            <label>
                                <input type="checkbox" name="bitbadges_siwbb_show_claim_on_auth" 
                                    value="yes" <?php checked(get_option('bitbadges_siwbb_show_claim_on_auth'), 'yes'); ?>>
                                Show claim requirements on BitBadges authorization page
                            </label>
                            <p class="description">
                            If checked, BitBadges will display the entire claim criteria directly on the authorization page. 
                            If unchecked, users will only see a link to the claim page on the WordPress login page.
                          </p>
                        </td>
                    </tr>
                    <tr>
                        <th scope="row">Exclusive Authentication</th>
                        <td>
                            <label>
                                <input type="checkbox" name="bitbadges_siwbb_exclusive_auth" 
                                    value="yes" <?php checked(get_option('bitbadges_siwbb_exclusive_auth'), 'yes'); ?>>
                                Disable Normal WordPress Login (Only Allow Sign In with BitBadges)
                            </label>
                            <?php if (!get_option('bitbadges_siwbb_exclusive_auth')): ?>
                                <p class="description" style="color: #d63638;">
                                    <strong>Warning:</strong> Make sure you have approved a BitBadges account as administrator before proceeding! 
                                    See instructions.
                                    If you do not, you will permanently lock yourself out of the WordPress admin console.
                                    This option will disable the normal authorization flow (causing the default admin login to fail).
                                </p>
                            <?php endif; ?>
                            <?php if (!get_option('bitbadges_siwbb_exclusive_auth')): ?>
                <div class="">
                    <p><strong>Important:</strong> Before enabling exclusive authentication, please do the following to avoid permanent lockout:</p>
                    <p>
                      1) Set up Sign In with BitBadges without exclusive authentication and save the settings.
                      <br>
                      2) Sign in with a BitBadges address that you want to use as an admin account.
                      <br>
                      3) Sign back in with your admin account.
                      <br>
                      4) Set your BitBadges address as the administrator in the <a href="<?php echo esc_url(admin_url('users.php')); ?>">Users</a> section of WordPress. You may need to assign it an email.
                      <br>
                      5) Now, you are safe to enable exclusive authentication.
                      <br>
                      You will then be able to access the WordPress admin console using your BitBadges account. The previous admin account will no longer work since we exclusively authenticate with BitBadges.
                    </p>
                </div>
            <?php endif; ?>
                            
                        </td>
                    </tr>
                </table>
              
                <?php submit_button(); ?>
            </form>
        </div>
        <?php
    }

    public function add_login_styles() {
        ?>
        <style type="text/css">
            body.login #bitbadges-login-container {
                width: 320px;
                margin: 20px auto;
                padding: 0;
            }
            
            body.login .bitbadges-login-wrapper {
                width: 100%;
                margin: 0 auto;
            }
            
            body.login .bitbadges-button {
                display: flex !important;
                align-items: center;
                justify-content: center;
                gap: 10px;
                width: 100%;
                background-color: #000000;
                border: 1px solid #000000;
                border-radius: 8px;
                color: white !important;
                padding: 12px 20px;
                text-decoration: none;
                font-size: 14px;
                line-height: 1.5;
                cursor: pointer;
                text-align: center;
                box-sizing: border-box;
                transition: all 0.3s ease;
            }
            
            body.login .bitbadges-button:hover {
                background-color: #333333;
                border-color: #333333;
            }
            
            body.login .bitbadges-button:focus {
                box-shadow: 0 0 0 1px #fff, 0 0 0 3px #000000;
                outline: none;
            }
            
            body.login .bitbadges-button img {
                width: 24px;
                height: 24px;
                vertical-align: middle;
                border-radius: 4px;
            }
            
            body.login .bitbadges-button span {
                vertical-align: middle;
                font-weight: 500;
            }
            
            body.login .bitbadges-divider {
                margin: 32px 0;
                text-align: center;
                position: relative;
            }
            
            body.login .bitbadges-divider:before {
                content: "";
                position: absolute;
                top: 50%;
                left: 0;
                right: 0;
                height: 1px;
                background: #dcdcde;
            }
            
            body.login .bitbadges-divider span {
                background: #f0f0f1;
                padding: 0 16px;
                color: #50575e;
                font-size: 13px;
                position: relative;
                z-index: 1;
            }

            body.login #loginform {
                margin-bottom: 24px !important;
            }

            body.login .bitbadges-login-wrapper {
                margin-top: 24px !important;
            }

            /* Match WordPress login form width */
            @media screen and (max-width: 782px) {
                body.login #bitbadges-login-container {
                    width: 100%;
                    padding: 0 20px;
                    box-sizing: border-box;
                }
            }
        </style>
        <?php
    }

    public function add_login_button() {
        // Enqueue the images style
        wp_enqueue_style('bitbadges-siwbb-images');
        ?>
        <div id="bitbadges-login-container">
            <?php if (!get_option('bitbadges_siwbb_exclusive_auth')): ?>
                <div class="bitbadges-divider">
                    <span>Or</span>
                </div>
            <?php endif; ?>
            <div class="bitbadges-login-wrapper">
                <a href="<?php echo esc_url($this->get_authorization_url()); ?>" class="bitbadges-button">
                    <span class="bitbadges-logo" aria-label="<?php esc_attr_e('BitBadges Logo', 'bitbadges-siwbb'); ?>"></span>
                    <span><?php esc_html_e('Sign in with BitBadges', 'bitbadges-siwbb'); ?></span>
                </a>
            </div>
        </div>
        <?php
    }

    private function get_authorization_url() {
        // Start session if not already started
        if (session_status() === PHP_SESSION_NONE) {
            session_start();
        }

        $state = wp_create_nonce('bitbadges_auth');
        $_SESSION['bitbadges_auth_state'] = $state;

        $params = array(
            'client_id' => $this->client_id,
            'redirect_uri' => $this->redirect_uri,
            'response_type' => 'code',
            'state' => $state,
            'scope' => '',
            '_wpnonce' => wp_create_nonce('bitbadges_callback')
        );

        // Add claim ID if configured
        $claim_id = get_option('bitbadges_siwbb_claim_id');
        if (!empty($claim_id)) {
            // Only add showClaim parameter if admin has chosen to show it
            if (get_option('bitbadges_siwbb_show_claim_on_auth') === 'yes') {
                $params['claimId'] = $claim_id;
                $params['showClaim'] = 'true';
            }
        }

        return add_query_arg($params, $this->auth_url);
    }

    public function handle_oauth_callback() {
        if (!isset($_GET['action']) || sanitize_text_field(wp_unslash($_GET['action'])) !== 'bitbadges-callback') {
            return;
        }

        // Start session if not already started
        if (session_status() === PHP_SESSION_NONE) {
            session_start();
        }

        // Verify state to prevent CSRF
        if (!isset($_GET['state']) || !isset($_SESSION['bitbadges_auth_state'])) {
            wp_die(esc_html__('Invalid authentication request - state parameter missing', 'bitbadges-siwbb'));
        }

        $state = sanitize_text_field(wp_unslash($_GET['state']));
        if (!wp_verify_nonce($state, 'bitbadges_auth') || $state !== $_SESSION['bitbadges_auth_state']) {
            wp_die(esc_html__('Invalid authentication request - state verification failed', 'bitbadges-siwbb'));
        }

        if (isset($_GET['error'])) {
            wp_die(esc_html(sprintf(
                /* translators: %s: error message */
                __('Authentication error: %s', 'bitbadges-siwbb'),
                sanitize_text_field(wp_unslash($_GET['error']))
            )));
        }

        if (!isset($_GET['code'])) {
            wp_die(esc_html__('No authorization code received', 'bitbadges-siwbb'));
        }

        // Exchange code for token and get user info
        $code = sanitize_text_field(wp_unslash($_GET['code']));
        $token_response = $this->get_access_token($code);
        if (!$token_response) {
            wp_die(esc_html__('Failed to get access token', 'bitbadges-siwbb'));
        }

        $this->login_or_create_user($token_response);
    }

    private function get_access_token($code) {
        $request_body = array(
            'grant_type' => 'authorization_code',
            'client_id' => $this->client_id,
            'client_secret' => $this->client_secret,
            'redirect_uri' => $this->redirect_uri,
            'code' => $code
        );

        $response = wp_remote_post($this->token_url, array(
            'headers' => array(
                'Content-Type' => 'application/json',
                'x-api-key' => $this->api_key
            ),
            'body' => json_encode($request_body)
        ));

        if (is_wp_error($response)) {
            return false;
        }

        $body = wp_remote_retrieve_body($response);
        $body_array = json_decode($body, true);
        
        if (!isset($body_array['access_token']) || !isset($body_array['address'])) {
            return false;
        }

        return $body_array;
    }

    private function verify_claim_success($address) {
        $claim_id = get_option('bitbadges_siwbb_claim_id');
        if (empty($claim_id)) {
            return true; // No claim verification needed
        }

        $verify_url = 'https://api.bitbadges.io/api/v0/claims/success/' . $claim_id . '/' . $address;
        
        $response = wp_remote_get($verify_url, array(
            'headers' => array(
                'x-api-key' => $this->api_key
            )
        ));

        if (is_wp_error($response)) {
            return false;
        }

        $status_code = wp_remote_retrieve_response_code($response);
        $body = wp_remote_retrieve_body($response);
        $body_array = json_decode($body, true);

        if ($status_code !== 200 || !isset($body_array['successCount'])) {
            return false;
        }

        return $body_array['successCount'] >= 1;
    }

    public function login_or_create_user($token_response) {
        // Extract BitBadges address as username
        $username = sanitize_user($token_response['address']);
        
        // Create display variations of the address
        $display_name = substr($username, 0, 6) . '...' . substr($username, -4);
        $nickname = $username;
        
        // Verify claim success if claim ID is configured
        if (!$this->verify_claim_success($username)) {
            wp_die(esc_html__('Authentication failed: You must successfully meet the claim criteria.', 'bitbadges-siwbb'));
        }
        
        // Check if user exists
        $user = get_user_by('login', $username);
        
        if (!$user) {
            // Create new user
            $userdata = array(
                'user_login' => $username,
                'user_pass' => wp_generate_password(),
                'display_name' => $display_name,
                'nickname' => $nickname,
                'user_nicename' => $username,
                'role' => 'subscriber',
                'show_admin_bar_front' => false
            );
            
            $user_id = wp_insert_user($userdata);
            if (is_wp_error($user_id)) {
                wp_die(esc_html__('Failed to create user', 'bitbadges-siwbb'));
            }
            
            $user = get_user_by('id', $user_id);
        } else {
            // Update existing user's display information
            wp_update_user(array(
                'ID' => $user->ID,
                'display_name' => $display_name,
                'nickname' => $nickname
            ));
        }
        
        // Store the access token in user meta for future use if needed
        update_user_meta($user->ID, 'bitbadges_access_token', $token_response['access_token']);
        
        // Log the user in
        wp_set_current_user($user->ID);
        wp_set_auth_cookie($user->ID);
        
        wp_redirect(home_url());
        exit;
    }

    public function disable_default_auth($user, $username, $password) {
        // Allow WordPress CLI authentication
        if (defined('WP_CLI') && WP_CLI) {
            return $user;
        }

        // Allow authentication if accessing wp-admin/admin-ajax.php
        if (defined('DOING_AJAX') && DOING_AJAX) {
            return $user;
        }

        // Only allow access through BitBadges
        if (isset($_GET['action'])) {
            $action = sanitize_text_field(wp_unslash($_GET['action']));
            if ($action === 'bitbadges-callback') {
                // Verify nonce for callback action
                if (!isset($_GET['_wpnonce']) || !wp_verify_nonce(sanitize_text_field(wp_unslash($_GET['_wpnonce'])), 'bitbadges_callback')) {
                    return new WP_Error('invalid_nonce', 'Invalid security token.');
                }
                return $user;
            }
        }
        
        // Block all other authentication attempts
        return new WP_Error('bitbadges_only', 'Only Sign in with BitBadges is allowed.');
    }

    public function custom_login_page() {
        // Don't override the callback handling
        if (isset($_GET['action'])) {
            $action = sanitize_text_field(wp_unslash($_GET['action']));
            
            if ($action === 'bitbadges-callback') {
                if (!isset($_GET['_wpnonce']) || !wp_verify_nonce(sanitize_text_field(wp_unslash($_GET['_wpnonce'])), 'bitbadges_callback')) {
                    wp_die(esc_html__('Invalid callback attempt', 'bitbadges-siwbb'));
                }
                return;
            }

            // Don't override logout
            if ($action === 'logout') {
                if (!isset($_GET['_wpnonce']) || !wp_verify_nonce(sanitize_text_field(wp_unslash($_GET['_wpnonce'])), 'log-out')) {
                    wp_die(esc_html__('Invalid logout attempt', 'bitbadges-siwbb'));
                }
                return;
            }
        }

        // Get claim ID for requirements link
        $claim_id = get_option('bitbadges_siwbb_claim_id');

        // Clear any existing output
        if (ob_get_level()) {
            ob_end_clean();
        }

        // Enqueue the images style
        wp_enqueue_style('bitbadges-siwbb-images');

        ?>
        <!DOCTYPE html>
        <html <?php language_attributes(); ?>>
        <head>
            <meta charset="<?php bloginfo('charset'); ?>">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title><?php esc_html_e('Login - ', 'bitbadges-siwbb'); bloginfo('name'); ?></title>
            <?php do_action('login_head'); ?>
            <style type="text/css">
                body {
                    background: #f0f0f1;
                    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Oxygen-Sans, Ubuntu, Cantarell, "Helvetica Neue", sans-serif;
                }
                .login-container {
                    max-width: 320px;
                    margin: 100px auto;
                    padding: 40px;
                    background: white;
                    border-radius: 4px;
                    box-shadow: 0 1px 3px rgba(0, 0, 0, 0.13);
                }
                .login-header {
                    text-align: center;
                    margin-bottom: 30px;
                }
                .site-title {
                    font-size: 20px;
                    margin: 0 0 10px;
                }
                .login-message {
                    color: #50575e;
                    margin-bottom: 20px;
                    text-align: center;
                }
                .bitbadges-button {
                    display: flex !important;
                    align-items: center;
                    justify-content: center;
                    gap: 10px;
                    width: 100%;
                    padding: 12px 20px;
                    background-color: #000000;
                    border: 1px solid #000000;
                    border-radius: 8px;
                    color: white;
                    text-decoration: none;
                    text-align: center;
                    font-size: 14px;
                    line-height: 1.5;
                    cursor: pointer;
                    transition: all 0.3s ease;
                    box-sizing: border-box;
                }
                .bitbadges-button:hover {
                    background-color: #333333;
                    border-color: #333333;
                }
                .bitbadges-button:focus {
                    box-shadow: 0 0 0 1px #fff, 0 0 0 3px #000000;
                    outline: none;
                }
                .bitbadges-button img {
                    width: 32px;
                    height: 32px;
                    vertical-align: middle;
                }
                .bitbadges-logo {
                    width: 32px;
                    height: 32px;
                    vertical-align: middle;
                    border-radius: 4px;
                }
                .bitbadges-button span {
                    vertical-align: middle;
                }
                .login-footer {
                    text-align: center;
                    margin-top: 20px;
                }
                .login-footer a {
                    color: #50575e;
                    text-decoration: none;
                }
                .login-footer a:hover {
                    color: #135e96;
                }
                .claim-requirements {
                    margin: 15px 0;
                    text-align: center;
                    font-size: 13px;
                }
                
                .claim-requirements a {
                    color: #2271b1;
                    text-decoration: none;
                }
                
                .claim-requirements a:hover {
                    color: #135e96;
                    text-decoration: underline;
                }
            </style>
        </head>
        <body class="login">
            <div class="login-container">
                <div class="login-header">
                    <?php
                    $site_icon_url = get_site_icon_url(150);
                    if ($site_icon_url) {
                        $site_icon_id = get_option('site_icon');
                        if ($site_icon_id) {
                            echo wp_get_attachment_image($site_icon_id, array(150, 150), false, array(
                                'style' => 'max-width: 150px; height: auto;',
                                'alt' => esc_attr(get_bloginfo('name'))
                            ));
                        }
                    }
                    ?>
                    <h1 class="site-title"><?php bloginfo('name'); ?></h1>
                </div>
                
                <div class="login-message">
                    <?php esc_html_e('Sign in to your account using BitBadges', 'bitbadges-siwbb'); ?>
                </div>

                <?php if (!empty($claim_id)): ?>
                <div class="claim-requirements">
                    <a href="https://bitbadges.io/claims/<?php echo esc_attr($claim_id); ?>" target="_blank">
                        View Required Claim Criteria →
                    </a>
                </div>
                <?php endif; ?>

                <a href="<?php echo esc_url($this->get_authorization_url()); ?>" class="bitbadges-button">
                    <span class="bitbadges-logo" aria-label="<?php esc_attr_e('BitBadges Logo', 'bitbadges-siwbb'); ?>"></span>
                    <span><?php esc_html_e('Sign in with BitBadges', 'bitbadges-siwbb'); ?></span>
                </a>

                <div class="login-footer">
                    <a href="<?php echo esc_url(home_url('/')); ?>">
                        <?php esc_html_e('← Back to', 'bitbadges-siwbb'); ?> <?php bloginfo('name'); ?>
                    </a>
                </div>
            </div>
            <?php do_action('login_footer'); ?>
        </body>
        </html>
        <?php
        exit;
    }

    public function handle_admin_address_update() {
        if (
            isset($_POST['update_admin_address']) && 
            check_admin_referer('update_admin_address', 'admin_address_nonce') &&
            current_user_can('manage_options')
        ) {
            $current_user = wp_get_current_user();
            update_option('bitbadges_siwbb_admin_address', $current_user->user_login);
            add_settings_error(
                'bitbadges_messages',
                'admin_address_updated',
                'Administrator address has been updated.',
                'updated'
            );
        }
    }

    public function register_plugin_assets() {
        // Register the BitBadges logo
        wp_register_style(
            'bitbadges-siwbb-images',
            plugin_dir_url(__FILE__) . 'assets/css/images.css',
            array(),
            '1.0.0'
        );
    }
}

// Initialize the plugin
new BitBadges_SIWBB(); 