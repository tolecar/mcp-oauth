<?php
/**
 * Plugin Name: MCP OAuth2 Server
 * Description: Provides a lightweight OAuth2 server optimized for Model Context Protocol (MCP) integrations.
 * Version: 0.1.0
 * Author: Example Author
 */

if (!defined('ABSPATH')) {
    exit; // Exit if accessed directly
}

class MCPOAuth2Server {
    private static $instance = null;

    public static function instance() {
        if (self::$instance === null) {
            self::$instance = new self();
        }
        return self::$instance;
    }

    private function __construct() {
        add_action('rest_api_init', array($this, 'register_routes'));
        add_action('init', array($this, 'register_post_types'));
        register_activation_hook(__FILE__, array($this, 'activate'));
    }

    public function activate() {
        $this->register_post_types();
        flush_rewrite_rules();
    }

    public function register_post_types() {
        register_post_type('mcp_oauth_client', array(
            'labels' => array('name' => 'OAuth Clients'),
            'public' => false,
            'show_ui' => false,
            'capability_type' => 'post',
        ));

        register_post_type('mcp_oauth_token', array(
            'labels' => array('name' => 'OAuth Tokens'),
            'public' => false,
            'show_ui' => false,
            'capability_type' => 'post',
        ));
    }

    public function register_routes() {
        register_rest_route('mcp/v1', '/authorize', array(
            'methods'  => 'GET',
            'callback' => array($this, 'handle_authorize'),
            'permission_callback' => '__return_true',
        ));

        register_rest_route('mcp/v1', '/token', array(
            'methods'  => 'POST',
            'callback' => array($this, 'handle_token'),
            'permission_callback' => '__return_true',
        ));
    }

    public function handle_authorize(WP_REST_Request $request) {
        $response_type = $request->get_param('response_type');
        $client_id     = $request->get_param('client_id');
        $redirect_uri  = $request->get_param('redirect_uri');
        $state         = $request->get_param('state');

        if ($response_type !== 'code') {
            return new WP_REST_Response(array('error' => 'unsupported_response_type'), 400);
        }

        if (!is_user_logged_in()) {
            return new WP_REST_Response(array('error' => 'login_required'), 401);
        }

        $code = wp_generate_password(32, false);
        set_transient('mcp_auth_code_' . $code, array(
            'client_id'    => $client_id,
            'user_id'      => get_current_user_id(),
            'redirect_uri' => $redirect_uri,
            'created'      => time(),
        ), MINUTE_IN_SECONDS * 10);

        $redirect = add_query_arg(array(
            'code'  => $code,
            'state' => $state,
        ), $redirect_uri);

        return new WP_REST_Response(array('redirect' => $redirect));
    }

    public function handle_token(WP_REST_Request $request) {
        $grant_type = $request->get_param('grant_type');
        $client_id  = $request->get_param('client_id');
        $client_secret = $request->get_param('client_secret');
        $code       = $request->get_param('code');
        $refresh_token = $request->get_param('refresh_token');

        $client_query = get_posts(array(
            'post_type'  => 'mcp_oauth_client',
            'post_status'=> 'publish',
            'numberposts'=> 1,
            'meta_query' => array(
                array('key' => '_client_id', 'value' => $client_id),
                array('key' => '_client_secret', 'value' => $client_secret),
            )
        ));
        $client = $client_query ? $client_query[0] : null;

        if (!$client) {
            return new WP_REST_Response(array('error' => 'invalid_client'), 401);
        }

        if ($grant_type === 'authorization_code') {
            $code_data = get_transient('mcp_auth_code_' . $code);
            if (!$code_data || $code_data['client_id'] !== $client_id) {
                return new WP_REST_Response(array('error' => 'invalid_grant'), 400);
            }

            delete_transient('mcp_auth_code_' . $code);

            $access_token  = wp_generate_password(40, false);
            $refresh_token = wp_generate_password(40, false);
            $expires       = current_time('mysql', true);
            $expires       = date('Y-m-d H:i:s', strtotime('+1 hour', strtotime($expires)));

            $post_id = wp_insert_post(array(
                'post_type'   => 'mcp_oauth_token',
                'post_status' => 'publish',
                'post_title'  => 'Token ' . time(),
                'post_author' => $code_data['user_id'],
            ));

            if ($post_id) {
                update_post_meta($post_id, '_client_id', $client_id);
                update_post_meta($post_id, '_user_id', $code_data['user_id']);
                update_post_meta($post_id, '_access_token', $access_token);
                update_post_meta($post_id, '_refresh_token', $refresh_token);
                update_post_meta($post_id, '_expires', $expires);
                update_post_meta($post_id, '_scope', '');
            }

            return new WP_REST_Response(array(
                'access_token'  => $access_token,
                'token_type'    => 'Bearer',
                'expires_in'    => HOUR_IN_SECONDS,
                'refresh_token' => $refresh_token,
            ));
        }

        if ($grant_type === 'refresh_token') {
            $token_query = get_posts(array(
                'post_type'   => 'mcp_oauth_token',
                'post_status' => 'publish',
                'numberposts' => 1,
                'meta_query'  => array(
                    array('key' => '_refresh_token', 'value' => $refresh_token),
                )
            ));

            $token_post = $token_query ? $token_query[0] : null;

            if (!$token_post || get_post_meta($token_post->ID, '_client_id', true) !== $client_id) {
                return new WP_REST_Response(array('error' => 'invalid_grant'), 400);
            }

            $access_token_new  = wp_generate_password(40, false);
            $refresh_token_new = wp_generate_password(40, false);
            $expires           = current_time('mysql', true);
            $expires           = date('Y-m-d H:i:s', strtotime('+1 hour', strtotime($expires)));

            update_post_meta($token_post->ID, '_access_token', $access_token_new);
            update_post_meta($token_post->ID, '_refresh_token', $refresh_token_new);
            update_post_meta($token_post->ID, '_expires', $expires);

            return new WP_REST_Response(array(
                'access_token'  => $access_token_new,
                'token_type'    => 'Bearer',
                'expires_in'    => HOUR_IN_SECONDS,
                'refresh_token' => $refresh_token_new,
            ));
        }

        return new WP_REST_Response(array('error' => 'unsupported_grant_type'), 400);
    }
}

MCPOAuth2Server::instance();
