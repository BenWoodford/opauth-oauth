<?php
/**
 * OAuth2 strategy for Opauth
 * 
 * More information on Opauth: http://opauth.org
 * 
 * @copyright    Copyright © 2012 U-Zyn Chua (http://uzyn.com)
 * @link         http://opauth.org
 * @package      Opauth.GitHubStrategy
 * @license      MIT License
 */

/**
 * GitHub strategy for Opauth
 * 
 * @package                        Opauth.GitHub
 */
class OAuthStrategy extends OpauthStrategy {
        
        /**
         * Compulsory config keys, listed as unassociative arrays
         */
        public $expects = array('client_id', 'client_secret');
        
        /**
         * Optional config keys, without predefining any default values.
         */
        public $optionals = array('redirect_uri', 'scope', 'state');
        
        /**
         * Optional config keys with respective default values, listed as associative arrays
         * eg. array('scope' => 'email');
         */
        public $defaults = array(
                'redirect_uri' => '{complete_url_to_strategy}oauth2callback'
        );
        
        /**
         * Auth request
         */
        public function request() {
                $url = $this->strategy['request_token_url'];
                $params = array(
                        'client_id' => $this->strategy['client_id'],
                        'redirect_uri' => $this->strategy['redirect_uri']
                );

                foreach ($this->optionals as $key) {
                        if (!empty($this->strategy[$key])) $params[$key] = $this->strategy[$key];
                }
                
                $this->clientGet($url, $params);
        }
        
        /**
         * Internal callback, after OAuth
         */
        public function oauth2callback() {
                if (array_key_exists('code', $_GET) && !empty($_GET['code'])) {
                        $code = $_GET['code'];
                        $url = $this->strategy['access_token_url'];
                        
                        $params = array(
                                'code' => $code,
                                'client_id' => $this->strategy['client_id'],
                                'client_secret' => $this->strategy['client_secret'],
                                'redirect_uri' => $this->strategy['redirect_uri'],
                                'grant_type' => 'authorization_code',
                        );
                        if (!empty($this->strategy['state'])) $params['state'] = $this->strategy['state'];
                        
                        $response = $this->serverPost($url, $params, null, $headers);
                        $results = json_decode($response,true);
                        
                        if (!empty($results) && !empty($results['access_token'])) {
                                $user = $this->user($results['access_token']);
                                
                                $this->auth = array(
                                        'uid' => $user['user']['user_id'],
                                        'info' => array(),
                                        'nickname' => $user['user']['username'],
                                        'email' => $user['user']['user_email'],
                                        'credentials' => array(
                                                'token' => $results['access_token']
                                        ),
                                        'raw' => $user
                                );
                                
                                $this->callback();
                        }
                        else {
                                $error = array(
                                        'code' => 'access_token_error',
                                        'message' => 'Failed when attempting to obtain access token',
                                        'raw' => array(
                                                'response' => $response,
                                                'headers' => $headers
                                        )
                                );

                                $this->errorCallback($error);
                        }
                }
                else {
                        $error = array(
                                'code' => 'oauth2callback_error',
                                'raw' => $_GET
                        );
                        
                        $this->errorCallback($error);
                }
        }
        
        private function user($access_token) {
                $user = $this->serverGet($this->strategy['api_user_endpoint'], array('oauth_token' => $access_token), null, $headers);

                if (!empty($user)) {
                        return $this->recursiveGetObjectVars(json_decode($user));
                }
                else {
                        $error = array(
                                'code' => 'userinfo_error',
                                'message' => 'Failed when attempting to query API for user information',
                                'raw' => array(
                                        'response' => $user,
                                        'headers' => $headers
                                )
                        );

                        $this->errorCallback($error);
                }
        }
}
