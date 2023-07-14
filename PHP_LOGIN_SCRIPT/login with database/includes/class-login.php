<?php
class Login {
    public $user;
    
    public function __construct() {
        global $db;

        session_start();
        
        $this->db = $db;
    }
    
    public function verify_session() {
        $username = $_SESSION['username'];
        
        if ( empty( $username ) && ! empty( $_COOKIE['rememberme'] ) ) {
            list($selector, $authenticator) = explode(':', $_COOKIE['rememberme']);
            
            $results = $this->db->get_results("SELECT * FROM auth_tokens WHERE selector = :selector", ['selector'=>$selector]);
            $auth_token = $results[0];
            
            if ( hash_equals( $auth_token->token, hash( 'sha256', base64_decode( $authenticator ) ) ) ) {
                $username = $auth_token->username;
                $_SESSION['username'] = $username;
            }
        }
        
        $user =  $this->user_exists( $username );
        
        if ( false !== $user ) {
            $this->user = $user;
            
            return true;
        }
        
        return false;
    }
    
    public function verify_login($post) {
        if ( ! isset( $post['username'] ) || ! isset( $post['password'] ) ) {
            return false;
        }
        
        // Check if user exists
        $user = $this->user_exists( $post['username'] );
        
        if ( false !== $user ) {
            if ( password_verify( $post['password'], $user->password ) ) {
                $_SESSION['username'] = $user->username;
                
                if ( $post['rememberme'] ) {
                    $this->rememberme($user);
                }

                return true;
            }
        }
        
        return false;
    }
    
    public function register($post) {
        // Required fields
        $required = array( 'username', 'password', 'email' );
        
        foreach ( $required as $key ) {
            if ( empty( $post[$key] ) ) {
                return array('status'=>0,'message'=>sprintf('Please enter your %s', $key));
            }
        }
        
        // Check if username exists already
        if ( false !== $this->user_exists( $post['username'] ) ) {
            return array('status'=>0,'message'=>'Username already exists');
        }
        
        // Create if doesn't exist
        $insert = $this->db->insert('users', 
            array(
                'username'  =>  $post['username'], 
                'password'  =>  password_hash($post['password'], PASSWORD_DEFAULT),
                'name'      =>  $post['name'],
                'email'     =>  $post['email'],
            )
        );
        
        if ( $insert == true ) {
            return array('status'=>1,'message'=>'Account created successfully');
        }
        
        return array('status'=>0,'message'=>'An unknown error occurred.');
    }
    
    public function lost_password($post) {
        // Verify email submitted
        if ( empty( $post['email'] ) ) {
            return array('status'=>0,'message'=>'Please enter your email address');
        }
        
        // Verify email exists
        if ( ! $user = $this->user_exists( $post['email'], 'email' ) ) {
            return array('status'=>0,'message'=>'That email address does not exist in our records');
        }
        
        // Create tokens
        $selector = bin2hex(random_bytes(8));
        $token = random_bytes(32);

        $url = sprintf('%sreset.php?%s', ABS_URL, http_build_query([
            'selector' => $selector,
            'validator' => bin2hex($token)
        ]));

        // Token expiration
        $expires = new DateTime('NOW');
        $expires->add(new DateInterval('PT01H')); // 1 hour
        
        // Delete any existing tokens for this user
        $this->db->delete('password_reset', 'email', $user->email);
        
        // Insert reset token into database
        $insert = $this->db->insert('password_reset', 
            array(
                'email'     =>  $user->email,
                'selector'  =>  $selector, 
                'token'     =>  hash('sha256', $token),
                'expires'   =>  $expires->format('U'),
            )
        );
        
        // Send the email
        if ( false !== $insert ) {
            // Recipient
            $to = $user->email;
            
            // Subject
            $subject = 'Your password reset link';
            
            // Message
            $message = '<p>We recieved a password reset request. The link to reset your password is below. ';
            $message .= 'If you did not make this request, you can ignore this email</p>';
            $message .= '<p>Here is your password reset link:</br>';
            $message .= sprintf('<a href="%s">%s</a></p>', $url, $url);
            $message .= '<p>Thanks!</p>';
            
            // Headers
            $headers = "From: " . ADMIN_NAME . " <" . ADMIN_EMAIL . ">\r\n";
            $headers .= "Reply-To: " . ADMIN_EMAIL . "\r\n";
            $headers .= "Content-type: text/html\r\n";
            
            // Send email
            $sent = mail($to, $subject, $message, $headers);
        }
        
        if ( false !== $sent ) {
            // If they're resetting their password, we're making sure they're logged out
            session_destroy();
            
            return array('status'=>1,'message'=>'Check your email for the password reset link');
        }
        
        return array('status'=>0,'message'=>'There was an error send your password reset link');
    }
    
    public function reset_password($post) {
        // Required fields
        $required = array( 'selector', 'validator', 'password' );
        
        foreach ( $required as $key ) {
            if ( empty( $post[$key] ) ) {
                return array('status'=>0,'message'=>'There was an error processing your request. Error Code: 001');
            }
        }
        
        extract($post);
        
        // Get tokens
        $results = $this->db->get_results("SELECT * FROM password_reset WHERE selector = :selector AND expires >= :time", ['selector'=>$selector,'time'=>time()]);
        
        if ( empty( $results ) ) {
            return array('status'=>0,'message'=>'There was an error processing your request. Error Code: 002');
        }
        
        $auth_token = $results[0];
        $calc = hash('sha256', hex2bin($validator));
        
        // Validate tokens
        if ( hash_equals( $calc, $auth_token->token ) )  {
            $user = $this->user_exists($auth_token->email, 'email');
            
            if ( false === $user ) {
                return array('status'=>0,'message'=>'There was an error processing your request. Error Code: 003');
            }
            
            // Update password
            $update = $this->db->update('users', 
                array(
                    'password'  =>  password_hash($password, PASSWORD_DEFAULT),
                ), $user->ID
            );
            
            // Delete any existing tokens for this user
            $this->db->delete('password_reset', 'email', $user->email);
            
            if ( $update == true ) {
                // New password. New session.
                session_destroy();
            
                return array('status'=>1,'message'=>'Password updated successfully. <a href="index.php">Login here</a>');
            }
        }
        
        return array('status'=>0,'message'=>'There was an error processing your request. Error Code: 004');
    }
    
    private function rememberme($user) {
        $selector = base64_encode(random_bytes(9));
        $authenticator = random_bytes(33);
        
        // Set rememberme cookie
        setcookie(
            'rememberme', 
            $selector.':'.base64_encode($authenticator),
            time() + 864000,
            '/',
            '',
            true,
            true
        );
        
        // Clean up old tokens
        $this->db->delete('auth_tokens', 'username', $user->username);
        
        // Insert auth token into database
        $insert = $this->db->insert('auth_tokens', 
            array(
                'selector'  =>  $selector, 
                'token'     =>  hash('sha256', $authenticator),
                'username'  =>  $user->username,
                'expires'   =>  date('Y-m-d\TH:i:s', time() + 864000),
            )
        );
    }
    
    private function user_exists($where_value, $where_field = 'username') {
        $user = $this->db->get_results("
            SELECT * FROM users 
            WHERE {$where_field} = :where_value", 
            ['where_value'=>$where_value]
        );
        
        if ( false !== $user ) {
            return $user[0];
        }
        
        return false;
    }
}

$login = new Login;