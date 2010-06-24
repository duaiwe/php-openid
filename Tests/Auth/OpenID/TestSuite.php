<?php

// TODO: copy error handling logic from Tests/TestDriver.php
class Auth_OpenID_TestSuite extends PHPUnit_Framework_TestSuite {
    protected function setUp() {
        ini_set('error_log', '/dev/null');
        //error_reporting(E_ALL | E_STRICT);
        //set_error_handler( array(__CLASS__, 'error_handler') );
    }

    public static function error_handler($code, $message) {
    }
}

?>
