<?php

require_once 'Tests/Auth/OpenID/Message.php';

class Auth_OpenID_AllTests {

    public static function suite() {
        $suite = new PHPUnit_Framework_TestSuite();

        $suite->addTestSuite('Auth_OpenID_MessageSuite');

        return $suite;
    }
}

?>
