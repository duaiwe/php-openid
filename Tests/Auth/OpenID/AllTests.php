<?php

require_once 'Tests/Auth/OpenID/AX.php';
require_once 'Tests/Auth/OpenID/Association.php';
require_once 'Tests/Auth/OpenID/CryptUtil.php';
require_once 'Tests/Auth/OpenID/DiffieHellman.php';
require_once 'Tests/Auth/OpenID/Extension.php';
require_once 'Tests/Auth/OpenID/HMAC.php';
require_once 'Tests/Auth/OpenID/KVForm.php';
require_once 'Tests/Auth/OpenID/Message.php';
require_once 'Tests/Auth/OpenID/Negotiation.php';
require_once 'Tests/Auth/OpenID/Nonce.php';
require_once 'Tests/Auth/OpenID/Util.php';
require_once 'Tests/Auth/OpenID/URINorm.php';

class Auth_OpenID_AllTests {

    public static function suite() {
        $suite = new PHPUnit_Framework_TestSuite();

        $suite->addTestSuite('Auth_OpenID_AXSuite');
        $suite->addTestSuite('Tests_Auth_OpenID_Association');
        $suite->addTestSuite('Tests_Auth_OpenID_CryptUtil');
        $suite->addTestSuite('Auth_OpenID_DiffieHellmanTest');
        $suite->addTestSuite('Tests_Auth_OpenID_Extension');
        $suite->addTestSuite('Auth_OpenID_HMACSuite');
        $suite->addTestSuite('Auth_OpenID_KVFormTest');
        $suite->addTestSuite('Auth_OpenID_MessageSuite');
        $suite->addTestSuite('Auth_OpenID_NegotiationSuite');
        $suite->addTestSuite('Auth_OpenID_NonceSuite');
        $suite->addTestSuite('Tests_Auth_OpenID_Util');
        $suite->addTestSuite('Tests_Auth_OpenID_URINorm');

        return $suite;
    }
}

?>
