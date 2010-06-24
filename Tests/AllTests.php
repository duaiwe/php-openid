<?php

require_once 'PHPUnit/Framework.php';

require_once 'Tests/Auth/OpenID/AllTests.php';


class AllTests {

    public static function suite() {
        $suite = new PHPUnit_Framework_TestSuite('OpenID');

        $suite->addTest(Auth_OpenID_AllTests::suite());

        return $suite;
    }

}


?>
