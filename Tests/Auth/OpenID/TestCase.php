<?php

/**
 * Base Test Case for OpenID tests.
 */
abstract class Auth_OpenID_TestCase extends PHPUnit_Framework_TestCase {

    /**
     * Assert that the message is an OpenID failure
     */
    function assertOpenIDFailure($message) {
        $this->assertTrue( Auth_OpenID::isFailure($message) );
    }

    function assertOpenIDValueEquals($message, $key, $expected, $ns=null) {
        if ($ns === null) $ns = Auth_OpenID_OPENID_NS;

        $actual = $message->getArg($ns, $key);
        $error_message = sprintf('Wrong value for openid.%s: expected=%s, actual=%s', 
            $key, $expected, $actual);

        $this->assertEquals($expected, $actual, $error_message);
    }

    function assertOpenIDNotHasKey($message, $key, $ns=null) {
        if ($ns === null) $ns = Auth_OpenID_OPENID_NS;

        $actual = $message->getArg($ns, $key);
        $error_message = sprintf('openid.%s unexpectedly present: %s', $key, $actual);

        $this->assertFalse($message->hasKey($ns, $key), $error_message);
    }

}

