<?php

/**
 * Tests for the Nonce implementation.
 *
 * PHP versions 4 and 5
 *
 * LICENSE: See the COPYING file included in this distribution.
 *
 * @package OpenID
 * @author JanRain, Inc. <openid@janrain.com>
 * @copyright 2006 Janrain, Inc.
 * @license http://www.apache.org/licenses/LICENSE-2.0 Apache
 */

require_once "Tests/Auth/OpenID/TestSuite.php";
require_once 'Auth/OpenID/Nonce.php';

class Auth_OpenID_NonceSuite extends Auth_OpenID_TestSuite {
    public static function suite() {
        $suite = new Auth_OpenID_NonceSuite();

        $suite->addTestSuite('Auth_OpenID_NonceTest');
        $suite->addTestSuite('Auth_OpenID_Nonce_BadSplitTest');
        $suite->addTestSuite('Auth_OpenID_Nonce_TimestampTest');

        return $suite;
    }
}

class Auth_OpenID_NonceTest extends PHPUnit_Framework_TestCase {

	private $regex = '/\A\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\dZ/';

    function test_mkNonce()
    {
        $nonce_str = Auth_OpenID_mkNonce();
        $this->assertEquals(1, preg_match($this->regex, $nonce_str));
    }

    function test_mkNonce_when()
    {
        $nonce_str = Auth_OpenID_mkNonce(0);
        $this->assertEquals(1, preg_match($this->regex, $nonce_str));
        $tpart = substr($nonce_str, 0, 20);
        $this->assertEquals('1970-01-01T00:00:00Z', $tpart);
    }

    function test_splitNonce()
    {
        $s = '1970-01-01T00:00:00Z';
        $expected_t = 0;
        $expected_salt = '';
        list($actual_t, $actual_salt) = Auth_OpenID_splitNonce($s);
        $this->assertEquals($expected_t, $actual_t);
        $this->assertEquals($expected_salt, $actual_salt);
    }


    function test_mkSplit()
    {
        $t = 42;;
        $nonce_str = Auth_OpenID_mkNonce($t);
        $this->assertEquals(1, preg_match($this->regex, $nonce_str));
        list($et, $salt) = Auth_OpenID_splitNonce($nonce_str);
        $this->assertEquals(6, strlen($salt));
        $this->assertEquals($et, $t);
    }
}

class Auth_OpenID_Nonce_BadSplitTest extends PHPUnit_Framework_TestCase {

	function split_data() {
		return array(
			array(''),
			array('1970-01-01T00:00:00+1:00'),
			array('1969-01-01T00:00:00Z'),
			array('1970-00-01T00:00:00Z'),
			array('1970.01-01T00:00:00Z'),
			array('Thu Sep  7 13:29:31 PDT 2006'),
			array('monkeys'),
		);
	}

	/**
	 * @dataProvider split_data
	 */
	function test_split($nonce) {
        $result = Auth_OpenID_splitNonce($nonce);
        $this->assertNull($result);
	}
}

class Auth_OpenID_Nonce_TimestampTest extends PHPUnit_Framework_TestCase {

	function timestamp_data() {
		return array(
		   // exact, no allowed skew
		   array('1970-01-01T00:00:00Z', 0, 0, true),

		   // exact, large skew
		   array('1970-01-01T00:00:00Z', 1000, 0, true),

		   // no allowed skew, one second old
		   array('1970-01-01T00:00:00Z', 0, 1, false),

		   // many seconds old, outside of skew
		   array('1970-01-01T00:00:00Z', 10, 50, false),

		   // one second old, one second skew allowed
		   array('1970-01-01T00:00:00Z', 1, 1, true),

		   // One second in the future, one second skew allowed
		   array('1970-01-01T00:00:02Z', 1, 1, true),

		   // two seconds in the future, one second skew allowed
		   array('1970-01-01T00:00:02Z', 1, 0, false),

		   // malformed nonce string
		   array('monkeys', 0, 0, false)
		);
	}

	/**
	 * @dataProvider timestamp_data
	 */
    function test_timestamp($nonce, $skew, $now, $expected)
    {
        $actual = Auth_OpenID_checkTimestamp($nonce, $skew, $now);
        $this->assertEquals($expected, $actual);
    }
}

