<?php

/**
 * Tests for the HMAC-SHA1 utility functions used by the OpenID
 * library.
 *
 * PHP versions 4 and 5
 *
 * LICENSE: See the COPYING file included in this distribution.
 *
 * @package OpenID
 * @author JanRain, Inc. <openid@janrain.com>
 * @copyright 2005-2008 Janrain, Inc.
 * @license http://www.apache.org/licenses/LICENSE-2.0 Apache
 */

require_once 'Auth/OpenID/HMAC.php';
require_once 'Tests/Auth/OpenID/TestSuite.php';
require_once 'Tests/Auth/OpenID/TestUtil.php';

class Auth_OpenID_HMACSuite extends Auth_OpenID_TestSuite {
    public static function suite() {
        $suite = new Auth_OpenID_NonceSuite();

        $suite->addTestSuite('Auth_OpenID_HMAC_SHA1Test');
        $suite->addTestSuite('Auth_OpenID_HMAC_SHA256Test');

        return $suite;
    }
}

abstract class Auth_OpenID_HMAC_TestCase extends PHPUnit_Framework_TestCase {

    function _strConvert($s)
    {
        $repeat_pat = '/^0x([a-f0-9]{2}) repeated (\d+) times$/';
        if (preg_match($repeat_pat, $s, $match)) {
            $c = chr(hexdec($match[1]));
            $n = $match[2];
            $data = '';
            for ($i = 0; $i < $n; $i++) {
                $data .= $c;
            }
        } elseif (substr($s, 0, 2) == "0x") {
            $data = pack('H*', substr($s, 2, strlen($s) - 1));
        } elseif (preg_match('/^"(.*)"$/', $s, $match)) {
            $data = $match[1];
        } else {
            $data = $s;
        }
        return $data;
    }

    function clean_config($raw, $digest_len) {
        $data = array();
        foreach ($raw as $k => $v) {
            $clean = array();

            $clean['key'] = $this->_strConvert($v['key']);
            if (array_key_exists('key_len', $v)) {
                if (Auth_OpenID::bytes($clean['key']) != $v['key_len']) {
                    trigger_error('Bad key length', E_USER_ERROR);
                }
            }

            $clean['data'] = $this->_strConvert($v['data']);
            if (array_key_exists('data_len', $v)) {
                if (Auth_OpenID::bytes($clean['data']) != $v['data_len']) {
                    trigger_error('Bad data length', E_USER_ERROR);
                }
            }

            $clean['digest'] = $this->_strConvert($v['digest']);
            if (Auth_OpenID::bytes($clean['digest']) != $digest_len) {
                $l = Auth_OpenID::bytes($clean['digest']);
                trigger_error("Bad digest length: $l", E_USER_ERROR);
            }

            $data[] = $clean;
        }

        return $data;
    }
}

class Auth_OpenID_HMAC_SHA1Test extends Auth_OpenID_HMAC_TestCase {
    function hmac_data() {
        $config = parse_ini_file('Tests/Auth/OpenID/data/hmac-sha1.ini', true);
        $config = $this->clean_config($config, 20);
        return $config;
    }

    /**
     * @dataProvider hmac_data
     */
    function test_hmac($key, $data, $expected) {
        $actual = Auth_OpenID_HMACSHA1($key, $data);
        $this->assertEquals(bin2hex($expected), bin2hex($actual));
    }
}

class Auth_OpenID_HMAC_SHA256Test extends Auth_OpenID_HMAC_TestCase {
    function hmac_data() {
        $config = parse_ini_file('Tests/Auth/OpenID/data/hmac-sha256.ini', true);
        $config = $this->clean_config($config, 32);
        return $config;
    }

    /**
     * @dataProvider hmac_data
     */
    function test_hmac($key, $data, $expected) {
        $actual = Auth_OpenID_HMACSHA256($key, $data);
        $this->assertEquals(bin2hex($expected), bin2hex($actual));
    }
}

