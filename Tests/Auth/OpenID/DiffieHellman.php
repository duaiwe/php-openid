<?php

/**
 * Tests for the Diffie-Hellman key exchange implementation in the
 * OpenID library.
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

require_once 'Auth/OpenID/DiffieHellman.php';
require_once 'Tests/Auth/OpenID/TestUtil.php';

class Auth_OpenID_DiffieHellmanTest extends PHPUnit_Framework_TestCase {

    protected function setUp() {
        if (defined('Auth_OpenID_NO_MATH_SUPPORT') && Auth_OpenID_NO_MATH_SUPPORT) {
            $this->markTestSkipped('No Math Support Available');
        }
    }

    function private_data() {
        $config = parse_ini_file('Tests/Auth/OpenID/data/dh-private.cfg', true);
        return $config;
    }

    /**
     * @dataProvider private_data
     */
    function test_private($input, $expected) {
        $lib = Auth_OpenID_getMathLib();
        $dh = new Auth_OpenID_DiffieHellman(null, null, $input);
        $this->assertEquals($lib->cmp($expected, $dh->getPublicKey()), 0);
    }


    function exch_data() {
        $config = parse_ini_file('Tests/Auth/OpenID/data/dh-exch.cfg', true);
        return $config;
    }

    /**
     * @dataProvider exch_data
     */
    function test_exch($p1, $p2, $shared)
    {
        $lib = Auth_OpenID_getMathLib();
        $shared = $lib->init($shared);
        $dh1 = new Auth_OpenID_DiffieHellman(null, null, $p1);
        $dh2 = new Auth_OpenID_DiffieHellman(null, null, $p2);
        $sh1 = $dh1->getSharedSecret($dh2->getPublicKey());
        $sh2 = $dh2->getSharedSecret($dh1->getPublicKey());
        $this->assertEquals($lib->cmp($shared, $sh1), 0);
        $this->assertEquals($lib->cmp($shared, $sh2), 0);
    }
}

