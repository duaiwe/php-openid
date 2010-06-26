<?php

/**
 * Tests for the URI normalization routines used by the OpenID
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

require_once 'Auth/OpenID/URINorm.php';
require_once 'Tests/Auth/OpenID/TestUtil.php';

class Tests_Auth_OpenID_URINorm extends PHPUnit_Framework_TestCase {

    function normalization_data()
    {
        $config = parse_ini_file('Tests/Auth/OpenID/data/uri-normalization.cfg', true);
        return $config;
    }

    /**
     * @dataProvider normalization_data
     */
    function test_normalization($name, $uri, $expected)
    {
        $actual = Auth_OpenID_urinorm($uri);
        $this->assertEquals($expected, $actual);
    }

}

