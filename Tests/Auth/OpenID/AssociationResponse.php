<?php

require_once "Tests/Auth/OpenID/TestUtil.php";
require_once "Tests/Auth/OpenID/MemStore.php";
require_once "Tests/Auth/OpenID/TestSuite.php";

require_once "Auth/OpenID/Message.php";
require_once "Auth/OpenID/Server.php";
require_once "Auth/OpenID/Consumer.php";
require_once "Auth/OpenID/Association.php";

class Auth_OpenID_AssociationResponseSuite extends Auth_OpenID_TestSuite {
    public static function suite() {
        $suite = new Auth_OpenID_AssociationResponseSuite();

        $suite->addTestSuite('Auth_OpenID_AssociationResponseTest');
        $suite->addTestSuite('Auth_OpenID_InvalidAssociationFieldsTest');
        $suite->addTestSuite('Auth_OpenID_ExtractAssociationDiffieHellmanTest');

        return $suite;
    }
}

abstract class Auth_OpenID_AssociationResponseTestCase extends PHPUnit_Framework_TestCase {

    static protected $association_response_values = array(
        'expires_in' => '1000',
        'assoc_handle' => 'a handle',
        'assoc_type' => 'a type',
        'session_type' => 'a session type',
        'ns' => Auth_OpenID_OPENID2_NS
    );

    function setUp()
    {
        $this->store = new Tests_Auth_OpenID_MemStore();
        $this->consumer = new Auth_OpenID_GenericConsumer($this->store);
        $this->endpoint = new Auth_OpenID_ServiceEndpoint();
    }

    /**
     * Build an association response message that contains the specified
     * subset of keys. The values come from association_response_values.
     *
     * This is useful for testing for missing keys and other times that we
     * don't care what the values are.
     */
    static function mkAssocResponse($keys)
    {
        $args = array();

        foreach ($keys as $key) {
            $args[$key] = self::$association_response_values[$key];
        }

        return Auth_OpenID_Message::fromOpenIDArgs($args);
    }

    function assertOpenIDFailure($response) {
        $this->assertTrue( Auth_OpenID::isFailure($response) );
    }
}

/**
 * Test for returning an error upon missing fields in association
 * responses for OpenID 2
 */
class Auth_OpenID_AssociationResponseTest extends Auth_OpenID_AssociationResponseTestCase {

    function missingFields_dataProvider() {
        return array(
            // OpenID 2 messages
            array( array('ns') ),
            array( array('assoc_handle', 'assoc_type', 'session_type', 'ns') ),
            array( array('expires_in', 'assoc_type', 'session_type', 'ns') ),
            array( array('expires_in', 'assoc_handle', 'session_type', 'ns') ),
            array( array('expires_in', 'assoc_handle', 'assoc_type', 'ns') ),

            // OpenID 1 messages
            array( array() ),
            array( array('assoc_handle', 'assoc_type') ),
            array( array('expires_in', 'assoc_type') ),
            array( array('expires_in', 'assoc_handle') ),
        );
    }

    /**
     * @dataProvider missingFields_dataProvider
     */
    function test_missingFields($keys)
    {
        $msg = self::mkAssocResponse( array('ns') );
        $association = $this->consumer->_extractAssociation($msg, null);
        $this->assertOpenIDFailure($association);
    }

    function mismatch_dataProvider() {
        return array(
            array('no-encryption', ''),
            array('DH-SHA1', 'no-encryption'),
            array('DH-SHA256', 'no-encryption'),
            array('no-encryption', 'DH-SHA1'),
            array('DH-SHA1', 'DH-SHA256', true),
            array('DH-SHA256', 'DH-SHA1', true),
            array('no-encryption', 'DH-SHA1', true),
        );
    }


    /**
     * @dataProvider mismatch_dataProvider
     */
    function test_sessionTypeMismatch($requested_session_type, $response_session_type, $openid1=false)
    {
        $assoc_session = (object) array('session_type' => $requested_session_type, 'allowed_assoc_types' => array());
        $keys = array_keys(parent::$association_response_values);
        if ($openid1) {
            if (in_array('ns', $keys)) {
                unset($keys[array_search('ns', $keys)]);
            }
        }

        $msg = self::mkAssocResponse($keys);
        $msg->setArg(Auth_OpenID_OPENID_NS, 'session_type',
                     $response_session_type);
        $this->assertTrue(
           $this->consumer->_extractAssociation($msg, $assoc_session) === null);
    }

    function responseSessionType_dataProvider() {
        return array(
            array('no-encryption', null),
            array('no-encryption', ''),
            array('no-encryption', 'no-encryption'),
            array('DH-SHA1', 'DH-SHA1'),

            // DH-SHA256 is not a valid session type for OpenID1, but this
            // function does not test that. This is mostly just to make sure
            // that it will pass-through stuff that is not explicitly handled,
            // so it will get handled the same way as it is handled for OpenID 2
            array('DH-SHA256', 'DH-SHA256'),
        );
    }

    /**
     * @dataProvider responseSessionType_dataProvider
     */
    function test_responseSessionType($expected_session_type, $session_type_value)
    {
        // Create a Message with just 'session_type' in it, since
        // that's all this function will use. 'session_type' may be
        // absent if it's set to None.
        $args = array();
        if ($session_type_value !== null) {
            $args['session_type'] = $session_type_value;
        }
        $message = Auth_OpenID_Message::fromOpenIDArgs($args);
        $this->assertTrue($message->isOpenID1());

        $actual_session_type = $this->consumer->_getOpenID1SessionType($message);
        $error_message = sprintf('Returned sesion type parameter %s was expected ' .
                                 'to yield session type %s, but yielded %s',
                                 $session_type_value, $expected_session_type,
                                 $actual_session_type);
        $this->assertEquals(
                            $expected_session_type,
                            $actual_session_type,
                            $error_message);
    }

}

class DummyAssociationSession {
    var $secret = "shh! don't tell!";
    var $extract_secret_called = false;
    var $session_type = null;
    var $allowed_assoc_types = null;

    function extractSecret($message)
    {
        $this->extract_secret_called = true;
        return $this->secret;
    }
}

class Auth_OpenID_InvalidAssociationFieldsTest extends Auth_OpenID_AssociationResponseTestCase {
    function setUp()
    {
        parent::setUp();
        $this->session_type = 'testing-session';

        // This must something that works for Association.fromExpiresIn
        $this->assoc_type = 'HMAC-SHA1';

        $this->assoc_handle = 'testing-assoc-handle';

        // These arguments should all be valid
        $this->assoc_response = Auth_OpenID_Message::fromOpenIDArgs(array(
            'expires_in' => '1000',
            'assoc_handle' => $this->assoc_handle,
            'assoc_type' => $this->assoc_type,
            'session_type' => $this->session_type,
            'ns' => Auth_OpenID_OPENID2_NS,
            ));

        $this->assoc_session = new DummyAssociationSession();

        // Make the session for the response's session type
        $this->assoc_session->session_type = $this->session_type;
        $this->assoc_session->allowed_assoc_types = array($this->assoc_type);
    }

    function test_worksWithGoodFields()
    {
        // Handle a full successful association response
        $assoc = $this->consumer->_extractAssociation(
                   $this->assoc_response, $this->assoc_session);
        $this->assertTrue($this->assoc_session->extract_secret_called);
        $this->assertEquals($this->assoc_session->secret, $assoc->secret);
        $this->assertEquals(1000, $assoc->lifetime);
        $this->assertEquals($this->assoc_handle, $assoc->handle);
        $this->assertEquals($this->assoc_type, $assoc->assoc_type);
    }

    function test_badAssocType()
    {
        // Make sure that the assoc type in the response is not valid
        // for the given session.
        $this->assoc_session->allowed_assoc_types = array();
        $this->assertTrue(
             $this->consumer->_extractAssociation($this->assoc_response,
                                                  $this->assoc_session) === null);
    }

    function test_badExpiresIn()
    {
        // Invalid value for expires_in should cause failure
        $this->assoc_response->setArg(Auth_OpenID_OPENID_NS, 'expires_in', 'forever');
        $assoc = $this->consumer->_extractAssociation($this->assoc_response,
                                                      $this->assoc_session);
        $this->assertTrue(Auth_OpenID::isFailure($assoc));
    }
}

class Auth_OpenID_ExtractAssociationDiffieHellmanTest extends Auth_OpenID_AssociationResponseTestCase {
    var $secret = 'xxxxxxxxxxxxxxxxxxxx';

    function _setUpDH()
    {
        list($sess, $message) = $this->consumer->_createAssociateRequest(
                                  $this->endpoint, 'HMAC-SHA1', 'DH-SHA1');

        // XXX: this is testing _createAssociateRequest
        $this->assertEquals($this->endpoint->compatibilityMode(),
                            $message->isOpenID1());

        $server_sess = Auth_OpenID_DiffieHellmanSHA1ServerSession::fromMessage($message);
        $server_resp = $server_sess->answer($this->secret);
        $server_resp['assoc_type'] = 'HMAC-SHA1';
        $server_resp['assoc_handle'] = 'handle';
        $server_resp['expires_in'] = '1000';
        $server_resp['session_type'] = 'DH-SHA1';
        return array($sess, Auth_OpenID_Message::fromOpenIDArgs($server_resp));
    }

    function test_success()
    {
        list($sess, $server_resp) = $this->_setUpDH();
        $ret = $this->consumer->_extractAssociation($server_resp, $sess);
        $this->assertTrue($ret !== null);
        $this->assertEquals($ret->assoc_type, 'HMAC-SHA1');
        $this->assertEquals($ret->secret, $this->secret);
        $this->assertEquals($ret->handle, 'handle');
        $this->assertEquals($ret->lifetime, 1000);
    }

    function test_openid2success()
    {
        // Use openid 2 type in endpoint so _setUpDH checks
        // compatibility mode state properly
        $this->endpoint->type_uris = array(Auth_OpenID_TYPE_2_0,
                                           Auth_OpenID_TYPE_1_1);
        $this->test_success();
    }

    /**
     * Can't run this test because the base64 decoder is broken.
     */
    /*
    function test_badDHValues()
    {
        list($sess, $server_resp) = $this->_setUpDH();
        $server_resp->setArg(Auth_OpenID_OPENID_NS, 'enc_mac_key', "\x00\x00\x00");
        $this->assertTrue($this->consumer->_extractAssociation($server_resp, $sess) === null);
    }
    */
}

