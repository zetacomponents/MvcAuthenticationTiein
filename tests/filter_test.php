<?php
/**
 *
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 *
 * @license http://www.apache.org/licenses/LICENSE-2.0 Apache License, Version 2.0
 * @filesource
 * @package MvcAuthenticationTiein
 * @version //autogen//
 * @subpackage Tests
 */

require_once( dirname( __FILE__ ) . '/filter_test_case.php' );

/**
 * Tests logging in with ezcMvcAuthenticationFilter.
 *
 * @package MvcAuthenticationTiein
 * @version //autogen//
 * @subpackage Tests
 */
class ezcMvcAuthenticationFilterTest extends ezcMvcAuthenticationFilterTestCase
{
    public static function suite()
    {
        return new PHPUnit\Framework\TestSuite( __CLASS__ );
    }

    public function testCreateUserAndLogin()
    {
        $filter = new ezcMvcAuthenticationFilter();
        $filter->createUser( 'jan@example.com', 'qwerty', array( 'name' => 'Jan Modaal' ) );

        $this->assertTrue( $this->login( $filter, 'jan@example.com', 'qwerty' ) );
        $this->assertEquals( 'jan@example.com', $_SESSION['ezcAuth_id'] );
    }

    public function testLoginWrongPassword()
    {
        $filter = new ezcMvcAuthenticationFilter();
        $filter->createUser( 'jan@example.com', 'qwerty', array() );
        $this->assertFalse( $this->login( $filter, 'jan@example.com', 'wrong' ) );
        $this->assertFalse( isset( $_SESSION['ezcAuth_id'] ) );
    }

    public function testLoginWrongPasswordIsTheStoredHash()
    {
        $filter = new ezcMvcAuthenticationFilter();
        $filter->createUser( 'jan@example.com', 'qwerty', array() );
        $this->assertFalse( $this->login( $filter, 'jan@example.com', $this->storedPassword( 'jan@example.com' ) ) );
    }

    public function testLoginUnknownUser()
    {
        $filter = new ezcMvcAuthenticationFilter();
        $this->assertFalse( $this->login( $filter, 'nobody@example.com', 'qwerty' ) );
    }

    public function testLoginEmptyStoredPassword()
    {
        $this->insertUser( 'jan@example.com', '' );
        $filter = new ezcMvcAuthenticationFilter();
        $this->assertFalse( $this->login( $filter, 'jan@example.com', '' ) );
    }

    public function testLoginOverriddenDeterministicHash()
    {
        $this->insertUser( 'jan@example.com', sha1( 'qwerty' ) );
        $filter = new ezcMvcAuthenticationFilterSha1Wrapper();
        $this->assertTrue( $this->login( $filter, 'jan@example.com', 'qwerty' ) );
        $this->assertEquals( sha1( 'qwerty' ), $this->storedPassword( 'jan@example.com' ) );

        $_SESSION = array();
        $this->assertFalse( $this->login( $filter, 'jan@example.com', 'wrong' ) );
    }

    public function testSetupAuthEmptySession()
    {
        $filter = new ezcMvcAuthenticationFilterWrapper();
        $this->assertFalse( $filter->setupAuth()->run() );
    }
}
?>
