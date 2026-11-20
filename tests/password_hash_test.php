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
 * Tests the password hashes of ezcMvcAuthenticationFilter.
 *
 * @package MvcAuthenticationTiein
 * @version //autogen//
 * @subpackage Tests
 */
class ezcMvcAuthenticationFilterPasswordHashTest extends ezcMvcAuthenticationFilterTestCase
{
    public static function suite()
    {
        return new PHPUnit\Framework\TestSuite( __CLASS__ );
    }

    public function testHashPasswordUsesPasswordHash()
    {
        $filter = new ezcMvcAuthenticationFilterWrapper();
        $hash = $filter->hashPassword( 'qwerty' );
        $this->assertTrue( password_verify( 'qwerty', $hash ) );
        $this->assertNotEquals( md5( 'qwerty' ), $hash );
        $this->assertNotEquals( $hash, $filter->hashPassword( 'qwerty' ) );
    }

    public function testCreateUserStoresPasswordHash()
    {
        $filter = new ezcMvcAuthenticationFilter();
        $filter->createUser( 'jan@example.com', 'qwerty', array( 'name' => 'Jan Modaal' ) );
        $stored = $this->storedPassword( 'jan@example.com' );
        $this->assertTrue( password_verify( 'qwerty', $stored ) );

        $this->assertTrue( $this->login( $filter, 'jan@example.com', 'qwerty' ) );
        $this->assertEquals( 'jan@example.com', $_SESSION['ezcAuth_id'] );
        // a current hash is not replaced
        $this->assertEquals( $stored, $this->storedPassword( 'jan@example.com' ) );
    }

    public function testLoginLegacyMd5HashIsRehashed()
    {
        $this->insertUser( 'jan@example.com', md5( 'qwerty' ) );
        $filter = new ezcMvcAuthenticationFilter();
        $this->assertTrue( $this->login( $filter, 'jan@example.com', 'qwerty' ) );

        $stored = $this->storedPassword( 'jan@example.com' );
        $this->assertNotEquals( md5( 'qwerty' ), $stored );
        $this->assertTrue( password_verify( 'qwerty', $stored ) );

        // and the new hash works for the next login
        $_SESSION = array();
        $this->assertTrue( $this->login( $filter, 'jan@example.com', 'qwerty' ) );
    }

    public function testLoginLegacyMd5HashWrongPassword()
    {
        $this->insertUser( 'jan@example.com', md5( 'qwerty' ) );
        $filter = new ezcMvcAuthenticationFilter();
        $this->assertFalse( $this->login( $filter, 'jan@example.com', 'wrong' ) );
        $this->assertFalse( $this->login( $filter, 'jan@example.com', md5( 'qwerty' ) ) );
        $this->assertEquals( md5( 'qwerty' ), $this->storedPassword( 'jan@example.com' ) );
    }

    private function createMd5SizedUserTable()
    {
        $this->db->exec( 'DROP TABLE "user"' );
        // SQLite does not enforce VARCHAR lengths, the CHECK constraint
        // rejects a longer value like a database in strict mode does
        $this->db->exec( 'CREATE TABLE "user" ( "email" VARCHAR(255) PRIMARY KEY, "name" VARCHAR(255), "password" VARCHAR(32) CHECK ( length( "password" ) <= 32 ) )' );
    }

    public function testLoginLegacyMd5HashColumnTooShortRejected()
    {
        $this->createMd5SizedUserTable();
        $this->insertUser( 'jan@example.com', md5( 'qwerty' ) );

        $filter = new ezcMvcAuthenticationFilter();
        $this->assertTrue( $this->login( $filter, 'jan@example.com', 'qwerty' ) );
        $this->assertEquals( md5( 'qwerty' ), $this->storedPassword( 'jan@example.com' ) );

        $_SESSION = array();
        $this->assertTrue( $this->login( $filter, 'jan@example.com', 'qwerty' ) );
        $_SESSION = array();
        $this->assertFalse( $this->login( $filter, 'jan@example.com', 'wrong' ) );

        $_SESSION = array();
        $this->assertTrue( $this->login( new ezcMvcAuthenticationFilter(), 'jan@example.com', 'qwerty' ) );
        $this->assertEquals( md5( 'qwerty' ), $this->storedPassword( 'jan@example.com' ) );
    }

    public function testLoginLegacyMd5HashColumnTooShortTruncated()
    {
        $this->db->exec( 'DROP TABLE "user"' );
        $this->db->exec( 'CREATE TABLE "user" ( "email" VARCHAR(255) PRIMARY KEY, "name" VARCHAR(255), "password" VARCHAR(32) )' );
        // truncates like a database that is not in strict mode
        $this->db->exec( 'CREATE TRIGGER "truncate_password" AFTER UPDATE OF "password" ON "user" WHEN length( NEW."password" ) > 32 ' .
                         'BEGIN UPDATE "user" SET "password" = substr( NEW."password", 1, 32 ) WHERE "email" = NEW."email"; END' );
        $this->insertUser( 'jan@example.com', md5( 'qwerty' ) );

        $filter = new ezcMvcAuthenticationFilter();
        $this->assertTrue( $this->login( $filter, 'jan@example.com', 'qwerty' ) );
        $this->assertEquals( md5( 'qwerty' ), $this->storedPassword( 'jan@example.com' ) );

        $_SESSION = array();
        $this->assertTrue( $this->login( new ezcMvcAuthenticationFilter(), 'jan@example.com', 'qwerty' ) );
        $this->assertEquals( md5( 'qwerty' ), $this->storedPassword( 'jan@example.com' ) );
    }

    public function testLoginLegacyMd5HashRehashDisabled()
    {
        $this->insertUser( 'jan@example.com', md5( 'qwerty' ) );
        $filter = new ezcMvcAuthenticationFilter( new ezcMvcAuthenticationFilterOptions( array( 'rehashPasswords' => false ) ) );
        $this->assertTrue( $this->login( $filter, 'jan@example.com', 'qwerty' ) );
        $this->assertEquals( md5( 'qwerty' ), $this->storedPassword( 'jan@example.com' ) );
    }

    public function testLoginPasswordWithNulByte()
    {
        // password_hash() throws for a password with a NUL byte; the login
        // must fail the same way for unknown and existing users
        $filter = new ezcMvcAuthenticationFilter();
        $this->assertFalse( $this->login( $filter, 'nobody@example.com', "qw\0erty" ) );

        $filter->createUser( 'jan@example.com', 'qwerty', array() );
        $this->assertFalse( $this->login( $filter, 'jan@example.com', "qw\0erty" ) );

        $this->insertUser( 'piet@example.com', md5( 'qwerty' ) );
        $this->assertFalse( $this->login( $filter, 'piet@example.com', "qw\0erty" ) );
    }

    public function testLoginLegacyMd5HashPasswordWithNulByte()
    {
        // the MD5 hash still matches, but it can not be replaced
        $this->insertUser( 'jan@example.com', md5( "qw\0erty" ) );
        $filter = new ezcMvcAuthenticationFilter();
        $this->assertTrue( $this->login( $filter, 'jan@example.com', "qw\0erty" ) );
        $this->assertEquals( md5( "qw\0erty" ), $this->storedPassword( 'jan@example.com' ) );
    }

    public function testOptionRehashPasswords()
    {
        $options = new ezcMvcAuthenticationFilterOptions();
        $this->assertTrue( $options->rehashPasswords );
        try
        {
            $options->rehashPasswords = 'no';
            $this->fail( 'Expected exception was not thrown.' );
        }
        catch ( ezcBaseValueException $e )
        {
            $this->assertStringContainsString( 'rehashPasswords', $e->getMessage() );
        }
    }
}
?>
