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

/**
 * Exposes the protected methods of the filter.
 *
 * @package MvcAuthenticationTiein
 * @version //autogen//
 * @subpackage Tests
 * @access private
 */
class ezcMvcAuthenticationFilterWrapper extends ezcMvcAuthenticationFilter
{
    public function setupAuth( $user = null, $password = null )
    {
        return parent::setupAuth( $user, $password );
    }

    public function hashPassword( $password )
    {
        return parent::hashPassword( $password );
    }
}

/**
 * A filter which overrides hashPassword() with a deterministic hash.
 *
 * @package MvcAuthenticationTiein
 * @version //autogen//
 * @subpackage Tests
 * @access private
 */
class ezcMvcAuthenticationFilterSha1Wrapper extends ezcMvcAuthenticationFilter
{
    protected function hashPassword( $password )
    {
        return sha1( (string) $password );
    }
}

/**
 * @package MvcAuthenticationTiein
 * @version //autogen//
 * @subpackage Tests
 */
class ezcMvcAuthenticationFilterTest extends ezcTestCase
{
    private $db;

    public static function suite()
    {
        return new PHPUnit\Framework\TestSuite( "ezcMvcAuthenticationFilterTest" );
    }

    public function setUp() : void
    {
        if ( !ezcBaseFeatures::hasExtensionSupport( 'pdo_sqlite' ) )
        {
            $this->markTestSkipped( 'PHP must be compiled with PDO SQLite.' );
        }
        $this->db = ezcDbFactory::create( 'sqlite://:memory:' );
        $this->db->exec( 'CREATE TABLE "user" ( "email" VARCHAR(255) PRIMARY KEY, "name" VARCHAR(255), "password" VARCHAR(255), "full name" VARCHAR(255) )' );
        ezcDbInstance::set( $this->db );
        $_SESSION = array();
    }

    public function tearDown() : void
    {
        $_SESSION = array();
        ezcDbInstance::reset();
    }

    private function insertUser( $email, $password )
    {
        $s = $this->db->prepare( 'INSERT INTO "user" ( "email", "name", "password" ) VALUES ( ?, ?, ? )' );
        $s->execute( array( $email, 'Jan Modaal', $password ) );
    }

    private function storedPassword( $email )
    {
        $s = $this->db->prepare( 'SELECT "password" FROM "user" WHERE "email" = ?' );
        $s->execute( array( $email ) );
        return $s->fetchColumn( 0 );
    }

    private function login( ezcMvcAuthenticationFilter $filter, $user, $password )
    {
        return $filter->login( new ezcMvcRequest(), $user, $password )->run();
    }

    public function testHashPasswordUsesPasswordHash()
    {
        $filter = new ezcMvcAuthenticationFilterWrapper();
        $hash = $filter->hashPassword( 'qwerty' );
        $this->assertTrue( password_verify( 'qwerty', $hash ) );
        $this->assertNotEquals( md5( 'qwerty' ), $hash );
        $this->assertNotEquals( $hash, $filter->hashPassword( 'qwerty' ) );
    }

    public function testCreateUserAndLogin()
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

    public function testLoginOverriddenDeterministicHash()
    {
        $this->insertUser( 'jan@example.com', sha1( 'qwerty' ) );
        $filter = new ezcMvcAuthenticationFilterSha1Wrapper();
        $this->assertTrue( $this->login( $filter, 'jan@example.com', 'qwerty' ) );
        $this->assertEquals( sha1( 'qwerty' ), $this->storedPassword( 'jan@example.com' ) );

        $_SESSION = array();
        $this->assertFalse( $this->login( $filter, 'jan@example.com', 'wrong' ) );
    }

    public function testSetupAuthFromSession()
    {
        $filter = new ezcMvcAuthenticationFilterWrapper();
        $_SESSION['ezcAuth_id'] = 'jan@example.com';
        $_SESSION['ezcAuth_timestamp'] = time();

        $deprecations = array();
        set_error_handler( function ( $errno, $errstr ) use ( &$deprecations )
        {
            $deprecations[] = $errstr;
            return true;
        }, E_DEPRECATED );
        try
        {
            $authentication = $filter->setupAuth();
        }
        finally
        {
            restore_error_handler();
        }

        $this->assertEquals( array(), $deprecations );
        $this->assertNull( $authentication->credentials->password );
        $this->assertTrue( $authentication->run() );
    }

    public function testSetupAuthEmptySession()
    {
        $filter = new ezcMvcAuthenticationFilterWrapper();
        $this->assertFalse( $filter->setupAuth()->run() );
    }

    public function testCreateUserQuotesExtraInfoColumns()
    {
        $filter = new ezcMvcAuthenticationFilter();
        $filter->createUser( 'jan@example.com', 'qwerty', array( 'full name' => 'Jan Modaal' ) );
        $s = $this->db->query( 'SELECT "full name" FROM "user"' );
        $this->assertEquals( 'Jan Modaal', $s->fetchColumn( 0 ) );
    }

    public function testCreateUserExtraInfoColumnWithQuote()
    {
        // the key is one column name, even when it contains the quote character
        $this->db->exec( 'ALTER TABLE "user" ADD COLUMN "na""me" VARCHAR(255)' );
        $filter = new ezcMvcAuthenticationFilter();
        $filter->createUser( 'jan@example.com', 'qwerty', array( 'na"me' => 'Jan Modaal' ) );
        $s = $this->db->query( 'SELECT "na""me", "name" FROM "user"' );
        $this->assertEquals( array( 'Jan Modaal', null ), $s->fetch( PDO::FETCH_NUM ) );
    }

    public function testGeneratePassword()
    {
        $filter = new ezcMvcAuthenticationFilter();
        $passwords = array();
        for ( $i = 0; $i < 20; $i++ )
        {
            $password = $filter->generatePassword( 'jan@example.com' );
            $this->assertMatchesRegularExpression( '/^[a-z0-9]{12}$/', $password );
            $passwords[] = $password;
        }
        $this->assertCount( 20, array_unique( $passwords ) );
    }
}
?>
