<?php

namespace Jasny\Auth;

use Jasny\Auth;
use PHPUnit_Framework_TestCase as TestCase;
use PHPUnit_Framework_MockObject_MockObject as MockObject;
use Hashids\Hashids;

/**
 * @covers Jasny\Auth\Confirmation
 */
class ConfirmationTest extends TestCase
{
    /**
     * @var Confirmation|MockObject
     */
    public $auth;
    
    public function setUp()
    {
        $this->auth = $this->getMockForTrait(Auth\Confirmation::class);
    }
    
    /**
     * @return string
     */
    public function testGetConfirmationToken()
    {
        $this->auth->method('getConfirmationSecret')->willReturn('very secret');
        
        $user = $this->createMock(Auth\User::class);
        $user->method('getId')->willReturn(123);
        
        $token = $this->auth->getConfirmationToken($user, 'foo bar');
        
        $this->assertInternalType('string', $token);
        $this->assertNotEmpty($token);
        
        return $token;
    }
    
    /**
     * @depends testGetConfirmationToken
     * 
     * @param string $token
     */
    public function testFetchUserForConfirmationWithValidToken($token)
    {
        $user = $this->createMock(Auth\User::class);
        
        $this->auth->method('getConfirmationSecret')->willReturn('very secret');
        $this->auth->expects($this->once())->method('fetchUserById')->with(123)->willReturn($user);
        
        $result = $this->auth->fetchUserForConfirmation($token, 'foo bar');
        
        $this->assertSame($user, $result);
    }
    
    /**
     * @depends testGetConfirmationToken
     * 
     * @param string $token
     */
    public function testFetchUserForConfirmationWithDeletedUser($token)
    {
        $this->auth->method('getConfirmationSecret')->willReturn('very secret');
        $this->auth->expects($this->once())->method('fetchUserById')->with(123)->willReturn(null);
        
        $result = $this->auth->fetchUserForConfirmation($token, 'foo bar');
        
        $this->assertNull($result);
    }
    
    public function testFetchUserForConfirmationWithInvalidToken()
    {
        $this->auth->method('getConfirmationSecret')->willReturn('very secret');
        $this->auth->expects($this->never())->method('fetchUserById');
        
        $result = $this->auth->fetchUserForConfirmation('faKeToken', 'foo bar');
        
        $this->assertNull($result);
    }
    
    public function testFetchUserForConfirmationWithInvalidChecksum()
    {
        $user = $this->createMock(User::class);
        
        $salt = hash('sha256', 'very secret' . 'foo bar'); // hashids salt has been compromized
        $hashids = new Hashids($salt);
        
        $token = $hashids->encodeHex(str_repeat('0', 12) . '123'); // token with id and invalid checksum
        
        $this->auth->method('getConfirmationSecret')->willReturn('very secret');
        $this->auth->expects($this->once())->method('fetchUserById')->with(123)->willReturn($user);
        
        $result = $this->auth->fetchUserForConfirmation($token, 'foo bar');
        
        $this->assertNull($result);
    }
    
    /**
     * @depends testGetConfirmationToken
     * 
     * @param string $token
     */
    public function testFetchUserForConfirmationWithOtherSecret($token)
    {
        $this->auth->method('getConfirmationSecret')->willReturn('other secret');
        $this->auth->expects($this->never())->method('fetchUserById');
        
        $result = $this->auth->fetchUserForConfirmation($token, 'foo bar');
        
        $this->assertNull($result);
    }
    
    /**
     * @depends testGetConfirmationToken
     * 
     * @param string $token
     */
    public function testFetchUserForConfirmationWithOtherSubject($token)
    {
        $this->auth->method('getConfirmationSecret')->willReturn('very secret');
        $this->auth->expects($this->never())->method('fetchUserById');
        
        $result = $this->auth->fetchUserForConfirmation($token, 'other subject');
        
        $this->assertNull($result);
    }
    
    
    /**
     * @return string
     */
    public function testGetConfirmationTokenWithHexId()
    {
        $this->auth->method('getConfirmationSecret')->willReturn('very secret');
        
        $user = $this->createMock(Auth\User::class);
        $user->method('getId')->willReturn('585c7f9a22a9037a1c8b4567');
        
        $token = $this->auth->getConfirmationToken($user, 'foo bar');
        
        $this->assertInternalType('string', $token);
        $this->assertNotEmpty($token);
        
        return $token;
    }
    
    /**
     * @depends testGetConfirmationTokenWithHexId
     * 
     * @param string $token
     */
    public function testFetchUserForConfirmationWithHexId($token)
    {
        $user = $this->createMock(Auth\User::class);
        
        $this->auth->method('getConfirmationSecret')->willReturn('very secret');
        $this->auth->expects($this->once())->method('fetchUserById')->with('585c7f9a22a9037a1c8b4567')
            ->willReturn($user);
        
        $result = $this->auth->fetchUserForConfirmation($token, 'foo bar');
        
        $this->assertSame($user, $result);
    }
    
    /**
     * @return string
     */
    public function testGetConfirmationTokenUsingPassword()
    {
        $this->auth->method('getConfirmationSecret')->willReturn('very secret');
        
        $user = $this->createMock(Auth\User::class);
        $user->method('getId')->willReturn(123);
        $user->method('getHashedPassword')->willReturn('1234567890abcdef');
        
        $token = $this->auth->getConfirmationToken($user, 'foo bar', true);
        
        $this->assertInternalType('string', $token);
        $this->assertNotEmpty($token);
        
        return $token;
    }
    
    /**
     * @depends testGetConfirmationTokenUsingPassword
     * 
     * @param string $token
     */
    public function testFetchUserForConfirmationUsingPassword($token)
    {
        $user = $this->createMock(Auth\User::class);
        $user->expects($this->once())->method('getHashedPassword')->willReturn('1234567890abcdef');
        
        $this->auth->method('getConfirmationSecret')->willReturn('very secret');
        $this->auth->expects($this->once())->method('fetchUserById')->with(123)->willReturn($user);
        
        $result = $this->auth->fetchUserForConfirmation($token, 'foo bar', true);
        
        $this->assertSame($user, $result);
    }
    
    /**
     * @depends testGetConfirmationTokenUsingPassword
     * 
     * @param string $token
     */
    public function testFetchUserForConfirmationAfterChangedPassword($token)
    {
        $user = $this->createMock(Auth\User::class);
        $user->expects($this->once())->method('getHashedPassword')->willReturn('0000000000000000');
        
        $this->auth->method('getConfirmationSecret')->willReturn('very secret');
        $this->auth->expects($this->once())->method('fetchUserById')->with(123)->willReturn($user);
        
        $result = $this->auth->fetchUserForConfirmation($token, 'foo bar', true);
        
        $this->assertNull($result);
    }
}
