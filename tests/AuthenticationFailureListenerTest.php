<?php declare(strict_types=1);

namespace GravitateNZ\fta\auth\Security\tests;

use Symfony\Component\Security\Core\Event\AuthenticationFailureEvent;

/**
 * @covers \GravitateNZ\fta\auth\Security\AuthenticationFailureLockoutListener
 */
class AuthenticationFailureListenerTest extends \PHPUnit\Framework\TestCase
{
    use RequestStackTrait;

    public function testListener()
    {
        $user = $this->createMock(\GravitateNZ\fta\auth\Security\LockableUserInterface::class);
        $user->expects($this->once())
             ->method('incrementFailedLogins')
             ->with(
                $this->isInstanceOf(\DateTimeInterface::class)
            );

        $userProvider = $this->createMock(\Symfony\Component\Security\Core\User\UserProviderInterface::class);
        $userProvider->expects($this->once())
                     ->method('loadUserByUsername')
                     ->with('name')
                     ->willReturn($user);

        $token = $this->createMock(
            \Symfony\Component\Security\Core\Authentication\Token\TokenInterface::class
        );

        $token->expects($this->once())
              ->method('getUsername')
              ->willReturn('name');

        $event = new AuthenticationFailureEvent(
            $token,
            new \Symfony\Component\Security\Core\Exception\AuthenticationException()
        );

        $requestStack = $this->getRequestStack();

        $l = new \GravitateNZ\fta\auth\Security\AuthenticationFailureLockoutListener(
            $userProvider,
            $requestStack,
            'test',
            0
        );


        $l->lockoutHandler($event);
        [$count,$failCount]  = $requestStack->getSession()->get('name_test_logincount');
        $this->assertGreaterThan($failCount, $count);
        $this->assertEquals(1, $count);

    }

    public function testListenerWrongUserInterface()
    {
        $user = $this->createMock(\Symfony\Component\Security\Core\User\UserInterface::class);

        $userProvider = $this->createMock(\Symfony\Component\Security\Core\User\UserProviderInterface::class);
        $userProvider->expects($this->once())
                     ->method('loadUserByUsername')
                     ->with('name')
                     ->willReturn($user);

        $token = $this->createMock(
            \Symfony\Component\Security\Core\Authentication\Token\TokenInterface::class
        );
        $token->expects($this->once())->method('getUsername')->willReturn('name');
        $event = new AuthenticationFailureEvent(
            $token,
            new \Symfony\Component\Security\Core\Exception\AuthenticationException()
        );

        $requestStack = $this->getRequestStack();

        $this->expectException(\Symfony\Component\Security\Core\Exception\UnsupportedUserException::class);

        $l = new \GravitateNZ\fta\auth\Security\AuthenticationFailureLockoutListener(
            $userProvider,
            $requestStack,
            'test',
            0
        );

        $l->lockoutHandler($event);

    }

    public function testUserDoesNotExist()
    {

        $userProvider = $this->createMock(\Symfony\Component\Security\Core\User\UserProviderInterface::class);
        $userProvider->expects($this->once())
                     ->method('loadUserByUsername')
                     ->with('name')
                     ->willReturn(null);

        $token = $this->createMock(
            \Symfony\Component\Security\Core\Authentication\Token\TokenInterface::class
        );
        $token->expects($this->once())->method('getUsername')->willReturn('name');
        $event = new AuthenticationFailureEvent(
            $token,
            new \Symfony\Component\Security\Core\Exception\AuthenticationException()
        );

        $requestStack = $this->getRequestStack();

        $l = new \GravitateNZ\fta\auth\Security\AuthenticationFailureLockoutListener(
            $userProvider,
            $requestStack,
            'test',
            0
        );

        $l->lockoutHandler($event);

        [$count,$failCount]  = $requestStack->getSession()->get('name_test_logincount');
        $this->assertGreaterThan($failCount, $count);
        $this->assertEquals(1, $count);
    }
    
}