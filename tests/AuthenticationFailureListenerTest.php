<?php declare(strict_types=1);

use Symfony\Component\Security\Core\Event\AuthenticationFailureEvent;

/**
 * @covers \GravitateNZ\fta\auth\Security\AuthenticationFailureLockoutListener
 */
class AuthenticationFailureListenerTest extends \PHPUnit\Framework\TestCase
{

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

        $firewallConfig = new \Symfony\Bundle\SecurityBundle\Security\FirewallConfig("test", "test");
        $firewallMap = $this->createMock(\Symfony\Bundle\SecurityBundle\Security\FirewallMap::class);
        $firewallMap->method('getFirewallConfig')->willReturn($firewallConfig);

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

        $requestStack = new \Symfony\Component\HttpFoundation\RequestStack();
        $requestStack->push(new \Symfony\Component\HttpFoundation\Request());

        $l = new \GravitateNZ\fta\auth\Security\AuthenticationFailureLockoutListener(
            'test',
            $firewallMap,
            $userProvider,
            $requestStack
        );


        $l->lockoutHandler($event);
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

        $firewallConfig = new \Symfony\Bundle\SecurityBundle\Security\FirewallConfig("test", "test");
        $firewallMap = $this->createMock(\Symfony\Bundle\SecurityBundle\Security\FirewallMap::class);
        $firewallMap->method('getFirewallConfig')->willReturn($firewallConfig);

        $requestStack = new \Symfony\Component\HttpFoundation\RequestStack();
        $requestStack->push(new \Symfony\Component\HttpFoundation\Request());
        
        $this->expectException(\Symfony\Component\Security\Core\Exception\UnsupportedUserException::class);

        $l = new \GravitateNZ\fta\auth\Security\AuthenticationFailureLockoutListener(
            'test',
            $firewallMap,
            $userProvider,
            $requestStack
        );

        $l->lockoutHandler($event);

    }

}