<?php declare(strict_types=1);

namespace GravitateNZ\fta\auth\Security\tests;

use PHPUnit\Framework\TestCase;
use GravitateNZ\fta\auth\Security\UserLockedUserChecker;


/** @covers \GravitateNZ\fta\auth\Security\UserLockedUserChecker */
class UserLockedUserCheckerTest extends TestCase
{

    use RequestStackTrait;

//    public function testPostAuthUserInterface()
//    {
//        $userMock = $this->createMock(\Symfony\Component\Security\Core\User\UserInterface::class);
//
//        $requestStack = $this->getRequestStack();
//        $requestStack->getCurrentRequest()->attributes->set('_firewall_context','security.firewall.map.context.test');
//
//        $uc = new UserLockedUserChecker($requestStack, 1, "PT1S");
//        $this->assertNull($uc->checkPostAuth($userMock));
//    }

    public function testPreAuthLocked()
    {
        $d = new \DateTime();
        $userMock = $this->createMock(\GravitateNZ\fta\auth\Security\LockableUserInterface::class);
        $userMock->expects($this->once())
                 ->method("isLocked")
                 ->willReturn(true)
        //         ->with(1, $d->sub(new DateInterval("PT1S")))
        ;

        $userMock->expects($this->never())->method("clearLoginAttempts");

        $this->expectException(
            \Symfony\Component\Security\Core\Exception\LockedException::class
        );

        $requestStack = $this->getRequestStack();
        $requestStack->getCurrentRequest()->attributes->set('_firewall_context','security.firewall.map.context.test');

        $uc = new UserLockedUserChecker($requestStack, 1, "PT1S");
        $uc->checkPreAuth($userMock);
    }

    public function testPostAuthUnlocked()
    {
        $userMock = $this->createMock(\GravitateNZ\fta\auth\Security\LockableUserInterface::class);
        $userMock->method("isLocked")->willReturn(false);
        $userMock->expects($this->once())->method("clearLoginAttempts");

        $requestStack = $this->getRequestStack();
        $requestStack->getCurrentRequest()->attributes->set('_firewall_context','security.firewall.map.context.test');

        $uc = new UserLockedUserChecker($requestStack,1, "PT1S");
        $uc->checkPostAuth($userMock);
    }
}
