<?php declare(strict_types=1);


use PHPUnit\Framework\TestCase;
use GravitateNZ\fta\auth\Security\UserLockedUserChecker;


/** @covers \GravitateNZ\fta\auth\Security\UserLockedUserChecker */
class UserLockedUserCheckerTest extends TestCase
{


    public function testPostAuthUserInterface()
    {
        $userMock = $this->createMock(\Symfony\Component\Security\Core\User\UserInterface::class);
        $uc = new UserLockedUserChecker(1, "PT1S");
        $this->assertNull($uc->checkPostAuth($userMock));
    }

    public function testPostAuthLocked()
    {
        $d = new DateTime();
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

        $uc = new UserLockedUserChecker(1, "PT1S");
        $uc->checkPostAuth($userMock);
    }

    public function testPostAuthUnlocked()
    {
        $userMock = $this->createMock(\GravitateNZ\fta\auth\Security\LockableUserInterface::class);
        $userMock->method("isLocked")->willReturn(false);
        $userMock->expects($this->once())->method("clearLoginAttempts");

        $uc = new UserLockedUserChecker(1, "PT1S");
        $uc->checkPostAuth($userMock);
    }
}
