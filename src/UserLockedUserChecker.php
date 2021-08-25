<?php declare(strict_types=1);


namespace GravitateNZ\fta\auth\Security;

use Symfony\Component\Security\Core\Exception\LockedException;
use Symfony\Component\Security\Core\User\UserInterface;
use \Symfony\Component\Security\Core\User\UserCheckerInterface;

class UserLockedUserChecker implements UserCheckerInterface
{
    protected int $lockoutCount;
    protected string $interval;

    public function __construct(int $lockoutCount, string $interval)
    {
        $this->lockoutCount = $lockoutCount;
        $this->interval = $interval;
    }

    public function checkPostAuth(UserInterface $user)
    {
        if (!$user instanceof LockableUserInterface) {
            return;
        }

        $i = new \DateInterval($this->interval);
        $dt = (new \DateTime())->sub($i);
        if ($user->isLocked($this->lockoutCount, $dt)) {
            $e =  new LockedException("This account has been locked please try again in {$i->format("%i")} minutes");
            $e->setUser($user);
            throw $e;
        }

        $user->clearLoginAttempts();
    }

    /** @codeCoverageIgnore  */
    public function checkPreAuth(UserInterface $user)
    {}
}
