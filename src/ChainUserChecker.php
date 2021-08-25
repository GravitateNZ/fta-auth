<?php declare(strict_types=1);


namespace GravitateNZ\fta\auth\Security;


use Symfony\Component\Security\Core\Exception\AccountStatusException;
use Symfony\Component\Security\Core\User\UserCheckerInterface;
use Symfony\Component\Security\Core\User\UserInterface;

class ChainUserChecker implements UserCheckerInterface
{
    protected array $checkers;

    public function __construct(array $userCheckers)
    {
        $this->checkers = $userCheckers;
    }

    public function checkPreAuth(UserInterface $user)
    {
        /** @var UserCheckerInterface $checker */
        foreach ($this->checkers as $checker) {
            $checker->checkPreAuth($user);
        }
    }

    public function checkPostAuth(UserInterface $user)
    {
        /** @var UserCheckerInterface $checker */
        foreach ($this->checkers as $checker) {
            $checker->checkPostAuth($user);
        }
    }


}
