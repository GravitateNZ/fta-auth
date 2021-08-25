<?php declare(strict_types=1);


namespace GravitateNZ\fta\auth\Security;

use Symfony\Component\Security\Core\User\UserInterface;

interface LockableUserInterface extends UserInterface
{
    public function incrementFailedLogins(?\DateTimeInterface $time = null): void;
    public function clearLoginAttempts(): void;
    public function isLocked(int $limit, \DateTime $date): bool;
    public function getFailedLoginCount(): int;

}
