<?php declare(strict_types=1);


namespace GravitateNZ\fta\auth\Security\tests;


use Symfony\Component\Security\Core\Event\AuthenticationFailureEvent;

/**
 * @covers \GravitateNZ\fta\auth\Security\AuthenticationRecaptchaListener
 * @Covers \GravitateNZ\fta\auth\Security\FirewallContextTraits
 */
class AuthenticationRecaptchaListenerTest extends \PHPUnit\Framework\TestCase
{
    use RequestStackTrait;

    public function testFirewallNameMatch(): void
    {
        $token = $this->createMock(
            \Symfony\Component\Security\Core\Authentication\Token\TokenInterface::class
        );
        $event = new AuthenticationFailureEvent(
            $token,
            new \Symfony\Component\Security\Core\Exception\AuthenticationException()
        );

        $requestStack = $this->getRequestStack();

        $l = new \GravitateNZ\fta\auth\Security\AuthenticationRecaptchaListener(
            $requestStack,
            'testX',
            0
        );

        $l->recaptchaHandler($event);

        $this->assertTrue(false === $requestStack->getSession()->has('test_login_attempts'));
        $this->assertTrue(false === $requestStack->getSession()->has('test_login_annoy'));
    }

    public function testIncrement(): void
    {

        $token = $this->createMock(
            \Symfony\Component\Security\Core\Authentication\Token\TokenInterface::class
        );
        $event = new AuthenticationFailureEvent(
            $token,
            new \Symfony\Component\Security\Core\Exception\AuthenticationException()
        );

        $requestStack = $this->getRequestStack();

        $l = new \GravitateNZ\fta\auth\Security\AuthenticationRecaptchaListener(
            $requestStack,
            'test',
            2
        );

        $l->recaptchaHandler($event);
        $this->assertEquals(1, $requestStack->getSession()->get('test_login_attempts', 0));
        $this->assertNull($requestStack->getSession()->get('test_login_annoy'));
    }

    public function testIncrementAndAnnoy(): void
    {

        $token = $this->createMock(
            \Symfony\Component\Security\Core\Authentication\Token\TokenInterface::class
        );
        $event = new AuthenticationFailureEvent(
            $token,
            new \Symfony\Component\Security\Core\Exception\AuthenticationException()
        );

        $requestStack = $this->getRequestStack();

        $l = new \GravitateNZ\fta\auth\Security\AuthenticationRecaptchaListener(
            $requestStack,
            'test',
            1
        );

        $l->recaptchaHandler($event);
        $this->assertEquals(1, $requestStack->getSession()->get('test_login_attempts', 0));
        $this->assertTrue($requestStack->getSession()->get('test_login_annoy') === true);
    }
}