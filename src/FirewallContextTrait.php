<?php declare(strict_types=1);


namespace GravitateNZ\fta\auth\Security;


trait FirewallContextTrait
{

    public function getFirewallNameFromContext(): string
    {
        $context = $this->getFirewallContext();
        return str_replace('security.firewall.map.context.', '', $context);
    }

    public function getFirewallContext(): string
    {
        return $this->requestStack->getCurrentRequest()->attributes->get('_firewall_context','');
    }

}