# FWclean utility
see KB 4073671 WS16: NET: Unique logons result in registry bloat that causes servers hangs; firewall rules are not purged by User Profile deletion  
https://internal.support.services.microsoft.com/en-US/help/4073671
You can use *FWclean* utilility or Manually delete registry firewall rules from  `HKLM\System\CCS\Services\SharedAccess\Parameters\FirewallPolicy\RestrictedServices\Configurable\System`
