//! Vérification d'appartenance d'une IP à une whitelist (US-04).
//!
//! Les entrées acceptent des IP simples (`192.168.1.10`) ou des plages
//! CIDR (`10.0.0.0/24`), IPv4 et IPv6. Une entrée illisible est loggée
//! en WARN et ignorée : elle ne doit ni bloquer les autres entrées,
//! ni ouvrir l'accès par défaut.

use ipnet::IpNet;
use std::net::IpAddr;

/// `true` si `client_ip` correspond à au moins une entrée de `allowed`.
pub fn ip_allowed(client_ip: IpAddr, allowed: &[String]) -> bool {
    allowed.iter().any(|entry| {
        let entry = entry.trim();
        if let Ok(network) = entry.parse::<IpNet>() {
            network.contains(&client_ip)
        } else if let Ok(ip) = entry.parse::<IpAddr>() {
            ip == client_ip
        } else {
            tracing::warn!(entry, "Entrée allowed_ips invalide, ignorée");
            false
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    fn list(entries: &[&str]) -> Vec<String> {
        entries.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn ip_exacte_acceptee() {
        assert!(ip_allowed(ip("192.168.1.10"), &list(&["192.168.1.10"])));
    }

    #[test]
    fn ip_dans_un_cidr_acceptee() {
        let allowed = list(&["10.0.0.0/24"]);
        assert!(ip_allowed(ip("10.0.0.42"), &allowed));
        assert!(!ip_allowed(ip("10.0.1.42"), &allowed));
    }

    #[test]
    fn ip_hors_liste_refusee() {
        assert!(!ip_allowed(
            ip("8.8.8.8"),
            &list(&["192.168.1.10", "10.0.0.0/24"])
        ));
    }

    #[test]
    fn liste_vide_refuse_tout() {
        assert!(!ip_allowed(ip("192.168.1.10"), &[]));
    }

    #[test]
    fn entree_invalide_ignoree_sans_bloquer_les_suivantes() {
        let allowed = list(&["pas-une-ip", "999.999.0.0/8", "192.168.1.10"]);
        assert!(ip_allowed(ip("192.168.1.10"), &allowed));
        assert!(!ip_allowed(ip("8.8.8.8"), &allowed));
    }

    #[test]
    fn ipv6_supportee() {
        let allowed = list(&["2001:db8::/32", "::1"]);
        assert!(ip_allowed(ip("2001:db8::1"), &allowed));
        assert!(ip_allowed(ip("::1"), &allowed));
        assert!(!ip_allowed(ip("2001:db9::1"), &allowed));
    }

    #[test]
    fn espaces_toleres() {
        assert!(ip_allowed(ip("192.168.1.10"), &list(&[" 192.168.1.10 "])));
    }
}
