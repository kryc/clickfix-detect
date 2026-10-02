use std::time::Duration;

use crate::{NetworkRequest, NetworkResponse};

pub(crate) struct NetworkFetch {
    pub response: NetworkResponse,
    pub final_url: String,
    pub redirects: Vec<String>,
}

#[cfg(not(target_arch = "wasm32"))]
#[derive(Clone)]
struct PinnedResolver {
    addresses: Vec<std::net::SocketAddr>,
}

#[cfg(not(target_arch = "wasm32"))]
impl ureq::Resolver for PinnedResolver {
    fn resolve(&self, _netloc: &str) -> std::io::Result<Vec<std::net::SocketAddr>> {
        Ok(self.addresses.clone())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NetworkPolicy {
    pub enabled: bool,
    pub public_http_only: bool,
    pub timeout: Duration,
    pub max_redirects: usize,
    pub max_response_bytes: usize,
}

impl Default for NetworkPolicy {
    fn default() -> Self {
        Self {
            enabled: false,
            public_http_only: true,
            timeout: Duration::from_secs(10),
            max_redirects: 5,
            max_response_bytes: 4 * 1024 * 1024,
        }
    }
}

impl NetworkPolicy {
    #[must_use]
    pub fn public_http() -> Self {
        Self {
            enabled: true,
            ..Self::default()
        }
    }
}

#[cfg(not(target_arch = "wasm32"))]
pub(crate) fn send(
    policy: &NetworkPolicy,
    request: &NetworkRequest,
) -> Result<NetworkFetch, String> {
    use std::collections::BTreeMap;
    use std::io::Read;

    use url::Url;

    if !policy.enabled {
        return Err("network access is disabled".into());
    }
    let mut method = request.method.clone();
    let mut url = request.url.clone();
    let mut body = request.body.clone();
    let mut headers = request.headers.clone();
    let mut redirects = Vec::new();
    for redirect in 0..=policy.max_redirects {
        let addresses = resolve_and_validate_url(policy, &url)?;
        let agent = ureq::AgentBuilder::new()
            .redirects(0)
            .timeout_connect(policy.timeout)
            .timeout_read(policy.timeout)
            .timeout_write(policy.timeout)
            .try_proxy_from_env(false)
            .resolver(PinnedResolver { addresses })
            .build();
        let mut outgoing = agent.request(&method, &url);
        for (name, value) in &headers {
            outgoing = outgoing.set(name, value);
        }
        let result = if body.is_empty() {
            outgoing.call()
        } else {
            outgoing.send_bytes(&body)
        };
        let response = match result {
            Ok(response) | Err(ureq::Error::Status(_, response)) => response,
            Err(ureq::Error::Transport(error)) => return Err(error.to_string()),
        };
        if matches!(response.status(), 301 | 302 | 303 | 307 | 308) {
            if redirect == policy.max_redirects {
                return Err("network redirect limit reached".into());
            }
            let location = response
                .header("location")
                .ok_or_else(|| "redirect response omitted Location".to_owned())?;
            let next_url = Url::parse(&url)
                .and_then(|base| base.join(location))
                .map_err(|error| format!("invalid redirect URL: {error}"))?
                .to_string();
            if !same_origin(&url, &next_url)? {
                headers.retain(|name, _| {
                    !matches!(
                        name.to_ascii_lowercase().as_str(),
                        "authorization" | "cookie" | "proxy-authorization"
                    )
                });
            }
            url = next_url;
            redirects.push(url.clone());
            if response.status() == 303
                || (matches!(response.status(), 301 | 302) && method.eq_ignore_ascii_case("POST"))
            {
                method = "GET".into();
                body.clear();
            }
            continue;
        }
        let status = response.status();
        let headers = response
            .headers_names()
            .into_iter()
            .filter_map(|name| {
                response
                    .header(&name)
                    .map(|value| (name.to_ascii_lowercase(), value.to_owned()))
            })
            .collect::<BTreeMap<_, _>>();
        let mut bytes = Vec::new();
        response
            .into_reader()
            .take(policy.max_response_bytes.saturating_add(1) as u64)
            .read_to_end(&mut bytes)
            .map_err(|error| error.to_string())?;
        if bytes.len() > policy.max_response_bytes {
            return Err(format!(
                "network response exceeds {} bytes",
                policy.max_response_bytes
            ));
        }
        return Ok(NetworkFetch {
            response: NetworkResponse {
                status,
                headers,
                body: bytes,
            },
            final_url: url,
            redirects,
        });
    }
    Err("network redirect handling failed".into())
}

#[cfg(target_arch = "wasm32")]
pub(crate) fn send(
    _policy: &NetworkPolicy,
    _request: &NetworkRequest,
) -> Result<NetworkFetch, String> {
    Err("real network access is unavailable in the browser build".into())
}

#[cfg(not(target_arch = "wasm32"))]
fn same_origin(left: &str, right: &str) -> Result<bool, String> {
    use url::Url;

    let left = Url::parse(left).map_err(|error| format!("invalid redirect source URL: {error}"))?;
    let right =
        Url::parse(right).map_err(|error| format!("invalid redirect target URL: {error}"))?;
    Ok(left.scheme() == right.scheme()
        && left.host_str().map(str::to_ascii_lowercase)
            == right.host_str().map(str::to_ascii_lowercase)
        && left.port_or_known_default() == right.port_or_known_default())
}

#[cfg(not(target_arch = "wasm32"))]
fn resolve_and_validate_url(
    policy: &NetworkPolicy,
    value: &str,
) -> Result<Vec<std::net::SocketAddr>, String> {
    use std::net::ToSocketAddrs;

    use url::Url;

    let url = Url::parse(value).map_err(|error| format!("invalid URL: {error}"))?;
    if !matches!(url.scheme(), "http" | "https") {
        return Err(format!("network scheme {} is not allowed", url.scheme()));
    }
    if !url.username().is_empty() || url.password().is_some() {
        return Err("URLs containing credentials are not allowed".into());
    }
    let host = url
        .host_str()
        .ok_or_else(|| "network URL has no host".to_owned())?;
    let port = url
        .port_or_known_default()
        .ok_or_else(|| "network URL has no usable port".to_owned())?;
    let addresses = (host, port)
        .to_socket_addrs()
        .map_err(|error| format!("DNS resolution failed: {error}"))?
        .collect::<Vec<_>>();
    validate_resolved_addresses(policy, &addresses)?;
    Ok(addresses)
}

#[cfg(not(target_arch = "wasm32"))]
fn validate_resolved_addresses(
    policy: &NetworkPolicy,
    addresses: &[std::net::SocketAddr],
) -> Result<(), String> {
    if addresses.is_empty() {
        return Err("DNS resolution returned no addresses".into());
    }
    if policy.public_http_only && addresses.iter().any(|address| !is_public_ip(address.ip())) {
        return Err("network destination is not public".into());
    }
    Ok(())
}

#[cfg(not(target_arch = "wasm32"))]
fn is_public_ip(ip: std::net::IpAddr) -> bool {
    use std::net::IpAddr;

    match ip {
        IpAddr::V4(ip) => {
            !(ip.is_private()
                || ip.is_loopback()
                || ip.is_link_local()
                || ip.is_broadcast()
                || ip.is_documentation()
                || ip.is_multicast()
                || ip.is_unspecified()
                || ip.octets()[0] == 0
                || ip.octets()[0] >= 240
                || ip.octets()[0] == 100 && (64..=127).contains(&ip.octets()[1]))
        }
        IpAddr::V6(ip) => {
            let segments = ip.segments();
            !(ip.is_loopback()
                || ip.is_multicast()
                || ip.is_unspecified()
                || (segments[0] & 0xfe00) == 0xfc00
                || (segments[0] & 0xffc0) == 0xfe80
                || (segments[0] == 0x2001 && segments[1] == 0x0db8)
                || ip
                    .to_ipv4_mapped()
                    .is_some_and(|mapped| !is_public_ip(IpAddr::V4(mapped))))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(not(target_arch = "wasm32"))]
    #[test]
    fn rejects_private_and_metadata_destinations() {
        for address in [
            "127.0.0.1",
            "10.0.0.1",
            "169.254.169.254",
            "192.168.1.1",
            "::1",
            "fe80::1",
            "fc00::1",
        ] {
            assert!(!is_public_ip(address.parse().unwrap()), "{address}");
        }
        assert!(is_public_ip("1.1.1.1".parse().unwrap()));
        assert!(is_public_ip("2606:4700:4700::1111".parse().unwrap()));
    }

    #[test]
    fn network_is_disabled_by_default() {
        assert!(!NetworkPolicy::default().enabled);
        assert!(NetworkPolicy::public_http().enabled);
    }

    #[cfg(not(target_arch = "wasm32"))]
    #[test]
    fn redirect_origin_comparison_includes_scheme_host_and_port() {
        assert!(same_origin(
            "https://example.invalid/start",
            "https://example.invalid/next"
        )
        .unwrap());
        assert!(!same_origin(
            "https://example.invalid/start",
            "https://other.invalid/next"
        )
        .unwrap());
        assert!(!same_origin(
            "https://example.invalid/start",
            "http://example.invalid/next"
        )
        .unwrap());
        assert!(same_origin("https://example.org/start", "https://xn--example-.org/next").is_err());
    }

    #[cfg(not(target_arch = "wasm32"))]
    #[test]
    fn validated_address_set_is_the_connection_allowlist() {
        let policy = NetworkPolicy::public_http();
        assert!(validate_resolved_addresses(&policy, &["1.1.1.1:443".parse().unwrap()]).is_ok());
        assert!(validate_resolved_addresses(
            &policy,
            &[
                "1.1.1.1:443".parse().unwrap(),
                "127.0.0.1:443".parse().unwrap()
            ]
        )
        .is_err());
    }
}
