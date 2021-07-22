use cidr_utils::cidr::IpCidr;
use std::collections::{hash_set::IntoIter, HashSet};
use std::net::IpAddr;
use std::str::FromStr;

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub enum NoProxyItem {
    Wildcard,
    IpCidr(String, IpCidr),
    WithDot(String, bool, bool),
    Plain(String),
}

impl From<String> for NoProxyItem {
    fn from(value: String) -> Self {
        if value == "*" {
            Self::Wildcard
        } else if let Ok(ip_cidr) = IpCidr::from_str(&value) {
            Self::IpCidr(value, ip_cidr)
        } else if value.starts_with('.') || value.ends_with('.') {
            let start = value.starts_with('.');
            let end = value.ends_with('.');
            Self::WithDot(value, start, end)
        } else {
            Self::Plain(value)
        }
    }
}

fn parse_host(input: &str) -> &str {
    // According to RFC3986, raw IPv6 hosts will be wrapped in []. So we need to strip those off
    // the end in order to parse correctly
    if input.starts_with('[') {
        let x: &[_] = &['[', ']'];
        input.trim_matches(x)
    } else {
        input
    }
}

impl NoProxyItem {
    pub fn matches(&self, value: &str) -> bool {
        let value = parse_host(value);
        match self {
            Self::Wildcard => true,
            Self::IpCidr(source, ip_cidr) => {
                if value == source {
                    true
                } else if let Ok(ip_value) = IpAddr::from_str(value) {
                    ip_cidr.contains(ip_value)
                } else {
                    false
                }
            }
            Self::WithDot(source, start, end) => {
                if *start && *end {
                    value.contains(source)
                } else if *start {
                    value.ends_with(source)
                } else if *end {
                    value.starts_with(source)
                } else {
                    source == value
                }
            }
            Self::Plain(source) => source == value,
        }
    }
}

#[derive(Clone, Debug, Default)]
pub struct NoProxy {
    content: HashSet<NoProxyItem>,
    has_wildcard: bool,
}

impl<T: AsRef<str>> From<T> for NoProxy {
    fn from(value: T) -> Self {
        let content: HashSet<_> = value
            .as_ref()
            .split(',')
            .map(|item| NoProxyItem::from(item.trim().to_string()))
            .collect();
        let has_wildcard = content.contains(&NoProxyItem::Wildcard);
        Self {
            content,
            has_wildcard,
        }
    }
}

impl IntoIterator for NoProxy {
    type Item = NoProxyItem;
    type IntoIter = IntoIter<NoProxyItem>;

    fn into_iter(self) -> Self::IntoIter {
        self.content.into_iter()
    }
}

impl Extend<NoProxyItem> for NoProxy {
    fn extend<T: IntoIterator<Item = NoProxyItem>>(&mut self, iter: T) {
        self.content.extend(iter);
        self.has_wildcard = self.content.contains(&NoProxyItem::Wildcard);
    }
}

impl NoProxy {
    pub fn matches(&self, input: &str) -> bool {
        if self.has_wildcard {
            return true;
        }
        for item in self.content.iter() {
            if item.matches(input) {
                return true;
            }
        }
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn should_match(pattern: &str, value: &str) {
        let no_proxy = NoProxy::from(pattern);
        assert!(
            no_proxy.matches(value),
            "{} should match {}",
            pattern,
            value
        );
    }

    fn shouldnt_match(pattern: &str, value: &str) {
        let no_proxy = NoProxy::from(pattern);
        assert!(
            !no_proxy.matches(value),
            "{} should not match {}",
            pattern,
            value
        );
    }

    #[test]
    fn wildcard() {
        should_match("*", "www.wikipedia.org");
        should_match("*", "192.168.0.1");
        should_match("localhost , *", "wikipedia.org");
    }

    #[test]
    fn cidr() {
        should_match("21.19.35.40/24", "21.19.35.4");
        shouldnt_match("21.19.35.40/24", "127.0.0.1");
    }

    #[test]
    fn leading_dot() {
        should_match(".wikipedia.org", "fr.wikipedia.org");
        shouldnt_match(".wikipedia.org", "fr.wikipedia.co.uk");
        shouldnt_match(".wikipedia.org", "wikipedia.org");
        shouldnt_match(".wikipedia.org", "google.com");
        should_match(".168.0.1", "192.168.0.1");
        shouldnt_match(".168.0.1", "192.169.0.1");
    }

    #[test]
    fn trailing_dot() {
        should_match("fr.wikipedia.", "fr.wikipedia.com");
        should_match("fr.wikipedia.", "fr.wikipedia.org");
        should_match("fr.wikipedia.", "fr.wikipedia.somewhere.dangerous");
        shouldnt_match("fr.wikipedia.", "www.google.com");
        should_match("192.168.0.", "192.168.0.1");
        shouldnt_match("192.168.0.", "192.169.0.1");
    }

    #[test]
    fn combination() {
        let pattern = "127.0.0.1,localhost,.local,169.254.169.254,fileshare.company.com";
        should_match(pattern, "localhost");
        should_match(pattern, "somewhere.local");
    }

    #[test]
    fn from_reqwest() {
        let pattern = ".foo.bar,bar.baz,10.42.1.1/24,::1,10.124.7.8,2001::/17";
        shouldnt_match(pattern, "hyper.rs");
        shouldnt_match(pattern, "foo.bar.baz");
        shouldnt_match(pattern, "10.43.1.1");
        shouldnt_match(pattern, "10.124.7.7");
        shouldnt_match(pattern, "[ffff:db8:a0b:12f0::1]");
        shouldnt_match(pattern, "[2005:db8:a0b:12f0::1]");

        should_match(pattern, "hello.foo.bar");
        should_match(pattern, "bar.baz");
        should_match(pattern, "10.42.1.100");
        should_match(pattern, "[::1]");
        should_match(pattern, "[2001:db8:a0b:12f0::1]");
        should_match(pattern, "10.124.7.8");
    }
}
