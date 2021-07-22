# no proxy

This crate is a simple `NO_PROXY` parser and evaluator. It follows [this article from Gitlab](https://about.gitlab.com/blog/2021/01/27/we-need-to-talk-no-proxy/)
on how to properly implement it.

## Usage

```rust
use no_proxy::NoProxy;

let no_proxy = NoProxy::from(".foo.bar,bar.baz,10.42.1.1/24,::1,10.124.7.8,2001::/17");
if no_proxy.matches("bar.baz") {
    println!("matches 'bar.baz'");
}
```

