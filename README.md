## About

A basic dns resolver.

## Example

```rs
let address = dns_resolver::resolve("www.metafilter.com", RecordType::A).await?;
```

## References

Based on [Introducing "Implement DNS in a Weekend](https://jvns.ca/blog/2023/05/12/introducing-implement-dns-in-a-weekend/) by Julia Evans.