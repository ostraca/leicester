# leicester
A traffic transparently redirect bindings for Rust.

# Overview
Rust bindings for tcp traffic transparently redirect, it provides a few major features:
* tcp ingress/egress transparently redirect to local port
* avoid the use of kernel connntrack

Limitations:
* kernel version >= 3.16
* IPv4 available only

# Example
A basic implementation example.

```toml
[dependencies]
leicester = { version = "0.0.1" }
```

Then, on your main.rs:
```rust,no_run
use leicester::{self, Config};

fn main() {
    let conf = &Config {
        eth_name: "ens33",
        proxy_port: "17000",
        redirect_port: "9080",
        route_table: "133",
        ignore_mask: 68,
        mask: 1,
    };

    let hijacker = leicester::Builder::new(conf);
    if hijacker.deploy().is_ok() {
        println!("traffic redirect rules deploy successeful!");
    } else {
        println!("traffic redirect rules deploy failed!");
    }
}

```

More examples can be found [here](https://github.com/ostraca/leicester/tree/main/examples).

# Supported Rust Versions
This library is verified to work in rustc 1.51.0 (nightly), and the support of other versions needs more testing.

# License
This project is licensed under the [Apache License 2.0](https://github.com/ostraca/leicester/blob/main/LICENSE).
