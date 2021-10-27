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
