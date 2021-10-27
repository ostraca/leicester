use rust_iptables::iptables::{self, IPTables};
use std::error::Error;
use std::process::Command;

static DIVERT_CHAIN: &str = "DIVERT";
static REDIRECT_CHAIN: &str = "TPROXY_REDIRECT";
static INBOUND_CHAIN: &str = "INBOUND";
static OUTBOUND_CHAIN: &str = "OUTBOUND";
static TPROXY_PREROUTING_CHAIN: &str = "TPROXY_PREROUTING";
static TPROXY_INPUT_CHAIN: &str = "TPROXY_INPUT";
static TPROXY_OUTPUT_CHAIN: &str = "TPROXY_OUTPUT";

static MANGLE_TABLE: &str = "mangle";
static PREROUTING_CHAIN: &str = "PREROUTING";
static OUTPUT_CHAIN: &str = "OUTPUT";
static INPUT_CHAIN: &str = "INPUT";

pub struct Builder();

pub struct Config {
    pub eth_name: &'static str,

    pub proxy_port: &'static str,
    pub redirect_port: &'static str,
    pub route_table: &'static str,

    pub ignore_mask: isize,
    pub mask: isize,
}

pub struct Hijacker {
    pub ipt: IPTables,
    pub conf: Config,
}

impl Builder {
    pub fn new(conf: &Config) -> Hijacker {
        let ipt = iptables::new().unwrap();

        let cfg = Config {
            eth_name: conf.eth_name.clone(),
            proxy_port: conf.proxy_port.clone(),
            redirect_port: conf.redirect_port.clone(),
            route_table: conf.route_table.clone(),
            ignore_mask: conf.ignore_mask,
            mask: conf.mask,
        };

        Hijacker {
            ipt: ipt,
            conf: cfg,
        }
    }
}

impl Hijacker {
    pub fn deploy(&self) -> Result<(), Box<dyn Error>> {
        self.proc_init()?;

        self.route_init()?;

        self.chain_init()?;

        self.prerouting_init()?;

        self.input_init()?;

        self.output_init()?;

        self.divert_process()?;

        self.redirect_process()?;

        self.inbound_process()?;

        self.outbound_process()?;

        self.tproxy_prerouting_process()?;

        self.tproxy_output_process()?;

        self.tproxy_input_process()?;

        Ok(())
    }

    pub fn destroy(&self) -> Result<(), Box<dyn Error>> {
        self.ipt.flush_table(MANGLE_TABLE)?;
        self.ipt.delete_table(MANGLE_TABLE)?;

        let mut cmd = format!(
            "ip route del local 0.0.0.0/0 dev lo table {}",
            self.conf.route_table
        );
        Command::new("sh").arg("-c").arg(cmd).output()?;

        cmd = format!(
            "ip rule del fwmark {} lookup {}",
            self.conf.mask, self.conf.route_table
        );
        Command::new("sh").arg("-c").arg(cmd).output()?;

        Command::new("sh")
            .arg("-c")
            .arg("echo 0 > /proc/sys/net/ipv4/fwmark_reflect")
            .output()?;
        Command::new("sh")
            .arg("-c")
            .arg("echo 0 > /proc/sys/net/ipv4/tcp_fwmark_accept")
            .output()?;

        Ok(())
    }
}

impl Hijacker {
    fn proc_init(&self) -> Result<(), Box<dyn Error>> {
        Command::new("sh")
            .arg("-c")
            .arg("echo 1 > /proc/sys/net/ipv4/fwmark_reflect")
            .output()?;
        Command::new("sh")
            .arg("-c")
            .arg("echo 1 > /proc/sys/net/ipv4/tcp_fwmark_accept")
            .output()?;

        Ok(())
    }

    fn route_init(&self) -> Result<(), Box<dyn Error>> {
        let cmd = format!(
            "ip rule add fwmark {} lookup {}",
            self.conf.mask, self.conf.route_table
        );
        Command::new("sh").arg("-c").arg(cmd).output()?;

        let cmd = format!(
            "ip route add local 0.0.0.0/0 dev lo table {}",
            self.conf.route_table
        );
        Command::new("sh").arg("-c").arg(cmd).output()?;

        Ok(())
    }

    fn chain_init(&self) -> Result<(), Box<dyn Error>> {
        self.ipt.new_chain(MANGLE_TABLE, DIVERT_CHAIN)?;
        self.ipt.new_chain(MANGLE_TABLE, REDIRECT_CHAIN)?;
        self.ipt.new_chain(MANGLE_TABLE, INBOUND_CHAIN)?;
        self.ipt.new_chain(MANGLE_TABLE, OUTBOUND_CHAIN)?;
        self.ipt.new_chain(MANGLE_TABLE, TPROXY_PREROUTING_CHAIN)?;
        self.ipt.new_chain(MANGLE_TABLE, TPROXY_INPUT_CHAIN)?;
        self.ipt.new_chain(MANGLE_TABLE, TPROXY_OUTPUT_CHAIN)?;

        Ok(())
    }

    fn prerouting_init(&self) -> Result<(), Box<dyn Error>> {
        let action = format!("-j {}", TPROXY_PREROUTING_CHAIN);
        self.ipt.append(MANGLE_TABLE, PREROUTING_CHAIN, &action)?;

        Ok(())
    }

    fn input_init(&self) -> Result<(), Box<dyn Error>> {
        let action = format!("-j {}", TPROXY_INPUT_CHAIN);
        self.ipt.append(MANGLE_TABLE, INPUT_CHAIN, &action)?;

        Ok(())
    }

    fn output_init(&self) -> Result<(), Box<dyn Error>> {
        let action = format!("-j {}", TPROXY_OUTPUT_CHAIN);
        self.ipt.append(MANGLE_TABLE, OUTPUT_CHAIN, &action)?;

        Ok(())
    }

    fn divert_process(&self) -> Result<(), Box<dyn Error>> {
        let mut action = format!("-j MARK --set-xmark {}", self.conf.mask);
        self.ipt.append(MANGLE_TABLE, DIVERT_CHAIN, &action)?;

        action = format!("-j ACCEPT");
        self.ipt.append(MANGLE_TABLE, DIVERT_CHAIN, &action)?;

        Ok(())
    }

    fn redirect_process(&self) -> Result<(), Box<dyn Error>> {
        let action = format!(
            "-p tcp -j TPROXY --on-port {} --on-ip 127.0.0.1 --tproxy-mark {}",
            self.conf.proxy_port, self.conf.mask
        );
        self.ipt.append(MANGLE_TABLE, REDIRECT_CHAIN, &action)?;

        Ok(())
    }

    fn inbound_process(&self) -> Result<(), Box<dyn Error>> {
        let action = format!(
            "-p tcp -m tcp --dport {} -j {}",
            self.conf.redirect_port, REDIRECT_CHAIN
        );
        self.ipt.append(MANGLE_TABLE, INBOUND_CHAIN, &action)?;

        Ok(())
    }

    fn outbound_process(&self) -> Result<(), Box<dyn Error>> {
        let mut action = format!("-m mark ! --mark {} -j RETURN", self.conf.mask);
        self.ipt.append(MANGLE_TABLE, OUTBOUND_CHAIN, &action)?;

        action = format!(
            "-p tcp -m tcp --dport {} -j {}",
            self.conf.redirect_port, REDIRECT_CHAIN
        );
        self.ipt.append(MANGLE_TABLE, OUTBOUND_CHAIN, &action)?;

        Ok(())
    }

    fn tproxy_prerouting_process(&self) -> Result<(), Box<dyn Error>> {
        let mut action = format!("! -d 127.0.0.0/8 -i lo -j {}", OUTBOUND_CHAIN);
        self.ipt
            .append(MANGLE_TABLE, TPROXY_PREROUTING_CHAIN, &action)?;

        action = format!(
            "! -d 127.0.0.0/8 -i {} -j {}",
            self.conf.eth_name, INBOUND_CHAIN
        );
        self.ipt
            .append(MANGLE_TABLE, TPROXY_PREROUTING_CHAIN, &action)?;

        Ok(())
    }

    fn tproxy_output_process(&self) -> Result<(), Box<dyn Error>> {
        let mut action = format!(
            "-p tcp -m tcp --sport {} --tcp-flags SYN,ACK,FIN,RST,URG,PSH SYN,ACK -j MARK --set-xmark {}", 
            self.conf.redirect_port, self.conf.ignore_mask
        );
        self.ipt
            .append(MANGLE_TABLE, TPROXY_OUTPUT_CHAIN, &action)?;

        action = format!("-o lo -j RETURN");
        self.ipt
            .append(MANGLE_TABLE, TPROXY_OUTPUT_CHAIN, &action)?;

        action = format!("-m mark --mark {} -j RETURN", self.conf.ignore_mask);
        self.ipt
            .append(MANGLE_TABLE, TPROXY_OUTPUT_CHAIN, &action)?;

        action = format!(
            "-p tcp -m tcp --dport {} -j {}",
            self.conf.redirect_port, DIVERT_CHAIN
        );
        self.ipt
            .append(MANGLE_TABLE, TPROXY_OUTPUT_CHAIN, &action)?;

        Ok(())
    }

    fn tproxy_input_process(&self) -> Result<(), Box<dyn Error>> {
        let mut action = format!(
            "-i {} -p tcp -m tcp --dport {} --tcp-flags SYN,ACK,FIN,RST,URG,PSH SYN -j MARK --set-xmark {}", 
            self.conf.eth_name, self.conf.redirect_port, self.conf.ignore_mask
        );
        self.ipt.append(MANGLE_TABLE, TPROXY_INPUT_CHAIN, &action)?;

        action = format!(
            "-i {} -p tcp -m tcp --sport {} -j MARK --set-xmark {}",
            self.conf.eth_name, self.conf.redirect_port, self.conf.ignore_mask
        );
        self.ipt.append(MANGLE_TABLE, TPROXY_INPUT_CHAIN, &action)?;

        Ok(())
    }
}
