//! OS-level route and NAT management for VPN operation.
//!
//! All operations require **root** or **CAP_NET_ADMIN** on Linux.
//! Non-Linux platforms return [`TunError::Unsupported`].

use super::TunError;

/// Manages OS-level routing tables and NAT/iptables rules.
pub struct RouteManager;

#[cfg(target_os = "linux")]
impl RouteManager {
    /// Add a host route for the VPN server through the original gateway,
    /// preventing the tunnel from routing its own transport traffic.
    pub fn add_server_route(server_ip: &str, gateway: &str) -> Result<(), TunError> {
        let dest = format!("{server_ip}/32");
        // Try to add; if it already exists, silently succeed
        let output = std::process::Command::new("ip")
            .args(["route", "add", &dest, "via", gateway])
            .output()
            .map_err(|e| TunError::Route(format!("ip: {e}")))?;
        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            if stderr.contains("File exists") {
                return Ok(()); // Route already present — OK
            }
            return Err(TunError::Route(format!(
                "ip route add {dest} via {gateway}: {}",
                stderr.trim()
            )));
        }
        Ok(())
    }

    /// Replace the default route to send all traffic through the TUN device.
    /// Deletes all existing default routes first to avoid conflicts with DHCP/NetworkManager.
    pub fn set_default_route(tun_name: &str) -> Result<(), TunError> {
        // Delete ALL default routes (DHCP/NetworkManager may add multiple)
        loop {
            if run_cmd("ip", &["route", "del", "default"]).is_err() {
                break;
            }
        }
        run_cmd("ip", &["route", "add", "default", "dev", tun_name, "scope", "global"])
    }

    /// Restore the original default route through a gateway.
    pub fn restore_default_route(gateway: &str) -> Result<(), TunError> {
        let _ = run_cmd("ip", &["route", "del", "default"]);
        run_cmd("ip", &["route", "add", "default", "via", gateway])
    }

    /// Remove the host route added by [`add_server_route`].
    pub fn remove_server_route(server_ip: &str) -> Result<(), TunError> {
        run_cmd("ip", &["route", "del", &format!("{server_ip}/32")])
    }

    /// Enable kernel IPv4 forwarding (`/proc/sys/net/ipv4/ip_forward`).
    pub fn enable_ip_forwarding() -> Result<(), TunError> {
        std::fs::write("/proc/sys/net/ipv4/ip_forward", "1")
            .map_err(|e| TunError::Route(format!("ip_forward: {e}")))
    }

    /// Add an iptables MASQUERADE NAT rule for the external interface.
    pub fn add_nat_rule(external_iface: &str) -> Result<(), TunError> {
        run_cmd(
            "iptables",
            &[
                "-t", "nat", "-A", "POSTROUTING", "-o", external_iface, "-j", "MASQUERADE",
            ],
        )
    }

    /// Add iptables FORWARD rules to allow traffic between TUN and external interfaces.
    /// Uses `-I FORWARD 1` to insert before Docker/other rules that may DROP traffic.
    pub fn add_forward_rules(tun_name: &str, external_iface: &str) -> Result<(), TunError> {
        // Allow forwarding from TUN to external interface (insert at top)
        run_cmd(
            "iptables",
            &["-I", "FORWARD", "1", "-i", tun_name, "-o", external_iface, "-j", "ACCEPT"],
        )?;
        // Allow established/related return traffic (insert at position 2, after the above)
        run_cmd(
            "iptables",
            &[
                "-I", "FORWARD", "2", "-i", external_iface, "-o", tun_name,
                "-m", "state", "--state", "ESTABLISHED,RELATED", "-j", "ACCEPT",
            ],
        )?;
        Ok(())
    }

    /// Remove the FORWARD rules (best-effort, ignores errors).
    pub fn remove_forward_rules(tun_name: &str, external_iface: &str) -> Result<(), TunError> {
        let _ = run_cmd(
            "iptables",
            &["-D", "FORWARD", "-i", tun_name, "-o", external_iface, "-j", "ACCEPT"],
        );
        let _ = run_cmd(
            "iptables",
            &[
                "-D", "FORWARD", "-i", external_iface, "-o", tun_name,
                "-m", "state", "--state", "ESTABLISHED,RELATED", "-j", "ACCEPT",
            ],
        );
        Ok(())
    }

    /// Remove the NAT rule (best-effort, ignores errors).
    pub fn remove_nat_rule(external_iface: &str) -> Result<(), TunError> {
        let _ = run_cmd(
            "iptables",
            &[
                "-t", "nat", "-D", "POSTROUTING", "-o", external_iface, "-j", "MASQUERADE",
            ],
        );
        Ok(())
    }

    /// Detect the current default gateway IP from `ip route show default`.
    pub fn get_default_gateway() -> Result<String, TunError> {
        let output = std::process::Command::new("ip")
            .args(["route", "show", "default"])
            .output()
            .map_err(|e| TunError::Route(e.to_string()))?;

        let stdout = String::from_utf8_lossy(&output.stdout);
        // Parse: "default via X.X.X.X dev ..."
        stdout
            .split_whitespace()
            .skip_while(|&w| w != "via")
            .nth(1)
            .map(String::from)
            .ok_or_else(|| TunError::Route("no default gateway found".into()))
    }
}

#[cfg(target_os = "linux")]
fn run_cmd(program: &str, args: &[&str]) -> Result<(), TunError> {
    let output = std::process::Command::new(program)
        .args(args)
        .output()
        .map_err(|e| TunError::Route(format!("{program}: {e}")))?;
    if !output.status.success() {
        return Err(TunError::Route(format!(
            "{program} {}: {}",
            args.join(" "),
            String::from_utf8_lossy(&output.stderr).trim()
        )));
    }
    Ok(())
}

#[cfg(not(target_os = "linux"))]
impl RouteManager {
    pub fn add_server_route(_server_ip: &str, _gateway: &str) -> Result<(), TunError> {
        Err(TunError::Unsupported)
    }
    pub fn set_default_route(_tun_name: &str) -> Result<(), TunError> {
        Err(TunError::Unsupported)
    }
    pub fn restore_default_route(_gateway: &str) -> Result<(), TunError> {
        Err(TunError::Unsupported)
    }
    pub fn remove_server_route(_server_ip: &str) -> Result<(), TunError> {
        Err(TunError::Unsupported)
    }
    pub fn enable_ip_forwarding() -> Result<(), TunError> {
        Err(TunError::Unsupported)
    }
    pub fn add_nat_rule(_external_iface: &str) -> Result<(), TunError> {
        Err(TunError::Unsupported)
    }
    pub fn add_forward_rules(_tun_name: &str, _external_iface: &str) -> Result<(), TunError> {
        Err(TunError::Unsupported)
    }
    pub fn remove_forward_rules(_tun_name: &str, _external_iface: &str) -> Result<(), TunError> {
        Err(TunError::Unsupported)
    }
    pub fn remove_nat_rule(_external_iface: &str) -> Result<(), TunError> {
        Err(TunError::Unsupported)
    }
    pub fn get_default_gateway() -> Result<String, TunError> {
        Err(TunError::Unsupported)
    }
}
