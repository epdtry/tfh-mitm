# Setup

These instructions are entirely untested.  Have fun!


## Building

Run `cargo build --release`.  This will create the binaries `tun-server` and
`tfh-relay` under `target/release/`.  Make a work directory and copy the
binaries there.

Everything else should happen inside that work directory, unless otherwise
noted.


## Run the lobby server

The TFH lobby server runs fine under Wine.  Get this working normally first,
before you start messing with the network and routing configuration.

In a normal X session:

 1. Follow the normal lobby server installation instructions.  When running
    `steamcmd`, use `wineconsole steamcmd.exe` instead of normal `wine`.
 2. To run the server, use this command:
    ```sh
    wineconsole .wine/drive_c/tfhlobby/LobbyExe.exe -f config/Lobby_server.geoproj -i
    ```
    (Note this assumes you used `c:\tfhlobby` as the `force_install_dir` for
    `steamcmd`.)  You can also find the right arguments by reading the .bat
    file the normal instructions tell you to run.
 3. Connect to the server and make sure it works.  If it doesn't show up in the
    server list, you may need to forward UDP port 27016 and/or open that port
    in your firewall.  If running inside a VM, you may need to enable port
    forwarding in your VM manager or switch to bridged networking.

Note that installing Steam is no longer required to run the lobby server.


## Create the sandbox

Open a shell inside a new network namespace using `sudo unshare -n bash`.  Note
this namespace will exist only until `bash` exits.  Now set it up:

```sh
# Check that the unshare worked
ip link     # should show only `lo`, no other interfaces

# Adjust the prompt so you can distinguish this shell from others
PS1="(sandbox) $PS1"

# Check SUDO_USER contains your actual username
echo $SUDO_USER

# Create the "inside" network interface.  This shell is already running as
# root, so no need for sudo.
ip tuntap add dev tun-tfh-inside mode tun user $SUDO_USER
ip link set dev tun-tfh-inside up
ip addr add dev tun-tfh-inside 192.168.84.2/24
ip route add default via 192.168.84.1

# Drop privileges
exec su - $SUDO_USER
PS1="(sandbox) $PS1"

# Let non-sandboxed processes access the inside interface via a unix socket
./tun-server tun-tfh-inside tun &
ls -l tun   # should show the socket, mode srwx------

# Leave this shell open.  It will be needed later.
```


## Set up the tunnel

```sh
sudo ip tuntap add dev tun-tfh-outside mode tun user $USER
sudo ip link set dev tun-tfh-outside up
sudo ip addr add dev tun-tfh-outside 192.168.84.1/24

# Run the tunnel.  This will relay traffic between the inside and outside
# interfaces.  Note this assumes that the outside interface is named
# `tun-tfh-outside` and that the inside interface will be provided through a
# unix socket named `tun`.
./tfh-relay
```

In the sandbox shell, try running `ping 192.168.84.1`.  You should see the
normal ping responses, and `tfh-relay` should print a pair of messages (one
`B->A` and one `A->B`) for each ping.


## Configure routing

Next, set up nftables/iptables NAT routing between `tun-tfh-outside` and your
real network interface.

```
# Find the name of your real network interface.
ip route
# Look for the line `default via <address> dev <ifname>`.  Put the ifname in a
# variable:
IFNAME=<ifname>

# Now set up NAT routing between tun-tfh-outside and $IFNAME.  Search for
# guides on iptables NAT routing / "how to use a linux machine as a router" if
# you want more details of how this works.
echo 1 | sudo tee /proc/sys/net/ipv4/ip_forward
sudo iptables -t nat -A POSTROUTING -o $IFNAME -j MASQUERADE
sudo iptables -A FORWARD -i $IFNAME -o tun-tfh-outside -m state --state RELATED,ESTABLISHED -j ACCEPT
sudo iptables -A FORWARD -i tun-tfh-outside -o $IFNAME -j ACCEPT

# Forward UDP port 27016 to the inside
sudo iptables -t nat -A PREROUTING -i $IFNAME -p udp --dport 27016 -j DNAT --to 192.168.84.2:27016
sudo iptables -A FORWARD -p tcp -d 192.168.84.2 --dport 27016 -j ACCEPT
```

You should now be able to ping outside servers from within the sandbox.  For
example, `ping 8.8.8.8`.


## Run the lobby server

The lobby server should now work when run inside the sandbox shell.

First, you'll have to set `$DISPLAY` inside the sandbox.  Check what the value
of `$DISPLAY` is in a normal graphical terminal (it's often `:0`, or `:10` if
you're using VNC), and set it to the same value inside.

```sh
export DISPLAY=:0  # or whatever
wineconsole ~/.wine/drive_c/tfhlobby/LobbyExe.exe -f config/Lobby_server.geoproj -i
```

This should work just the same as before, except you'll see a bunch of traffic
scroll by in the tfh-relay output.


## Modifying tfh-relay

As long as everything else is still running, you can kill and restart
`tfh-relay` as needed to test out different modifications.  This is effectively
the same as briefly unplugging the lobby server's network connection, so if
you're quick about it, this shouldn't even drop any players that are connected.
