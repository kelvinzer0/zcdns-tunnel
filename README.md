# ZCDNS Tunnel

**Stateless, Dynamic SSH Tunnels with Explicit Protocol Routing**

This project provides a stateless, dynamic SSH port forwarding solution that allows you to expose local services to the internet using custom domains. Authentication is handled entirely through DNS records, eliminating the need for a server-side database.

The server features a smart multiplexer that routes incoming traffic based on an explicit protocol prefix provided in the SSH username, ensuring precise routing for HTTPS/TLS and plain HTTP traffic.

## How It Works

1.  **DNS Setup:**
    *   Create a **CNAME record** for your custom domain (e.g., `app.your-domain.com`) that points to the tunnel server's domain (e.g., `tunnel.my-server.com`).
    *   Add a **TXT record** to a special challenge subdomain of your domain with your SSH public key. This is used for authentication.
        ```
        _zcdns-challenge.your-domain.com. IN TXT "zcdns-ssh-key=ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAQC..."
        ```

2.  **Client-Side: Create the Tunnel**
    *   Use the standard `ssh` command with remote port forwarding (`-R`) to connect to the server. **Crucially, prepend your domain with a protocol prefix (`http.` or `tls.`) in the username.**
    *   The server will automatically create a public listener on the port you request.

    **Unified Command Format:**
    ```bash
    ssh -N [protocol_prefix].<your_domain>@<tunnel_server> -p <ssh_port> -R <server_port>:<local_service_host>:<local_service_port>
    ```
    *   `[protocol_prefix]` can be `http` for plain HTTP traffic or `tls` for HTTPS/TLS traffic.

    **Example 1: Exposing a local web server on port 443 (for HTTPS)**
    ```bash
    # Traffic to https://app.your-domain.com will be forwarded to your local localhost:3000
    ssh -N tls.app.your-domain.com@tunnel.my-server.com -p 2222 -R 443:localhost:3000
    ```

    **Example 2: Exposing a local API on port 8080 (for plain HTTP)**
    ```bash
    # Traffic to http://api.your-domain.com:8080 will be forwarded to your local localhost:5000
    ssh -N http.api.your-domain.com@tunnel.my-server.com -p 2222 -R 8080:localhost:5000
    ```
    **Note:** The protocol prefix (`http.` or `tls.`) is now mandatory in the SSH username to explicitly tell the server how to route traffic for that specific tunnel. This allows for precise routing when multiple tunnels share the same domain but handle different protocols.

3.  **Server-Side: Explicit Protocol Routing**
    *   The server receives your SSH connection and, after authenticating you via DNS, extracts the domain and the `protocol_prefix` from your username.
    *   It then accepts your request to open a public port (`<server_port>`).
    *   When traffic arrives at that public port, the server's **multiplexer** determines the intended protocol (TLS or HTTP) based on the incoming traffic's characteristics (e.g., TLS handshake vs. HTTP request line).
    *   It then uses the extracted domain, the detected protocol, and the public port to find the correct intermediary bridge address.
    *   The traffic is then seamlessly forwarded to your local service through the secure SSH tunnel.

## Distributed Architecture (Experimental)

This project is evolving towards a distributed architecture to handle a large number of tunnels across multiple server instances. This is achieved through:

1.  **Gossip Protocol (Custom UDP Implementation):**
    *   Each `zcdns-tunnel` server instance (node) participates in a custom UDP-based gossip protocol.
    *   Nodes automatically discover each other, maintain a list of active peers, and detect node failures.
    *   This provides a decentralized and fault-tolerant way to manage cluster membership without external dependencies like etcd or Consul.

2.  **Consistent Hashing:**
    *   A consistent hashing ring is maintained by each node, populated with the addresses of all active peers discovered via the gossip protocol.
    *   When a client requests a `tcpip-forward` for a specific domain, the server uses consistent hashing to determine which node in the cluster is "responsible" for that domain.
    *   If the current node is the responsible node, it proceeds to establish the tunnel.
    *   **Note:** Currently, if a request arrives at a node that is *not* responsible for the domain, the request is denied. Future development will include inter-node communication (RPC) to forward these requests to the responsible node, enabling true load balancing and failover for tunnel establishment.

This distributed design aims to provide horizontal scalability, allowing the system to handle millions of tunnels by simply adding more small, independent `zcdns-tunnel` nodes.

### Bootstrapping the First Node

When starting a new cluster, or if no other `zcdns-tunnel` nodes are running and reachable via your `validation_domain` DNS records, you need to use the `--bootstrap` flag for the very first node. This tells the node to determine its own public IP address locally, rather than asking another peer.

For cloud deployments where the local IP might be a private IP, you can explicitly specify the public IP using the `--public-ip` flag:

```bash
./zcdns-tunnel --config configs/server.yml --bootstrap --public-ip <YOUR_PUBLIC_IP>
```

Once the first node is running, subsequent nodes can be started without the `--bootstrap` flag, and they will automatically discover the existing cluster via DNS and the gossip protocol.

## Features

*   **Stateless and "DB-less":** No database or server-side state to manage. All configuration is in DNS.
*   **DNS-Based Authentication:** Securely manage access through your DNS provider.
*   **Explicit Protocol Routing:** Use `http.` or `tls.` prefixes in SSH username for clear and reliable traffic routing.
*   **Dynamic Multiplexer:** A single listener on a given port can handle both HTTPS and HTTP traffic, routing to different tunnels based on protocol and domain.
*   **Flexible Port Forwarding:** Expose any local service on any desired public port on the server.

## Use Cases

*   Exposing local development servers for demos or webhooks.
*   Providing custom domains for SaaS applications.
*   Running services on dynamic IP addresses or behind NAT.
*   Building resilient, decentralized systems with simple routing.