# ZCDNS Tunnel

**Stateless, Dynamic SSH Tunnels with Automatic Protocol Detection**

This project provides a stateless, dynamic SSH port forwarding solution that allows you to expose local services to the internet using custom domains. Authentication is handled entirely through DNS records, eliminating the need for a server-side database.

The server features a smart multiplexer that automatically detects the protocol (HTTPS/TLS vs. plain HTTP) of incoming traffic on any forwarded port, routing it to the correct SSH tunnel.

## How It Works

1.  **DNS Setup:**
    *   Create a **CNAME record** for your custom domain (e.g., `app.your-domain.com`) that points to the tunnel server's domain (e.g., `tunnel.my-server.com`).
    *   Add a **TXT record** to your domain with your SSH public key:
        ```
        zcdns-ssh-key=ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC...
        ```

2.  **Client-Side: Create the Tunnel**
    *   Use the standard `ssh` command with remote port forwarding (`-R`) to connect to the server. Use your domain as the username.
    *   The server will automatically create a public listener on the port you request.

    **Unified Command Format:**
    ```bash
    ssh -N <your_domain>@<tunnel_server> -p <ssh_port> -R <server_port>:<local_service_host>:<local_service_port>
    ```

    **Example 1: Exposing a local web server on port 443 (for HTTPS)**
    ```bash
    # Traffic to https://app.your-domain.com will be forwarded to your local localhost:3000
    ssh -N app.your-domain.com@tunnel.my-server.com -p 2222 -R 443:localhost:3000
    ```

    **Example 2: Exposing a local API on port 8080 (for plain HTTP)**
    ```bash
    # Traffic to http://api.your-domain.com:8080 will be forwarded to your local localhost:5000
    ssh -N api.your-domain.com@tunnel.my-server.com -p 2222 -R 8080:localhost:5000
    ```
    **Note:** You no longer need any special prefixes like `http.` in the username. The server handles everything automatically.

3.  **Server-Side: Automatic Protocol Detection**
    *   The server receives your SSH connection and, after authenticating you via DNS, accepts your request to open a public port (`<server_port>`).
    *   When traffic arrives at that port, the server's **multiplexer** inspects the first few bytes of the connection.
    *   If it detects a TLS handshake (for HTTPS), it acts as an **SNI Proxy**, reading the SNI hostname to find your tunnel.
    *   If it detects a plain HTTP request, it acts as an **HTTP Proxy**, reading the `Host` header to find your tunnel.
    *   The traffic is then seamlessly forwarded to your local service through the secure SSH tunnel.

## Features

*   **Stateless and "DB-less":** No database or server-side state to manage. All configuration is in DNS.
*   **DNS-Based Authentication:** Securely manage access through your DNS provider.
*   **Dynamic Multiplexer:** A single listener on a given port can handle both HTTPS and HTTP traffic, routing to different tunnels.
*   **Simplified Client Experience:** A single, standard `ssh` command format for all protocol types. No special prefixes needed.
*   **Flexible Port Forwarding:** Expose any local service on any desired public port on the server.

## Use Cases

*   Exposing local development servers for demos or webhooks.
*   Providing custom domains for SaaS applications.
*   Running services on dynamic IP addresses or behind NAT.
*   Building resilient, decentralized systems with simple routing.