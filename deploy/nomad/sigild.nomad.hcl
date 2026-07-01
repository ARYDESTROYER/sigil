# Nomad jobspec for sigild. SKELETON — NOT APPLIED.
# The single-VM systemd shape (deploy/systemd/) is the starting point; this is
# the next step up (orchestrated VMs) before Kubernetes is ever considered.

job "sigild" {
  datacenters = ["dc1"]
  type        = "service"

  group "server" {
    count = 1

    network {
      port "http" {
        to = 8080
      }
    }

    task "sigild" {
      driver = "docker"

      # Give the service registry / health check time to deregister this
      # allocation before the container is killed, so in-flight requests drain
      # and Caddy/Nomad stop routing to it first (silences the validate warning
      # "defines services, but has no shutdown_delay set").
      shutdown_delay = "5s"

      config {
        # Placeholder — repoint at the image built from ../../sigild/Dockerfile
        # and published to the registry (tag = git short SHA). Not yet published.
        image = "ghcr.io/PLACEHOLDER/sigild:latest"
        ports = ["http"]
      }

      # Secrets injected via Nomad template/Vault, never baked into the image.
      env {
        SIGILD_ADDR = ":8080"
      }

      resources {
        cpu    = 250
        memory = 128
      }

      service {
        name = "sigild"
        port = "http"

        check {
          type     = "http"
          path     = "/healthz"
          interval = "10s"
          timeout  = "2s"
        }
      }
    }
  }
}
