/* Phase 1 microVM guest model proxy (M13.10 — ADR 0053 § 2's brokered model channel).
 *
 * Runs INSIDE the guest, started before the harness. Listens on 127.0.0.1:<listen_port> and
 * tunnels every accepted connection, BYTE FOR BYTE, to the host over AF_VSOCK (CID 2, the host)
 * on <host_port>. The host end connects onward to the model endpoint the run's route resolved.
 *
 * WHY THIS EXISTS. The hostile-guest profile has NO NETWORK DEVICE — the provider refuses one by
 * name (`workload_boundary_network_device_refused`) — and the harness is an ordinary agent CLI that
 * speaks HTTP to a base URL. Something in the guest therefore has to present an HTTP endpoint and
 * carry the bytes out over a channel that is not a network device. AF_VSOCK is not a network
 * device: it is a socket family the guest kernel carries built-in, which is how the guest agent
 * listens at all. So the boundary ADR 0053 § 2 names is preserved LITERALLY and completely.
 *
 * WHY IT IS A RAW BYTE TUNNEL AND NOT AN HTTP PROXY. Parsing HTTP here would mean re-implementing
 * chunked transfer, keep-alive and streaming responses inside a static C binary running as the
 * least-trusted thing in the estate, and every one of those is a place to be subtly wrong about
 * someone else's bytes. A tunnel is correct for HTTP/1.1, correct for streamed completions, and has
 * nothing to be wrong about: what the harness wrote is what the host reads.
 *
 * WHAT IT DELIBERATELY DOES NOT DO. It holds no credential and reads no header, and it opens no
 * second destination: one listen port, one vsock port, no configuration read from inside the guest.
 *
 * ON CREDENTIALS, STATED EXACTLY RATHER THAN REASSURINGLY. The lane this ships for is the LOCAL
 * model route, which has no credential at all — there is nothing to hold, so the guest holding
 * nothing is trivially true. A remote `openai_compatible` route DOES carry a run-scoped token, and
 * a pure byte tunnel cannot attach one without parsing the HTTP it was written not to parse. That
 * lane is therefore REFUSED at the host end rather than served by putting a token inside the guest,
 * and the refusal is typed. When it is built, the header injection belongs on the HOST side, which
 * is trusted, in Rust, and inside the daemon — never here.
 *
 * Build (matching guest-agent.c, the same static-no-libc-runtime constraint):
 *   gcc -static -O2 -s -o guest-model-proxy guest-model-proxy.c
 *
 * Usage: guest-model-proxy <listen_port> <host_vsock_port>
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdint.h>
#include <errno.h>
#include <signal.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <netinet/in.h>
#include <linux/vm_sockets.h>

/* The host's well-known context id in the vsock addressing scheme. */
#define HOST_CID 2
#define BUF 65536

/* Pump bytes from `from` to `to` until either side closes. Returns on EOF or error; a tunnel has
 * no opinion about what the bytes mean, so there is nothing else to decide. */
static void pump(int from, int to) {
  char buf[BUF];
  for (;;) {
    ssize_t n = read(from, buf, sizeof buf);
    if (n <= 0) return;
    ssize_t off = 0;
    while (off < n) {
      ssize_t w = write(to, buf + off, (size_t)(n - off));
      if (w <= 0) return;
      off += w;
    }
  }
}

int main(int argc, char **argv) {
  if (argc != 3) {
    fprintf(stderr, "usage: %s <listen_port> <host_vsock_port>\n", argv[0]);
    return 2;
  }
  int listen_port = atoi(argv[1]);
  int host_port = atoi(argv[2]);
  if (listen_port <= 0 || listen_port > 65535 || host_port <= 0) {
    fprintf(stderr, "ports out of range\n");
    return 2;
  }
  /* A child that dies mid-tunnel must not become a zombie, and a peer that closes early must not
   * kill this process with SIGPIPE — the tunnel notices the close through read/write instead. */
  signal(SIGCHLD, SIG_IGN);
  signal(SIGPIPE, SIG_IGN);

  int srv = socket(AF_INET, SOCK_STREAM, 0);
  if (srv < 0) { perror("socket"); return 1; }
  int one = 1;
  setsockopt(srv, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one);
  struct sockaddr_in a;
  memset(&a, 0, sizeof a);
  a.sin_family = AF_INET;
  a.sin_port = htons((uint16_t)listen_port);
  /* LOOPBACK ONLY. There is no network device to bind to anyway, and binding the wildcard would
   * still be the wrong statement of intent. */
  a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
  if (bind(srv, (struct sockaddr *)&a, sizeof a) < 0) { perror("bind"); return 1; }
  if (listen(srv, 16) < 0) { perror("listen"); return 1; }

  for (;;) {
    int c = accept(srv, NULL, NULL);
    if (c < 0) { if (errno == EINTR) continue; perror("accept"); return 1; }

    int v = socket(AF_VSOCK, SOCK_STREAM, 0);
    if (v < 0) { close(c); continue; }
    struct sockaddr_vm vm;
    memset(&vm, 0, sizeof vm);
    vm.svm_family = AF_VSOCK;
    vm.svm_cid = HOST_CID;
    vm.svm_port = (unsigned int)host_port;
    if (connect(v, (struct sockaddr *)&vm, sizeof vm) < 0) {
      /* The host end is not listening. Close rather than answer: a proxy that returned its own
       * error page would be putting bytes the model never sent in front of the harness. */
      close(v);
      close(c);
      continue;
    }

    pid_t pid = fork();
    if (pid == 0) {
      close(srv);
      pid_t inner = fork();
      if (inner == 0) { pump(v, c); shutdown(c, SHUT_WR); _exit(0); }
      pump(c, v);
      shutdown(v, SHUT_WR);
      if (inner > 0) waitpid(inner, NULL, 0);
      _exit(0);
    }
    close(c);
    close(v);
  }
}
