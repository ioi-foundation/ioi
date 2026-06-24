/* Phase 1 microVM guest agent (G1 — guest-agent vsock contract).
 *
 * Runs as PID 1 (rdinit=/init) inside the cloud-hypervisor microVM. Serves a versioned vsock RPC
 * on port 1024 so the host VmMonitor can stage the workspace, exec commands INSIDE the guest
 * (real kernel isolation — execution never touches the host kernel), and retrieve results. The
 * workspace lives in a guest tmpfs; it is transferred in/out as a tar stream over vsock (the
 * host's disk image is never the workspace, so the host checkout stays untouched). Static-linked
 * (gcc -static), no libc runtime deps in the guest. Build: gcc -static -O2 -o guest-agent guest-agent.c
 *
 * Wire protocol (binary, little-endian), one request per accepted connection:
 *   'H'  -> reply: u32 proto_version            (G1 version negotiation)
 *   'P'  -> reply: 1 byte 'O'                    (heartbeat / ping)
 *   'I'  -> u64 tar_len, tar bytes; extract into /workspace; reply 1 byte 'O'   (import workspace)
 *   'E'  -> u32 cmd_len, cmd bytes; run in /workspace
 *           reply: i32 exit_code, u32 out_len, out bytes (combined stdout+stderr)
 *   'X'  -> reply: u64 tar_len, tar bytes        (export /workspace as a tar)
 *   'Y'  -> sync(); reply 1 byte 'O'
 *   'S'  -> sync(); power off                    (shutdown)
 * The host's cloud-hypervisor "CONNECT 1024" handshake is host<->VMM and not seen here.
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdint.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/mount.h>
#include <sys/wait.h>
#include <sys/reboot.h>
#include <linux/vm_sockets.h>

#define PROTO_VERSION 2u
#define VSOCK_PORT 1024
#define WS "/workspace"

static int read_all(int fd, void *buf, size_t n) {
  size_t got = 0;
  while (got < n) {
    ssize_t r = read(fd, (char *)buf + got, n - got);
    if (r <= 0) return -1;
    got += (size_t)r;
  }
  return 0;
}
static int write_all(int fd, const void *buf, size_t n) {
  size_t put = 0;
  while (put < n) {
    ssize_t w = write(fd, (const char *)buf + put, n - put);
    if (w <= 0) return -1;
    put += (size_t)w;
  }
  return 0;
}

/* Run argv with stdin from in_fd (or -1) and stdout captured to *out (malloc'd) if out!=NULL.
 * Returns the child exit code. */
static int run(char *const argv[], int in_fd, char **out, size_t *out_len, const char *cwd) {
  int pipefd[2];
  if (out) { if (pipe(pipefd) != 0) return -1; }
  pid_t pid = fork();
  if (pid == 0) {
    if (cwd) { if (chdir(cwd) != 0) _exit(126); }
    if (in_fd >= 0) { dup2(in_fd, 0); }
    if (out) { dup2(pipefd[1], 1); dup2(pipefd[1], 2); close(pipefd[0]); close(pipefd[1]); }
    execv(argv[0], argv);
    _exit(127);
  }
  if (in_fd >= 0) close(in_fd);
  if (out) {
    close(pipefd[1]);
    size_t cap = 65536, len = 0; char *buf = (char *)malloc(cap);
    char tmp[8192]; ssize_t r;
    while ((r = read(pipefd[0], tmp, sizeof(tmp))) > 0) {
      if (len + (size_t)r > cap) { cap = (len + (size_t)r) * 2; buf = (char *)realloc(buf, cap); }
      memcpy(buf + len, tmp, (size_t)r); len += (size_t)r;
    }
    close(pipefd[0]);
    *out = buf; *out_len = len;
  }
  int status = 0; waitpid(pid, &status, 0);
  return WIFEXITED(status) ? WEXITSTATUS(status) : -1;
}

static void setup(void) {
  mkdir("/proc", 0555); mkdir("/sys", 0555); mkdir("/dev", 0755); mkdir(WS, 0755); mkdir("/tmp", 0777);
  mount("proc", "/proc", "proc", 0, "");
  mount("sysfs", "/sys", "sysfs", 0, "");
  mount("devtmpfs", "/dev", "devtmpfs", 0, "");
  /* workspace is a guest tmpfs; staged in/out via vsock tar (no host-disk write path needed). */
  mount("tmpfs", WS, "tmpfs", 0, "size=80%");
  mount("tmpfs", "/tmp", "tmpfs", 0, "");
}

static void handle_exec(int c) {
  uint32_t len;
  if (read_all(c, &len, 4) != 0) return;
  char *cmd = (char *)malloc((size_t)len + 1);
  if (!cmd) return;
  if (read_all(c, cmd, len) != 0) { free(cmd); return; }
  cmd[len] = 0;
  char *out = NULL; size_t out_len = 0;
  char *argv[] = {"/bin/busybox", "sh", "-c", cmd, NULL};
  int code = run(argv, -1, &out, &out_len, WS);
  int32_t code32 = code;
  uint32_t ol = (uint32_t)out_len;
  write_all(c, &code32, 4);
  write_all(c, &ol, 4);
  write_all(c, out, out_len);
  free(out); free(cmd);
}

static void handle_import(int c) {
  uint64_t len;
  if (read_all(c, &len, 8) != 0) return;
  int fd = open("/tmp/in.tar", O_CREAT | O_TRUNC | O_WRONLY, 0644);
  if (fd < 0) return;
  char buf[65536]; uint64_t got = 0;
  while (got < len) {
    size_t want = (len - got) < sizeof(buf) ? (size_t)(len - got) : sizeof(buf);
    if (read_all(c, buf, want) != 0) { close(fd); return; }
    if (write_all(fd, buf, want) != 0) { close(fd); return; }
    got += want;
  }
  close(fd);
  char *argv[] = {"/bin/busybox", "tar", "-xf", "/tmp/in.tar", "-C", WS, NULL};
  run(argv, -1, NULL, NULL, NULL);
  unlink("/tmp/in.tar");
  unsigned char o = 'O'; write_all(c, &o, 1);
}

static void handle_export(int c) {
  char *argv[] = {"/bin/busybox", "tar", "-cf", "/tmp/out.tar", "-C", WS, ".", NULL};
  run(argv, -1, NULL, NULL, NULL);
  int fd = open("/tmp/out.tar", O_RDONLY);
  uint64_t len = 0;
  struct stat st;
  if (fd >= 0 && fstat(fd, &st) == 0) len = (uint64_t)st.st_size;
  write_all(c, &len, 8);
  if (fd >= 0) {
    char buf[65536]; ssize_t r;
    while ((r = read(fd, buf, sizeof(buf))) > 0) write_all(c, buf, (size_t)r);
    close(fd);
  }
  unlink("/tmp/out.tar");
}

int main(void) {
  setup();
  int s = socket(AF_VSOCK, SOCK_STREAM, 0);
  if (s < 0) { printf("GUEST_AGENT_VSOCK_FAIL\n"); fflush(stdout); for (;;) sleep(60); }
  struct sockaddr_vm addr;
  memset(&addr, 0, sizeof(addr));
  addr.svm_family = AF_VSOCK;
  addr.svm_cid = VMADDR_CID_ANY;
  addr.svm_port = VSOCK_PORT;
  if (bind(s, (struct sockaddr *)&addr, sizeof(addr)) != 0) { printf("GUEST_AGENT_BIND_FAIL\n"); fflush(stdout); }
  listen(s, 8);
  printf("GUEST_AGENT_READY proto=%u\n", PROTO_VERSION);
  fflush(stdout);
  for (;;) {
    int c = accept(s, NULL, NULL);
    if (c < 0) continue;
    unsigned char op;
    if (read_all(c, &op, 1) != 0) { close(c); continue; }
    if (op == 'H') { uint32_t v = PROTO_VERSION; write_all(c, &v, 4); }
    else if (op == 'P') { unsigned char o = 'O'; write_all(c, &o, 1); }
    else if (op == 'Y') { sync(); unsigned char o = 'O'; write_all(c, &o, 1); }
    else if (op == 'I') { handle_import(c); }
    else if (op == 'E') { handle_exec(c); }
    else if (op == 'X') { handle_export(c); }
    else if (op == 'S') { close(c); sync(); reboot(RB_POWER_OFF); }
    close(c);
  }
}
