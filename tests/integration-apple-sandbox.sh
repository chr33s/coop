#!/usr/bin/env bash
set -uo pipefail

# Real-hardware checks for coop-sandbox (macos/coop-sandbox), the runtime
# behind the `apple-container` build. Unit tests cannot boot VMs; this boots
# real ones and checks what the backend's isolation contract relies on
# (docs/trust-model.md): peer isolation between sandboxes, no host mounts,
# agent sockets, or canary leakage, pinned SSH over the native channel, and
# the lifecycle (persistence, resources, disk growth, commit/restore, crash
# recovery, concurrency).
#
# Usage: tests/integration-apple-sandbox.sh [--only PHASE[,PHASE...]] [--keep]
#   Phases: setup disks machine isolation exposure identity persistence
#           resources growth snapshots recovery concurrency
#   CYCLES=5 stop/start cycles; CONCURRENT=4 sandboxes.
#
# Needs Apple Silicon, macOS 26+, Swift 6.2+, jq, and stock Apple `container`
# with its service running (builds the test image, supplies the kernel). It
# touches nothing but its own state root and image tag, both removed on exit.

if [[ "$(uname -s)" != Darwin || "$(uname -m)" != arm64 ]]; then
    echo "SKIP: coop-sandbox needs an Apple Silicon Mac"
    exit 0
fi
CONTAINER=""
for candidate in /usr/local/bin/container /opt/homebrew/bin/container; do
    [[ -x "$candidate" ]] && { CONTAINER="$candidate"; break; }
done
[[ -n "$CONTAINER" ]] || { echo "SKIP: no Apple container CLI installed"; exit 0; }
for tool in swift jq ssh ssh-keygen nc openssl; do
    command -v "$tool" >/dev/null || { echo "Missing prerequisite: $tool" >&2; exit 1; }
done

ONLY=""
KEEP=0
while [[ $# -gt 0 ]]; do
    case "$1" in
        --only) ONLY=",$2,"; shift 2 ;;
        --keep) KEEP=1; shift ;;
        *) echo "unknown argument: $1" >&2; exit 2 ;;
    esac
done
want() { [[ -z "$ONLY" || "$ONLY" == *",$1,"* ]]; }

cd "$(dirname "$0")/.." || exit 1
FIXTURES="$PWD/tests/fixtures/apple-sandbox"
RUN="t$(openssl rand -hex 4)"
WORK="$(mktemp -d "${TMPDIR:-/tmp}/coop-sandbox-test.XXXXXX")"
ROOT="$WORK/root"
IMAGE="local/coop-sandbox-test:$RUN"
SANDBOX="$WORK/bin/coop-sandbox"
CYCLES="${CYCLES:-5}"
CONCURRENT="${CONCURRENT:-4}"
# A secret that exists only in this script's environment; it must never reach
# the runtime, its logs, the image, or a guest.
CANARY="coop-test-canary-$(openssl rand -hex 16)"
export CANARY

pass_count=0
fail_count=0
skip_count=0

pass() {
    pass_count=$((pass_count + 1))
    echo "  PASS  $1"
}

fail() {
    fail_count=$((fail_count + 1))
    echo "  FAIL  $1"
    if [[ -n "${2:-}" ]]; then
        echo "        $2"
    fi
}

skip() {
    skip_count=$((skip_count + 1))
    echo "  SKIP  $1${2:+ ($2)}"
}

check() {
    local label="$1"
    shift
    if "$@"; then pass "$label"; else fail "$label"; fi
}

# refuses CMD...: CMD must fail.
refuses() { ! "$@" >/dev/null 2>&1; }

summary() {
    echo ""
    echo "────────────────────────────────────────"
    echo "  $pass_count passed, $fail_count failed, $skip_count skipped"
    echo "────────────────────────────────────────"
    if [[ $fail_count -gt 0 ]]; then
        exit 1
    fi
}

# ── Runtime helpers ───────────────────────────────────────────

sbx() { "$SANDBOX" "$1" --root "$ROOT" "${@:2}"; }
name() { echo "coop-test-$1-$RUN"; }
create() { sbx create "$1" --image "$IMAGE" --cpus "${2:-2}" --memory-mib "${3:-2048}" --disk-gib "${4:-8}" --owner "$RUN" >/dev/null; }
state() { sbx inspect "$1" 2>/dev/null | jq -r .status 2>/dev/null || echo missing; }
guest() { local n="$1"; shift; sbx exec "$n" -- "$@"; }
guest_in() { local n="$1"; shift; sbx exec -i "$n" -- "$@"; }
ip4() { sbx inspect "$1" | jq -r '.live.ipv4 // empty'; }
ip6() {
    local a i
    for ((i = 0; i < 40; i++)); do
        a="$(guest "$1" ip -6 -o addr show eth0 scope global | awk '{print $4}' | cut -d/ -f1 | head -1)"
        [[ -n "$a" ]] && { echo "$a"; return 0; }
        sleep 0.5
    done
    return 1
}

# systemd running (or degraded) with sshd and Docker active.
ready() {
    local n="$1" i st
    for ((i = 0; i < 600; i++)); do
        st="$(guest "$n" systemctl is-system-running 2>/dev/null || true)"
        if [[ "$st" == running || "$st" == degraded ]] && guest "$n" systemctl is-active --quiet ssh docker 2>/dev/null; then
            return 0
        fi
        sleep 0.2
    done
    return 1
}

boot() { sbx start "$1" >/dev/null && ready "$1"; }
verify() { guest "$1" /usr/local/sbin/coop-test-verify; }

cleanup() {
    local rc=$?
    if (( KEEP == 0 )); then
        if [[ -x "$SANDBOX" && -d "$ROOT" ]]; then
            for n in $(sbx list 2>/dev/null | jq -r '.[].id' 2>/dev/null); do
                sbx stop "$n" >/dev/null 2>&1
                sbx delete "$n" --owner "$RUN" >/dev/null 2>&1
            done
        fi
        "$CONTAINER" image delete "$IMAGE" >/dev/null 2>&1
        rm -rf "$WORK"
    else
        echo "Kept $WORK"
    fi
    exit "$rc"
}
trap cleanup EXIT

# ── Pinned SSH (never the host agent or ~/.ssh) ─────────────

KEY="$WORK/id"
KNOWN="$WORK/known_hosts"

enroll() {
    guest_in "$1" sh -c 'umask 077; mkdir -p /root/.ssh; cat > /root/.ssh/authorized_keys' <"$KEY.pub"
    grep -v "^$1 " "$KNOWN" >"$KNOWN.tmp" 2>/dev/null || true
    echo "$1 $(guest "$1" cut -d' ' -f1-2 /etc/ssh/ssh_host_ed25519_key.pub)" >>"$KNOWN.tmp"
    mv "$KNOWN.tmp" "$KNOWN"
}

pinned() {
    local n="$1"
    shift
    ssh -F /dev/null -i "$KEY" -o IdentitiesOnly=yes -o IdentityAgent=none \
        -o StrictHostKeyChecking=yes -o UserKnownHostsFile="$KNOWN" -o GlobalKnownHostsFile=/dev/null \
        -o HostKeyAlias="$n" -o HostKeyAlgorithms=ssh-ed25519 -o BatchMode=yes -o ConnectTimeout=5 \
        -o ForwardAgent=no -o LogLevel=ERROR "root@$(ip4 "$n")" "$@"
}

A="$(name a)"
B="$(name b)"

# ── Phases ────────────────────────────────────────────────────

echo "=== Phase: setup ==="
mkdir -p "$WORK/bin"
if ./scripts/build-coop-sandbox.sh "$WORK" >"$WORK/build.log" 2>&1; then
    pass "coop-sandbox builds and signs"
else
    fail "coop-sandbox builds and signs" "see $WORK/build.log"
    summary
fi
check "version reports protocol 1 on containerization 0.45.0" \
    test "$("$SANDBOX" version | jq -r '"\(.protocol) \(.containerization)"')" = "1 0.45.0"
if "$CONTAINER" build --platform linux/arm64 -t "$IMAGE" "$FIXTURES/image" >"$WORK/image.log" 2>&1 &&
    "$CONTAINER" image save --platform linux/arm64 -o "$WORK/image.tar" "$IMAGE" >/dev/null 2>&1; then
    pass "test image builds"
else
    fail "test image builds" "see $WORK/image.log"
    summary
fi
kernel="$(readlink -f "$HOME/Library/Application Support/com.apple.container/kernels/default.kernel-arm64")"
check "init accepts the pinned kernel" sbx init --kernel "$kernel"
check "init refuses an unpinned kernel" refuses "$SANDBOX" init --root "$WORK/other" --kernel "$FIXTURES/image/Dockerfile"
imported="$("$SANDBOX" image import --root "$ROOT" --oci-tar "$WORK/image.tar")"
# shellcheck disable=SC2016 # jq program text.
check "image imports into the private store" jq -e --arg r "$IMAGE" 'any(.reference == $r)' <<<"$imported"
rm -f "$WORK/image.tar"

if want disks; then
    echo ""
    echo "=== Phase: disks ==="
    for gib in 8 32 64; do
        n="$(name "d$gib")"
        create "$n" 2 2048 "$gib"
        if boot "$n"; then
            size="$(guest "$n" df -B1 --output=size / | tail -1 | xargs)"
            # ext4 metadata takes a little under 2 %; allow 5 %.
            check "${gib} GiB disk is ${gib} GiB in the guest" test "$size" -ge $((gib * 1024 * 1024 * 1024 * 95 / 100))
        else
            fail "${gib} GiB sandbox boots"
        fi
        sbx stop "$n"
        sbx delete "$n" --owner "$RUN"
    done
    t0="$(date +%s)"
    create "$(name cached)"
    check "a second create from the same image is a clone (<5 s)" test $(($(date +%s) - t0)) -lt 5
    sbx delete "$(name cached)" --owner "$RUN"
fi

create "$A" 4 8192 16
create "$B" 4 8192 16
check "created sandboxes are stopped and owned" test "$(sbx inspect "$A" | jq -r '"\(.status) \(.record.owner)"')" = "stopped $RUN"
boot "$A" || fail "sandbox A boots"
boot "$B" || fail "sandbox B boots"

if want machine; then
    echo ""
    echo "=== Phase: machine ==="
    v="$(verify "$A")"
    check "PID 1 is systemd" test "$(jq -r .pid1 <<<"$v")" = systemd
    check "systemd is running with no failed units" test "$(jq -r '"\(.system_state) \(.failed_units|length)"' <<<"$v")" = "running 0"
    check "sshd and Docker stay active after the exec" test "$(guest "$A" systemctl is-active ssh docker | tr '\n' ' ')" = "active active "
    check "docker runs a container" guest "$A" docker run --rm alpine:3.20 /bin/true
    check "docker builds an image" guest "$A" sh -c 'mkdir -p /tmp/b && printf "FROM alpine:3.20\nRUN echo built > /built\n" > /tmp/b/Dockerfile && docker build -q -t t /tmp/b >/dev/null'
    eff="$(sbx inspect "$A" | jq .effective)"
    check "effective config: kernel pseudo-filesystems only" \
        jq -e '[.mounts[] | select(.type | IN("proc","sysfs","devtmpfs","mqueue","tmpfs","cgroup2","devpts") | not)] | length == 0' <<<"$eff"
    check "effective config: no relays, ports, or agent forwarding" \
        jq -e '.socketRelays == 0 and .publishedPorts == 0 and .sshAgentForwarding == false' <<<"$eff"
    check "effective config: one interface on its own vmnet subnet" \
        jq -e '(.interfaces | length) == 1 and (.interfaces[0].network | startswith("vmnet-shared:10.231."))' <<<"$eff"
    # shellcheck disable=SC2016 # jq program text.
    check "effective config: boots its own disk under the root" \
        jq -e --arg p "/sandboxes/$A/rootfs.ext4" '.rootfs.type == "ext4" and (.rootfs.source | endswith($p))' <<<"$eff"
    check "effective config: requested CPUs and memory" jq -e '.cpus == 4 and .memoryBytes == 8589934592' <<<"$eff"
fi

if want isolation; then
    echo ""
    echo "=== Phase: isolation ==="
    # listeners TARGET: TCP/UDP echo on 7777/7778 as systemd units.
    listeners() {
        guest "$1" sh -c '
            sysctl -qw net.ipv4.icmp_echo_ignore_broadcasts=0
            systemctl is-active --quiet coop-test-tcp || systemd-run --quiet --unit=coop-test-tcp socat TCP6-LISTEN:7777,ipv6only=0,fork,reuseaddr SYSTEM:"echo pong"
            systemctl is-active --quiet coop-test-udp || systemd-run --quiet --unit=coop-test-udp socat UDP6-RECVFROM:7778,ipv6only=0,fork SYSTEM:"echo upong"' >/dev/null
        sleep 0.5
    }
    # probe ATTACKER TARGET LABEL: every vector blocked, host control reaches the target.
    probe() {
        local from="$1" to="$2" label="$3" t4 t6 mac ll reached host
        listeners "$to"
        t4="$(ip4 "$to")"
        t6="$(ip6 "$to")"
        mac="$(guest "$to" cat /sys/class/net/eth0/address)"
        ll="$(guest "$to" ip -6 -o addr show eth0 scope link | awk '{print $4}' | cut -d/ -f1 | head -1)"
        guest_in "$from" sh -c 'cat > /tmp/probe.sh && chmod +x /tmp/probe.sh' <"$FIXTURES/peer-probe.sh"
        reached="$(guest "$from" /tmp/probe.sh "$t4" "$t6" "$mac" "$ll" | jq -rs '[.[] | select(.reached) | .probe] | join(",")')"
        # TCP and IPv6 replies reach host sockets; IPv4 UDP/ICMP replies from
        # vmnet guests do not on macOS, so those are not host controls.
        host="$("$FIXTURES/host-probe.sh" "$t4" "$t6" | jq -r '[to_entries[] | select(.value == false and (.key | IN("ipv4-icmp","ipv4-udp") | not)) | .key] | join(",")')"
        if [[ -n "$reached" ]]; then
            fail "$label: guest blocked on every vector" "reached via $reached"
        elif [[ -n "$host" ]]; then
            fail "$label: host positive control reaches the target" "no reply over $host"
        else
            pass "$label: TCP/UDP/ICMP over IPv4/IPv6, forged routes, static neighbours, spoofed source, broadcast/multicast all blocked"
        fi
    }
    probe "$A" "$B" "A -> B"
    probe "$B" "$A" "B -> A"
    sbx stop "$A"; sbx stop "$B"
    boot "$A"; boot "$B"
    probe "$A" "$B" "A -> B after restarts"
fi

if want exposure; then
    echo ""
    echo "=== Phase: exposure ==="
    mi="$(guest "$A" cat /proc/self/mountinfo)"
    check "no virtiofs, 9p, FUSE, NFS, or SMB mounts" refuses grep -Eq ' - (virtiofs|9p|fuse|fuse\.[^ ]+|nfs4?|cifs|smb3?|smbfs) ' <<<"$mi"
    check "no host path in the mount table" refuses grep -q '/Users/' <<<"$mi"
    token="coop-test-file-$(openssl rand -hex 12)"
    printf '%s\n' "$token" >"$HOME/.coop-test-canary-$RUN"
    check "a host home file is not visible in the guest" \
        test -z "$(guest "$A" sh -c "grep -rslF '$token' / --exclude-dir=proc --exclude-dir=sys --exclude-dir=dev 2>/dev/null | head -1")"
    rm -f "$HOME/.coop-test-canary-$RUN"
    genv="$(guest "$A" sh -c 'tr "\0" "\n" < /proc/1/environ; env')"
    check "no SSH_AUTH_SOCK in the guest" refuses grep -q SSH_AUTH_SOCK <<<"$genv"
    socks="$(guest "$A" sh -c 'find / -xdev -type s 2>/dev/null')"
    check "no agent-like socket in the guest" refuses grep -Eiq 'agent|ssh-auth|host-services' <<<"$socks"
    # shellcheck disable=SC2016 # Expand in the guest.
    check "no host vsock listener reachable" \
        test -z "$(guest "$A" sh -c 'for p in $(seq 1 1024) 2375 5000 8080 268435456 268435457; do timeout 1 socat -u /dev/null VSOCK-CONNECT:2:$p 2>/dev/null && echo $p; done; true')"
    leaked=""
    # shellcheck disable=SC2009 # pgrep cannot match the environment `ps -E` shows.
    ps -axwwE -o command= | grep -E 'coop-sandbox (run|start)' | grep -v grep | grep -qF "$CANARY" && leaked+=" runtime-env"
    grep -qF "$CANARY" "$ROOT/sandboxes/$A/owner.log" "$ROOT/sandboxes/$A/boot.log" 2>/dev/null && leaked+=" logs"
    sbx inspect "$A" | grep -qF "$CANARY" && leaked+=" inspect"
    [[ -n "$(guest "$A" sh -c "grep -rlsF '$CANARY' / --exclude-dir=proc --exclude-dir=sys --exclude-dir=dev 2>/dev/null | head -1")" ]] && leaked+=" guest"
    check "a secret in the caller's environment reaches no runtime process, log, or guest" test -z "$leaked"
    skip "host services on the NAT gateway" "reachable by design; see docs/trust-model.md"
fi

if want identity; then
    echo ""
    echo "=== Phase: identity ==="
    ssh-keygen -q -t ed25519 -N '' -C "coop-test-$RUN" -f "$KEY"
    : >"$KNOWN"
    enroll "$A"
    check "strict SSH against the key read over the native channel" test "$(pinned "$A" echo ok)" = ok
    # shellcheck disable=SC2016 # Expand in the guest.
    check "no agent in the SSH session" test "$(pinned "$A" 'echo ${SSH_AUTH_SOCK:-none}')" = none
    fwd="$(
        eval "$(ssh-agent -s)" >/dev/null
        ssh -F /dev/null -i "$KEY" -o IdentitiesOnly=yes -o StrictHostKeyChecking=yes -o UserKnownHostsFile="$KNOWN" \
            -o GlobalKnownHostsFile=/dev/null -o HostKeyAlias="$A" -o BatchMode=yes -o ForwardAgent=yes -o LogLevel=ERROR \
            "root@$(ip4 "$A")" 'echo ${SSH_AUTH_SOCK:-none}'
        ssh-agent -k >/dev/null
    )"
    check "sshd refuses to forward even a throwaway agent" test "$fwd" = none
    key1="$(guest "$A" cut -d' ' -f1-2 /etc/ssh/ssh_host_ed25519_key.pub)"
    sbx stop "$A"
    boot "$A"
    check "host key is stable across restart" test "$(guest "$A" cut -d' ' -f1-2 /etc/ssh/ssh_host_ed25519_key.pub)" = "$key1"
    check "strict SSH works after restart" test "$(pinned "$A" echo ok)" = ok
    guest "$A" sh -c 'rm -f /etc/ssh/ssh_host_* && ssh-keygen -A >/dev/null && systemctl restart ssh'
    check "a replaced host key is rejected" refuses pinned "$A" true
    enroll "$A"
fi

if want persistence; then
    echo ""
    echo "=== Phase: persistence ==="
    m="$(openssl rand -hex 8)"
    guest "$A" sh -c "echo $m > /var/lib/coop-test/marker && docker volume create coopvol >/dev/null && docker run --rm -v coopvol:/v alpine:3.20 sh -c 'echo $m > /v/m'"
    before="$(verify "$A" | jq -c '{machine_id, ssh_host_key}')"
    lost=""
    ips=()
    for ((c = 1; c <= CYCLES; c++)); do
        u="$(openssl rand -hex 4)"
        # An unsynced write immediately before a normal stop must survive it.
        guest "$A" sh -c "echo $u > /var/lib/coop-test/unsynced"
        sbx stop "$A"
        boot "$A" || { lost+=" boot@$c"; break; }
        [[ "$(guest "$A" cat /var/lib/coop-test/marker)" == "$m" ]] || lost+=" file@$c"
        [[ "$(guest "$A" cat /var/lib/coop-test/unsynced)" == "$u" ]] || lost+=" unsynced@$c"
        [[ "$(guest "$A" docker run --rm -v coopvol:/v alpine:3.20 cat /v/m)" == "$m" ]] || lost+=" docker@$c"
        [[ "$(verify "$A" | jq -c '{machine_id, ssh_host_key}')" == "$before" ]] || lost+=" identity@$c"
        ips+=("$(ip4 "$A")")
    done
    if [[ -z "$lost" ]]; then
        pass "$CYCLES stop/start cycles keep files, an unsynced pre-stop write, Docker state, machine-id, and host key"
    else
        fail "$CYCLES stop/start cycles keep files, an unsynced pre-stop write, Docker state, machine-id, and host key" "lost:$lost"
    fi
    check "the address is stable across restarts" test "$(printf '%s\n' "${ips[@]}" | sort -u | wc -l | tr -d ' ')" = 1
    n="$(name fresh)"
    create "$n"
    boot "$n"
    check "a new sandbox from the same image gets its own identity" \
        test "$(verify "$n" | jq -c '{machine_id, ssh_host_key}')" != "$before"
    sbx stop "$n"
    sbx delete "$n" --owner "$RUN"
fi

if want resources; then
    echo ""
    echo "=== Phase: resources ==="
    mid="$(guest "$A" cat /etc/machine-id)"
    sbx stop "$A"
    sbx set "$A" --cpus 2 --memory-mib 4096 >/dev/null
    boot "$A"
    v="$(verify "$A")"
    # The runtime adds one vCPU of its own.
    check "CPU change applies at the next start" test "$(jq -r .nproc <<<"$v")" = 3
    check "memory change applies at the next start" test "$(jq -r .mem_kb <<<"$v")" -lt $((4200 * 1024))
    check "the disk keeps its identity" test "$(jq -r .machine_id <<<"$v")" = "$mid"
    check "set refuses a running sandbox" refuses sbx set "$A" --cpus 1
    sbx stop "$A"
    sbx set "$A" --cpus 4 --memory-mib 8192 >/dev/null
    boot "$A"
fi

if want growth; then
    echo ""
    echo "=== Phase: growth ==="
    g="$(name grow)"
    create "$g" 2 2048 8
    boot "$g"
    m="$(openssl rand -hex 6)"
    guest "$g" sh -c "echo $m > /var/lib/coop-test/marker"
    key="$(guest "$g" cat /etc/ssh/ssh_host_ed25519_key.pub)"
    sbx stop "$g"
    check "grow refuses to shrink" refuses sbx grow "$g" --disk-gib 4
    check "8 -> 32 GiB grows offline" sbx grow "$g" --disk-gib 32
    boot "$g"
    check "the guest filesystem is 32 GiB" test "$(guest "$g" df -B1 --output=size / | tail -1 | xargs)" -ge $((31 * 1024 * 1024 * 1024))
    check "data and host key survive the grow" test "$(guest "$g" cat /var/lib/coop-test/marker)$(guest "$g" cat /etc/ssh/ssh_host_ed25519_key.pub)" = "$m$key"
    sbx stop "$g"
    sbx delete "$g" --owner "$RUN"
fi

if want snapshots; then
    echo ""
    echo "=== Phase: snapshots ==="
    guest "$A" sh -c 'echo A > /var/lib/coop-test/state && docker volume create cp >/dev/null && docker run --rm -v cp:/v alpine:3.20 sh -c "echo A > /v/s"'
    mid="$(guest "$A" cat /etc/machine-id)"
    # Adversarial: a root guest disables its own `rm`; the identity reset must
    # not depend on the guest's tools.
    guest "$A" sh -c 'cp /usr/bin/rm /usr/bin/rm.coop-test && cp /usr/bin/true /usr/bin/rm && sync'
    sbx stop "$A"
    check "commit saves the stopped disk" sbx commit "$A" snap
    check "commit refuses an existing name without --replace" refuses sbx commit "$A" snap
    boot "$A"
    guest "$A" sh -c 'echo B > /var/lib/coop-test/state && docker run --rm -v cp:/v alpine:3.20 sh -c "echo B > /v/s" && echo x > /var/lib/coop-test/after && sync'
    sbx stop "$A"
    gen="$(sbx inspect "$A" | jq .record.diskGeneration)"
    check "restore replaces the disk" sbx restore "$A" snap
    check "restore bumps the disk generation" test "$(sbx inspect "$A" | jq .record.diskGeneration)" -gt "$gen"
    boot "$A"
    check "files and Docker volumes are back at the committed state" \
        test "$(guest "$A" cat /var/lib/coop-test/state)$(guest "$A" docker run --rm -v cp:/v alpine:3.20 cat /v/s)" = AA
    check "writes after the commit are gone" refuses guest "$A" test -e /var/lib/coop-test/after
    check "the restored disk generated a fresh identity, despite the guest's disabled rm" \
        test "$(guest "$A" cat /etc/machine-id)" != "$mid"
    guest "$A" sh -c 'cp /usr/bin/rm.coop-test /usr/bin/rm'
    c="$(name clone)"
    check "a new sandbox can be created from a committed disk" \
        sbx create "$c" --from-disk snap --cpus 2 --memory-mib 2048 --disk-gib 20 --owner "$RUN"
    boot "$c"
    check "it is grown to the requested size" test "$(guest "$c" df -B1 --output=size / | tail -1 | xargs)" -ge $((19 * 1024 * 1024 * 1024))
    check "it has its own identity" test "$(guest "$c" cat /etc/machine-id)" != "$mid"
    sbx stop "$c"
    sbx delete "$c" --owner "$RUN"
    sbx disk delete snap
    enroll "$A" 2>/dev/null || true
fi

if want recovery; then
    echo ""
    echo "=== Phase: recovery ==="
    r="$(name crash)"
    create "$r"
    # Owner killed during boot: a crashed state that start recovers.
    "$SANDBOX" run --root "$ROOT" "$r" >/dev/null 2>&1 &
    pid=$!
    sleep 0.3
    kill -9 "$pid" 2>/dev/null
    wait "$pid" 2>/dev/null
    sleep 1
    st="$(state "$r")"
    check "an owner killed during boot leaves a stopped or crashed sandbox" test "$st" = stopped -o "$st" = crashed
    check "start recovers it" boot "$r"
    # Owner killed while running: the VM dies with it and launchd respawns it.
    m="$(openssl rand -hex 4)"
    guest "$r" sh -c "echo $m > /var/lib/coop-test/crash && sync"
    old="$(sbx inspect "$r" | jq .live.pid)"
    kill -9 "$old"
    respawned=0
    for _ in $(seq 60); do
        now="$(sbx inspect "$r" | jq -r '.live.pid // empty')"
        [[ -n "$now" && "$now" != "$old" && "$(state "$r")" == running ]] && { respawned=1; break; }
        sleep 1
    done
    check "launchd respawns a killed owner" test "$respawned" = 1
    ready "$r"
    check "synced data survives the crash" test "$(guest "$r" cat /var/lib/coop-test/crash)" = "$m"
    # A client killed mid-stop does not stop the halt.
    "$SANDBOX" stop --root "$ROOT" "$r" >/dev/null 2>&1 &
    sleep 0.05
    kill -9 $! 2>/dev/null
    for _ in $(seq 100); do [[ "$(state "$r")" == stopped ]] && break; sleep 0.2; done
    sbx stop "$r" >/dev/null 2>&1
    check "a stop whose client was killed still ends stopped" test "$(state "$r")" = stopped
    # A create that never committed is removed by reconcile.
    mkdir -p "$ROOT/sandboxes/$(name half)"
    touch "$ROOT/sandboxes/$(name half)/rootfs.ext4"
    check "reconcile removes an uncommitted create" jq -e 'any(.action == "removed-uncommitted-create")' <<<"$(sbx reconcile)"
    check "delete refuses another owner" refuses sbx delete "$r" --owner someone-else
    check "delete removes the sandbox" sbx delete "$r" --owner "$RUN"
fi

if want concurrency; then
    echo ""
    echo "=== Phase: concurrency ==="
    sbx stop "$A"; sbx stop "$B"
    names=()
    for ((i = 1; i <= CONCURRENT; i++)); do
        names+=("$(name "c$i")")
        create "$(name "c$i")"
    done
    for n in "${names[@]}"; do sbx start "$n" >/dev/null & done
    wait
    all=1
    for n in "${names[@]}"; do ready "$n" || all=0; done
    check "$CONCURRENT sandboxes boot in parallel" test "$all" = 1
    check "each has its own address" test "$(for n in "${names[@]}"; do ip4 "$n"; done | sort -u | wc -l | tr -d ' ')" = "$CONCURRENT"
    check "each has its own subnet" test "$(for n in "${names[@]}"; do sbx inspect "$n" | jq -r '.effective.interfaces[0].network'; done | sort -u | wc -l | tr -d ' ')" = "$CONCURRENT"
    first="${names[0]}"
    leaks=0
    for n in "${names[@]:1}"; do
        t4="$(ip4 "$n")"
        guest "$first" sh -c "timeout 3 nc -z -w2 $t4 22 || ping -c1 -W2 $t4 >/dev/null 2>&1" && leaks=$((leaks + 1))
    done
    check "none reaches another" test "$leaks" = 0
    for n in "${names[@]}"; do sbx stop "$n"; sbx delete "$n" --owner "$RUN"; done
fi

summary
