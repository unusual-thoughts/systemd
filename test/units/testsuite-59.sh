#!/usr/bin/env bash
set -ex

systemd-analyze log-level debug

# Multiple level process tree, parent process stays up
cat >/tmp/test59-exit-cgroup.sh <<EOF
#!/usr/bin/env bash
set -eux

# process tree: systemd -> sleep
sleep infinity &
disown

# process tree: systemd -> bash -> bash -> sleep
((sleep infinity); true) &

# process tree: systemd -> bash -> sleep
sleep infinity
EOF
chmod +x /tmp/test59-exit-cgroup.sh

# service should be stopped cleanly
(sleep 1; systemctl stop one) &
systemd-run --wait --unit=one -p ExitType=cgroup /tmp/test59-exit-cgroup.sh

# service should exit uncleanly
(sleep 1; systemctl kill --signal 9 two) &
! systemd-run --wait --unit=two -p ExitType=cgroup /tmp/test59-exit-cgroup.sh


# Multiple level process tree, parent process exits quickly
cat >/tmp/test59-exit-cgroup-parentless.sh <<EOF
#!/usr/bin/env bash
set -eux

# process tree: systemd -> sleep
sleep infinity &

# process tree: systemd -> bash -> sleep
((sleep infinity); true) &
EOF
chmod +x /tmp/test59-exit-cgroup-parentless.sh

# service should be stopped cleanly
(sleep 1; systemctl stop three) &
systemd-run --wait --unit=three -p ExitType=cgroup /tmp/test59-exit-cgroup-parentless.sh

# service should exit uncleanly
(sleep 1; systemctl kill --signal 9 four) &
! systemd-run --wait --unit=four -p ExitType=cgroup /tmp/test59-exit-cgroup-parentless.sh


# Multiple level process tree, parent process exits uncleanly but last process exits cleanly
cat >/tmp/test59-exit-cgroup-clean.sh <<EOF
#!/usr/bin/env bash
set -eux

# process tree: systemd -> bash -> sleep
(sleep 1; true) &

exit 255
EOF
chmod +x /tmp/test59-exit-cgroup-clean.sh

# service should exit cleanly and be garbage-collected
systemd-run --wait --unit=five -p ExitType=cgroup /tmp/test59-exit-cgroup-clean.sh


# Multiple level process tree, parent process exits cleanly but last process exits uncleanly
cat >/tmp/test59-exit-cgroup-unclean.sh <<EOF
#!/usr/bin/env bash
set -eux

# process tree: systemd -> bash -> sleep
(sleep 1; exit 255) &
EOF
chmod +x /tmp/test59-exit-cgroup-unclean.sh

# service should exit uncleanly after 1 second
! systemd-run --wait --unit=six -p ExitType=cgroup /tmp/test59-exit-cgroup-unclean.sh

systemd-analyze log-level info

echo OK > /testok

exit 0
