# Linux smoke test: pair, health, exec, upload, audit with two HOME directories. Needs /out/tcs (from package-linux.sh build), ssh-keygen, python3.
set -u
cp /out/tcs /usr/local/bin/tcs; cp /out/tcs /usr/local/bin/tcsd
command -v python3 >/dev/null || (apt-get install -y -qq python3 >/dev/null 2>&1)
rm -rf /h; mkdir -p /h/ctl /h/srv
HOME=/h/ctl; export HOME; mkdir -p -m 700 $HOME/.ssh; ssh-keygen -q -t ed25519 -N "" -f $HOME/.ssh/id_ed25519 2>&1 | tail -1
HOME=/h/srv; mkdir -p -m 700 $HOME/.ssh; ssh-keygen -q -t ed25519 -N "" -f $HOME/.ssh/tcs_host_key 2>&1 | tail -1
(HOME=/h/srv tcsd pair --port 10199 > /h/srv.log 2>&1 &)
sleep 3; cat /h/srv.log | head -5
CODE=$(grep -o 'tcs pair [^ ]* [0-9]*' /h/srv.log | awk '{print $4}')
echo code=$CODE
HOME=/h/ctl tcs pair 127.0.0.1 $CODE --port 10199 < /dev/null 2>&1 | tail -4
echo "--- health"; HOME=/h/ctl tcs 127.0.0.1 health --port 10199 2>&1 | tail -3
echo "--- exec"; HOME=/h/ctl tcs 127.0.0.1 exec "print(1+1)" --port 10199 2>&1 | tail -3
echo "--- perms"; ls -ld /h/ctl/.ssh /h/srv/.ssh; ls /h/srv/.ssh /h/ctl/.ssh
echo "--- audit"; HOME=/h/srv tcsd audit --tail 3 2>&1 | tail -3
tcsd --help | grep -n "ssh\|python3" | head -4

echo "--- upload/timeout/data"
echo hi > /h/up.txt
HOME=/h/ctl tcs 127.0.0.1 upload /h/up.txt --port 10199 2>&1 | tail -2
(HOME=/h/srv tcsd --port 10199 > /h/srv2.log 2>&1 &) ; sleep 1
HOME=/h/ctl tcs 127.0.0.1 exec "import time; time.sleep(2); print('slow-ok')" --port 10199 2>&1 | tail -2
ls /h/srv/.local/share/TCS/data 2>&1 | head

pkill tcsd
