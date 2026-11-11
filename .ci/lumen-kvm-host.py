#!/usr/bin/env python3
"""Expose an ephemeral CI KVM host through an authenticated private SSH tunnel."""
import base64
import getpass
import json
import os
from pathlib import Path
import subprocess
import time
import urllib.error
import urllib.request

ROOT=Path.home()/'.lumen-kvm-host'
ROOT.mkdir(mode=0o700,exist_ok=True)
TOKEN=os.environ['GH_TOKEN']
REPO=os.environ['GITHUB_REPOSITORY']
BRANCH=os.environ['GITHUB_REF_NAME']
RUN_ID=os.environ['GITHUB_RUN_ID']
SERVER=os.environ['TASK_SERVER']
PORT=49730
START=time.time()
EXPIRES=START+70*60


def api(method,url,body=None):
    data=json.dumps(body).encode() if body is not None else None
    request=urllib.request.Request(url,data=data,method=method,
        headers={'Authorization':'Bearer '+TOKEN,'Accept':'application/vnd.github+json',
                 'X-GitHub-Api-Version':'2022-11-28','Content-Type':'application/json'})
    with urllib.request.urlopen(request,timeout=30) as response:
        return json.load(response)


def publish(status):
    url=f'https://api.github.com/repos/{REPO}/contents/.ci/lumen-host-status.json'
    sha=None
    try:
        old=api('GET',url+'?ref='+BRANCH)
        sha=old['sha']
    except urllib.error.HTTPError as error:
        if error.code!=404:
            raise
    state=dict(status=status,run_id=RUN_ID,updated=time.time(),expires=EXPIRES,
               runner_user=getpass.getuser(),reverse_port=PORT,sshd_port=22222,
               stop_file=str(ROOT/'stop'),
               runner_public_key=(ROOT/'runner-key.pub').read_text().strip(),
               host_public_key=(ROOT/'host-key.pub').read_text().strip(),
               kvm_present=Path('/dev/kvm').exists(),cpu_count=os.cpu_count(),
               meminfo=Path('/proc/meminfo').read_text())
    body=dict(message='Record ephemeral validation host state',branch=BRANCH,
              content=base64.b64encode((json.dumps(state,indent=2)+'\n').encode()).decode())
    if sha:
        body['sha']=sha
    api('PUT',url,body)
    print(json.dumps({k:state[k] for k in ('status','run_id','kvm_present','cpu_count')}),flush=True)


def main():
    if not Path('/dev/kvm').exists():
        raise RuntimeError('This CI host does not provide KVM')
    subprocess.run(['sudo','chmod','0666','/dev/kvm'],check=True)
    subprocess.run(['sudo','apt-get','update','-qq'],check=True)
    subprocess.run(['sudo','apt-get','install','-y','--no-install-recommends','openssh-server'],check=True)
    for name in ('runner-key','host-key'):
        subprocess.run(['ssh-keygen','-q','-t','ed25519','-N','','-f',str(ROOT/name)],check=True)
    (ROOT/'authorized_keys').write_text(os.environ['CLIENT_PUBLIC_KEY'].strip()+'\n')
    (ROOT/'authorized_keys').chmod(0o600)
    (ROOT/'known_hosts').write_text(os.environ['TASK_SERVER_HOST_KEY'].strip()+'\n')
    config=ROOT/'sshd.conf'
    config.write_text('\n'.join([
        'Port 22222','ListenAddress 127.0.0.1',f'HostKey {ROOT}/host-key',
        f'AuthorizedKeysFile {ROOT}/authorized_keys',f'PidFile {ROOT}/sshd.pid',
        'PasswordAuthentication no','KbdInteractiveAuthentication no','PermitRootLogin no',
        'PubkeyAuthentication yes','UsePAM yes',f'AllowUsers {getpass.getuser()}',
        'AllowTcpForwarding yes','X11Forwarding no','LogLevel VERBOSE','']) )
    subprocess.run(['sudo','mkdir','-p','/run/sshd'],check=True)
    with (ROOT/'sshd.log').open('ab',buffering=0) as log:
        sshd=subprocess.Popen(['sudo','/usr/sbin/sshd','-D','-e','-f',str(config)],stdout=log,stderr=log)
    publish('awaiting_restricted_forward_key')
    command=['ssh','-N','-T','-i',str(ROOT/'runner-key'),'-o','IdentitiesOnly=yes',
             '-o','BatchMode=yes','-o','StrictHostKeyChecking=yes','-o','ConnectTimeout=10',
             '-o','UserKnownHostsFile='+str(ROOT/'known_hosts'),'-o','ExitOnForwardFailure=yes',
             '-o','ServerAliveInterval=15','-o','ServerAliveCountMax=3','-p','2222',
             '-R',f'127.0.0.1:{PORT}:127.0.0.1:22222',f'aiuser@{SERVER}']
    tunnel=None
    published=False
    try:
        with (ROOT/'tunnel.log').open('ab',buffering=0) as log:
            while time.time()<EXPIRES and not (ROOT/'stop').exists():
                if sshd.poll() is not None:
                    raise RuntimeError('Owned CI sshd exited')
                if tunnel is None or tunnel.poll() is not None:
                    tunnel=subprocess.Popen(command,stdout=log,stderr=log)
                    time.sleep(5)
                if tunnel.poll() is None and not published:
                    publish('forwarding')
                    published=True
                time.sleep(5)
    finally:
        if tunnel and tunnel.poll() is None:
            tunnel.terminate()
            tunnel.wait(timeout=15)
        sshd.terminate()
        publish('closed')


if __name__=='__main__':
    main()
