#!/usr/bin/env python3
"""Expose an ephemeral CI KVM host through an authenticated private SSH tunnel."""
import base64
import argparse
import getpass
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile
import time
import urllib.error
import urllib.request

ROOT=Path.home()/'.lumen-kvm-host-ci3'
TOKEN=REPO=BRANCH=RUN_ID=SERVER=None
PORT=49734
STATUS_PATH='.ci/lumen-host-ci3-status.json'
START=time.time()
EXPIRES=START+90*60

# Ubuntu 24.04's headless emulator still loads PulseAudio and the Qt/X11
# libraries. -no-audio/-no-window do not remove these ELF dependencies.
HOST_PACKAGES=(
    'openssh-server','libpulse0','libnss3','libasound2t64','libdbus-1-3',
    'libfontconfig1','libgl1','libegl1','libx11-6','libx11-xcb1',
    'libxcb1','libxcb-cursor0','libxcomposite1','libxcursor1','libxdamage1',
    'libxext6','libxfixes3','libxi6','libxkbcommon0','libxrandr2',
    'libxrender1','libxtst6',
)


def install_host_dependencies(root,deadline=450,attempts=3):
    """Bounded official HTTPS apt bootstrap; never rewrites system mirrors/DNS.

    A separate signed source list and apt index/cache avoid stale or broken
    runner mirror configuration. Network failure retains logs and aborts
    before any SSH daemon, key or reverse tunnel is created.
    """
    root=Path(root)
    root.mkdir(parents=True,exist_ok=True)
    keyring=Path('/usr/share/keyrings/ubuntu-archive-keyring.gpg')
    release={}
    for line in Path('/etc/os-release').read_text().splitlines():
        if '=' in line:
            key,value=line.split('=',1)
            release[key]=value.strip('"')
    if release.get('ID')!='ubuntu' or release.get('VERSION_CODENAME')!='noble':
        raise RuntimeError('Third CI host dependencies require Ubuntu 24.04 noble')
    if not keyring.is_file():
        raise RuntimeError('Ubuntu archive signing keyring is unavailable')
    apt_work=Path(tempfile.mkdtemp(prefix='lumen-ci3-apt-',dir='/tmp'))
    # This directory contains public apt metadata only. _apt needs traversal
    # permission; the SSH keys and logs remain inside the private host ROOT.
    apt_work.chmod(0o755)
    for relative in ('lists','lists/partial','archives','archives/partial'):
        (apt_work/relative).mkdir(mode=0o755)
    source=apt_work/'ubuntu.list'
    source.write_text('\n'.join([
        'deb [signed-by='+str(keyring)+'] https://archive.ubuntu.com/ubuntu noble main restricted universe multiverse',
        'deb [signed-by='+str(keyring)+'] https://archive.ubuntu.com/ubuntu noble-updates main restricted universe multiverse',
        'deb [signed-by='+str(keyring)+'] https://security.ubuntu.com/ubuntu noble-security main restricted universe multiverse',
        '']))
    source.chmod(0o644)
    options=[
        '-o','Dir::Etc::sourcelist='+str(source),
        '-o','Dir::Etc::sourceparts=-',
        '-o','Dir::State::status=/var/lib/dpkg/status',
        '-o','Dir::State::lists='+str(apt_work/'lists'),
        '-o','Dir::Cache::archives='+str(apt_work/'archives'),
        '-o','Acquire::Retries=1',
        '-o','Acquire::Languages=none',
        '-o','Acquire::ForceIPv4=true',
        '-o','Acquire::https::Timeout=20',
        '-o','Acquire::http::Timeout=20',
        '-o','APT::Update::Error-Mode=any',
        '-o','DPkg::Lock::Timeout=30',
    ]
    receipt=dict(schema='lumen-ci3-apt-bootstrap-v1',passed=False,
                 system_run_verified=False,apt_work=str(apt_work),
                 source=str(source),sources_sha256=hashlib.sha256(source.read_bytes()).hexdigest(),
                 packages=list(HOST_PACKAGES),attempts=[],started=time.time())
    until=time.monotonic()+deadline

    def persist():
        path=root/'host-dependencies.json'
        path.write_text(json.dumps(receipt,indent=2)+'\n')
        path.chmod(0o600)

    def command(label,argv,timeout):
        remaining=until-time.monotonic()
        if remaining<=0:
            raise TimeoutError('Bounded host dependency bootstrap deadline exceeded')
        log=root/(label+'.log')
        budget=min(timeout,remaining)
        # The root-owned timeout supervisor signals the entire apt/dpkg
        # process group, rather than leaving children when sudo times out.
        supervisor=['timeout','--signal=TERM','--kill-after=5s',f'{budget:.3f}s']
        bounded=([argv[0],*supervisor,*argv[1:]] if argv[0]=='sudo'
                 else [*supervisor,*argv])
        row=dict(label=label,command=bounded,log=str(log))
        receipt['attempts'].append(row)
        persist()
        with log.open('wb') as stream:
            try:
                result=subprocess.run(bounded,stdin=subprocess.DEVNULL,
                    stdout=stream,stderr=subprocess.STDOUT,
                    timeout=budget+10,check=False)
                row['returncode']=result.returncode
            except subprocess.TimeoutExpired:
                row['returncode']=124
        row['sha256']=hashlib.sha256(log.read_bytes()).hexdigest()
        persist()
        print(json.dumps(dict(event='host_dependency_command',label=label,
            status='passed' if row['returncode']==0 else 'failed',
            returncode=row['returncode'])),flush=True)
        if row['returncode']:
            # APT uses only the public official sources above. Never print
            # environment values, authentication keys or SSH/tunnel logs.
            with log.open('rb') as stream:
                stream.seek(max(0,log.stat().st_size-8192))
                tail=stream.read(8192).decode('utf-8',errors='replace')
            print(json.dumps(dict(event='host_dependency_log_tail',label=label,
                                  limit_bytes=8192,output=tail)),flush=True)
        if row['returncode'] in (124,137):
            # An interrupted installation is never retried automatically.
            raise TimeoutError('Owned host dependency command timed out: '+label)
        return row['returncode']==0

    try:
        for attempt in range(1,attempts+1):
            update=command(f'apt-update-{attempt}',
                           ['sudo','apt-get',*options,'update','-qq'],90)
            if update and command(f'apt-install-{attempt}',
                    ['sudo','apt-get',*options,'install','-y','--no-install-recommends',*HOST_PACKAGES],120):
                if not command('dpkg-verify',['dpkg-query','-W',
                        '-f=${binary:Package}\t${db:Status-Status}\t${Version}\n',*HOST_PACKAGES],20):
                    raise RuntimeError('Dependency package query failed')
                verify=root/'dpkg-verify.log'
                installed={line.split('\t')[0].split(':')[0]:line.split('\t')[1]
                           for line in verify.read_text().splitlines()
                           if len(line.split('\t'))==3}
                if any(installed.get(package)!='installed' for package in HOST_PACKAGES):
                    raise RuntimeError('Host dependency package remains uninstalled')
                receipt.update(passed=True,completed=time.time(),installed=installed)
                persist()
                print(json.dumps(dict(event='host_dependency_bootstrap',status='passed',
                    commands=len(receipt['attempts']),packages=len(HOST_PACKAGES))),flush=True)
                return receipt
            if attempt<attempts and until-time.monotonic()>3:
                time.sleep(3)
        raise RuntimeError('Official HTTPS Ubuntu dependency bootstrap exhausted bounded retries')
    except BaseException as error:
        receipt.update(passed=False,error=repr(error),completed=time.time())
        persist()
        print(json.dumps(dict(event='host_dependency_bootstrap',status='failed',
            commands=len(receipt['attempts']),exception_type=type(error).__name__,
            error=str(error)[:1024])),flush=True)
        raise


def emulator_ldd_preflight(sdk_roots,output=None):
    """Inspect real host dependencies, including the launcher's bundled paths.

    This is a loader check only; it neither boots Android nor claims KVM,
    application, radio or system-flow validation. Explicit SDK roots must
    contain an emulator so a typo cannot silently become a skipped check.
    With output=None the inspection does not create or modify any file.
    """
    roots=sorted({Path(root).resolve() for root in sdk_roots},key=str)
    receipt=dict(schema='lumen-ci-emulator-loader-v1',passed=False,
                 system_run_verified=False,created=time.time(),checks=[])
    for sdk in roots:
        emulator=sdk/'emulator'
        bundled=[emulator/'lib64',emulator/'lib64/qt/lib',
                 emulator/'lib64/gles_swiftshader',emulator/'lib64/swiftshader']
        env=dict(os.environ)
        # Match the official emulator launcher's library search path. A raw
        # ldd of qemu without these paths incorrectly rejects bundled Qt.
        env['LD_LIBRARY_PATH']=':'.join(str(p) for p in bundled if p.is_dir())
        env['LC_ALL']='C'
        for relative in ('emulator','qemu/linux-x86_64/qemu-system-x86_64'):
            binary=emulator/relative
            check=dict(path=str(binary),passed=False,
                       library_path=env['LD_LIBRARY_PATH'])
            receipt['checks'].append(check)
            if not binary.is_file() or binary.is_symlink():
                check['error']='Required emulator ELF is missing or linked'
                continue
            with binary.open('rb') as stream:
                check['sha256']=hashlib.file_digest(stream,'sha256').hexdigest()
            try:
                result=subprocess.run(['ldd',str(binary)],env=env,
                    stdout=subprocess.PIPE,stderr=subprocess.STDOUT,
                    text=True,timeout=30,check=False)
                check.update(returncode=result.returncode,output=result.stdout,
                             missing=re.findall(r'^\s*(\S+)\s+=>\s+not found\s*$',
                                                result.stdout,re.MULTILINE))
                check['passed']=result.returncode==0 and not check['missing']
            except (OSError,subprocess.TimeoutExpired) as error:
                check['error']=repr(error)
    receipt['passed']=bool(roots) and all(row['passed'] for row in receipt['checks'])
    if not roots:
        receipt['error']='No installed emulator SDK was selected for inspection'
    if output is not None:
        output=Path(output)
        output.parent.mkdir(parents=True,exist_ok=True)
        output.write_text(json.dumps(receipt,indent=2)+'\n')
        output.chmod(0o600)
    if not receipt['passed']:
        raise RuntimeError('Emulator dependency preflight failed; inspect '+
                           (str(output) if output is not None else 'the selected SDK paths'))
    return receipt


def api(method,url,body=None):
    data=json.dumps(body).encode() if body is not None else None
    request=urllib.request.Request(url,data=data,method=method,
        headers={'Authorization':'Bearer '+TOKEN,'Accept':'application/vnd.github+json',
                 'X-GitHub-Api-Version':'2022-11-28','Content-Type':'application/json'})
    with urllib.request.urlopen(request,timeout=30) as response:
        return json.load(response)


def publish(status):
    url=f'https://api.github.com/repos/{REPO}/contents/{STATUS_PATH}'
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
    global TOKEN,REPO,BRANCH,RUN_ID,SERVER,START,EXPIRES
    TOKEN=os.environ['GH_TOKEN']
    REPO=os.environ['GITHUB_REPOSITORY']
    BRANCH=os.environ['GITHUB_REF_NAME']
    RUN_ID=os.environ['GITHUB_RUN_ID']
    SERVER=os.environ['TASK_SERVER']
    START=time.time()
    EXPIRES=START+90*60
    ROOT.mkdir(mode=0o700,exist_ok=True)
    if not Path('/dev/kvm').exists():
        raise RuntimeError('This CI host does not provide KVM')
    subprocess.run(['sudo','chmod','0666','/dev/kvm'],check=True)
    install_host_dependencies(ROOT/'bootstrap')
    sdk_roots=[Path(value) for key in ('ANDROID_HOME','ANDROID_SDK_ROOT')
               if (value:=os.environ.get(key)) and (Path(value)/'emulator/emulator').is_file()]
    if sdk_roots:
        emulator_ldd_preflight(sdk_roots,ROOT/'emulator-dependencies.json')
    else:
        # Fresh official packages are downloaded later by the private runtime.
        # Do not claim an ELF check before those bytes exist.
        (ROOT/'emulator-dependencies.json').write_text(json.dumps(dict(
            schema='lumen-ci-emulator-loader-v1',status='not_installed',passed=False,
            system_run_verified=False,checks=[],
            limitation='Run --preflight-only after the official emulator is installed.'),indent=2)+'\n')
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
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--preflight-only',action='store_true')
    parser.add_argument('--sdk-root',action='append',type=Path,default=[])
    parser.add_argument('--output',type=Path)
    arguments=parser.parse_args()
    if arguments.preflight_only:
        if not arguments.sdk_root or not arguments.output:
            parser.error('--preflight-only requires --sdk-root and --output')
        receipt=emulator_ldd_preflight(arguments.sdk_root,arguments.output)
        print(json.dumps(dict(passed=receipt['passed'],checks=len(receipt['checks']),
                              system_run_verified=False,output=str(arguments.output))))
    else:
        if arguments.sdk_root or arguments.output:
            parser.error('--sdk-root and --output require --preflight-only')
        main()
