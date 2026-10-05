"""Opt-in exact-pin alert-source and memory proof using isolated Docker fixtures."""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import os
import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
IMAGES = json.loads((ROOT / "deploy/images.json").read_text())
ULTRAFEEDER_PIN = IMAGES["ultrafeeder"]
DUMP978_PIN = IMAGES["dump978"]

READSB_PROBE = r"""
import json,os,socket,subprocess,sys,time,uuid
from pathlib import Path
band,health=sys.argv[1:]
directory=Path('/var/lib/adsb/alert-source')
os.umask(0o027)
assert not any(directory.iterdir())
listener=socket.socket()
port=30005 if band=='1090' else 30978
listener.bind(('127.0.0.1',port));listener.listen();listener.settimeout(8)
started=time.strftime('%Y-%m-%dT%H:%M:%SZ',time.gmtime())
marker={'schema_version':1,'band':band,'generation':str(uuid.uuid4()),
        'started_at':started,'activation_id':'a'*32,'contract_digest':'b'*64}
(directory/'source-marker.json').write_text(json.dumps(marker))
environment={**os.environ,'ALERT_SOURCE_BAND':band,'ALERT_SOURCE_INPUT_PORT':str(port),
             'ALERT_SOURCE_ACTIVATION_ID':'a'*32,'ALERT_SOURCE_CONTRACT_DIGEST':'b'*64}
process=subprocess.Popen(['/usr/local/bin/readsb','--net-only','--quiet',
    f'--net-connector=127.0.0.1,{port},'+('beast_in' if band=='1090' else 'uat_in'),
    '--write-json='+str(directory),'--write-json-every=1','--stats-every=10'],
    stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
connection=None
sequence=0
health_durations_ms=[]

# collect independent kernel observations using the release health script
def check_health():
    started=time.monotonic()
    result=subprocess.run(['/bin/bash','-c',health],env=environment,capture_output=True,text=True,timeout=5)
    elapsed_ms=int((time.monotonic()-started)*1000)
    # require actual completion inside the production timeout
    assert elapsed_ms<5000,elapsed_ms
    health_durations_ms.append(elapsed_ms)
    assert result.returncode==0,(result.stdout,result.stderr)
    state=json.loads((directory/'source-state.json').read_text())
    assert state['schema_version']==2 and state['process_running'] and state['input_connected'],state
    assert state['input_socket'].isdigit(),state
    return state

# wait through the bounded first statistics publication window
def wait_health():
    error=None
    # accept only the contract's ten-to-twenty-second startup window
    for waited in range(12,21):
        # advance only after an incomplete publication
        if waited>12:
            time.sleep(1)
        try:
            return check_health(),waited
        except AssertionError as exc:
            # retain the final bounded diagnostic
            error=exc
    raise error

# generate one physical fixture without external endpoints
def frame(unsupported=False,tisb=False):
    global sequence
    sequence+=1
    # encode one uat downlink fixture
    if band=='978':
        header='02606060' if tisb else ('5840621d' if unsupported else '0040621d')
        return ('-'+header+'00'*14+f';rssi=-20.0;t={time.time():.3f};\n').replace('\\n','\n').encode()
    payload=bytearray.fromhex('8D4840D6F8000000000000000000' if unsupported else '8D4840D6202CC371C32CE0576098')
    # compute one valid type-code-31 crc
    if unsupported:
        crc=0
        # fold each message byte
        for byte in payload[:11]:
            crc^=byte<<16
            # fold each byte bit
            for _ in range(8):
                crc=((crc<<1)^0xFFF409)&0xFFFFFF if crc&0x800000 else (crc<<1)&0xFFFFFF
        payload[-3:]=crc.to_bytes(3,'big')
    raw=(sequence*12000000).to_bytes(6,'big')+b'\xff'+payload
    return b'\x1a3'+raw.replace(b'\x1a',b'\x1a\x1a')

try:
    connection,_=listener.accept()
    # wait for the first complete ten-second decoder statistics period
    time.sleep(12)
    quiet,startup_wait=wait_health()
    startup_stats=json.loads((directory/'stats.json').read_text())
    startup_accepted=startup_stats['total']['remote']['accepted']
    assert sum(startup_accepted)==0,startup_stats['total']['remote']
    snapshots=[]
    # prove first tracked no-position identities
    for _ in range(4):
        connection.sendall(frame());time.sleep(1.2)
        snapshots.append(json.loads((directory/'aircraft.json').read_text()))
    assert any(value['aircraft'] for value in snapshots),snapshots
    tracked=next(value['aircraft'][0] for value in snapshots if value['aircraft'])
    assert 'lat' not in tracked and 'lon' not in tracked,tracked
    before=snapshots[-1]['aircraft'][0]['messages']
    connection.sendall(frame(unsupported=True));time.sleep(1.2)
    unsupported=json.loads((directory/'aircraft.json').read_text())
    assert unsupported['aircraft'][0]['messages']>before,unsupported
    tisb_retained=None
    # prove qualified tisb icao handling for uat
    if band=='978':
        # send enough qualified rebroadcast frames
        for _ in range(3):
            connection.sendall(frame(tisb=True));time.sleep(1.1)
        rebroadcast=json.loads((directory/'aircraft.json').read_text())
        tisb_retained=any(row['hex']=='606060' and row['type']=='tisb_icao' for row in rebroadcast['aircraft'])
        assert tisb_retained,rebroadcast
    active=check_health()
    assert active['input_socket']==quiet['input_socket'] and active['input_bytes']>quiet['input_bytes'],active
    listeners=subprocess.run(['/usr/bin/ss','-Hlntp'],check=True,capture_output=True,text=True,timeout=2).stdout
    readsb_listeners=[line for line in listeners.splitlines() if f'pid={process.pid},' in line]
    assert not readsb_listeners,readsb_listeners
    # stress the isolated connector under the fixed source cap
    for _ in range(5000):
        connection.sendall(frame())
    time.sleep(12)
    stats=json.loads((directory/'stats.json').read_text())
    assert sum(stats['total']['remote']['accepted'])>=5000,stats['total']['remote']
    rss=int(next(line.split()[1] for line in Path(f'/proc/{process.pid}/status').read_text().splitlines() if line.startswith('VmRSS:')))
    assert rss<65536,rss
    mode=oct((directory/'source-state.json').stat().st_mode&0o777)
    assert mode=='0o640',mode
    result={'band':band,'first_tracked_message':next(index+1 for index,value in enumerate(snapshots) if value['aircraft']),
        'no_position':True,'unsupported_counter_progress':True,'tisb_icao_retained':tisb_retained,
        'kernel_socket_stable':True,'kernel_bytes_progress':True,
        'readsb_listening_tcp_ports':[],'alternative_aircraft_ingress':False,
        'empty_output_directory_at_start':True,'fresh_generation_marker':True,
        'startup_statistics_wait_seconds':startup_wait,'startup_accepted':startup_accepted,
        'healthcheck_timeout_seconds':5,'healthcheck_invocations':len(health_durations_ms),
        'healthcheck_max_runtime_ms':max(health_durations_ms),
        'accepted':stats['total']['remote']['accepted'],'rss_kib':rss,
        'state_mode':mode,'source_state_schema':2,'network':'none','readonly_root':True,'capabilities':'none'}
    print(json.dumps(result))
finally:
    # close only this fixture connection
    if connection is not None:
        connection.close()
    listener.close()
    # stop only this decoder process
    if process.poll() is None:
        process.terminate()
        try:
            process.wait(timeout=3)
        except subprocess.TimeoutExpired:
            process.kill();process.wait(timeout=3)
"""

NATIVE_PROBE = r"""
import hashlib,json,socket,subprocess,tempfile,time
from pathlib import Path
root=Path(tempfile.mkdtemp(prefix='native-978-'))
listener=socket.socket();listener.bind(('127.0.0.1',0));listener.listen();listener.settimeout(8)
process=subprocess.Popen(['/usr/local/bin/skyaware978','--json-dir',str(root),
    '--connect',f'127.0.0.1:{listener.getsockname()[1]}','--reconnect-interval','1','--history-count','2'],
    stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
connection=None
snapshots=[]
try:
    connection,_=listener.accept()
    time.sleep(2)
    # prove identity before position using native skyaware978
    for _ in range(3):
        connection.sendall(('-0040621d'+'00'*14+f';rssi=-20.0;t={time.time():.3f};\n').encode())
        time.sleep(1.3)
        snapshots.append(json.loads((root/'aircraft.json').read_text()))
    assert any(value['aircraft'] for value in snapshots),snapshots
    tracked=next(value['aircraft'][0] for value in snapshots if value['aircraft'])
    assert tracked['hex']=='40621d' and 'lat' not in tracked and 'lon' not in tracked,tracked
    before=tracked['messages']
    connection.sendall(('-5840621d'+'00'*14+f';rssi=-20.0;t={time.time():.3f};\n').encode())
    time.sleep(1.3)
    unsupported=json.loads((root/'aircraft.json').read_text())
    updated=next(row for row in unsupported['aircraft'] if row['hex']=='40621d')
    assert updated['messages']>before,unsupported
    # prove native qualified rebroadcast retention
    for _ in range(2):
        connection.sendall(('-02606060'+'00'*14+f';rssi=-20.0;t={time.time():.3f};\n').encode())
        time.sleep(1.1)
    rebroadcast=json.loads((root/'aircraft.json').read_text())
    assert any(row['hex']=='606060' and row['type']=='tisb_icao' for row in rebroadcast['aircraft']),rebroadcast
    messages_before_disconnect=rebroadcast['messages']
    writer_time_before=rebroadcast['now']
    connection.close();connection=None
    time.sleep(3)
    disconnected=json.loads((root/'aircraft.json').read_text())
    # show fresh consumer json cannot prove upstream activity
    assert disconnected['now']>writer_time_before,disconnected
    assert disconnected['messages']==messages_before_disconnect,disconnected
    producer_fields={'producer_running','producer_active','input_connected','input_bytes','input_messages'}
    assert producer_fields.isdisjoint(disconnected),disconnected
    rss=int(next(line.split()[1] for line in Path(f'/proc/{process.pid}/status').read_text().splitlines() if line.startswith('VmRSS:')))
    binary_sha=hashlib.sha256(Path('/usr/local/bin/skyaware978').read_bytes()).hexdigest()
    assert rss<65536,rss
    print(json.dumps({'first_tracked_message':next(index+1 for index,value in enumerate(snapshots) if value['aircraft']),
        'no_position':True,'unsupported_counter_progress':True,'tisb_icao_retained':True,
        'json_keys':sorted(disconnected),'producer_coverage_fields_present':False,
        'writer_fresh_while_input_stalled':True,'messages_stable_while_input_stalled':True,
        'rss_kib':rss,'skyaware978_sha256':binary_sha,'network':'none','readonly_root':True,'capabilities':'none'}))
finally:
    # close only this fixture connection
    if connection is not None:
        connection.close()
    listener.close()
    # stop only this native decoder process
    if process.poll() is None:
        process.terminate()
        try:
            process.wait(timeout=3)
        except subprocess.TimeoutExpired:
            process.kill();process.wait(timeout=3)
"""

WORKER_PROBE = r"""
import json,resource,sys,time
from pathlib import Path
from adsb_admin.alert_catalog import AlertCatalog
from adsb_admin.alert_store import AlertStore,MAX_ENCOUNTERS,MAX_MAINTENANCE_NOTIFICATIONS,MAX_PENDING_EVENTS
from adsb_admin.alerts import AlertWorker

# provide a fixed disabled worker configuration
class ConfigStore:
    # keep configuration immutable
    def refresh(self):
        return None
    # return the complete private schema
    def get_private(self):
        return {'schema_version':1,'revision':1,'enabled':False,
            'categories':['military','medical','news'],
            'pushover':{'app_token':'fixture','user_key':'fixture'},
            'smtp':{'host':'example.invalid','port':465,'username':'fixture','password':'fixture',
                'from_address':'fixture@example.invalid','to_address':'fixture@example.invalid'},
            'overrides':[]}

# provide a fixed quiet source projection
class SourceMonitor:
    activation_id='a'*32
    contract_digest='b'*64
    # return no aircraft samples
    def poll(self,**_kwargs):
        return []
    # return one bounded source status
    def status(self):
        return {'activation_id':self.activation_id,'source_contract_digest':self.contract_digest,'bands':{}}

# fail closed if any sender is invoked
def forbidden_dispatch(_job,_settings):
    raise AssertionError('provider dispatch was invoked')

catalog=AlertCatalog.from_paths(Path(sys.argv[1]),Path(sys.argv[2]))
store=AlertStore(Path('/state/alerts.sqlite3'))
created=0
# populate the enforced encounter cap and maximal pending queue
for index in range(MAX_ENCOUNTERS):
    event_id=store.observe_aircraft(hex_id=f'{index+1:06x}',label='bounded fixture',categories=('military',),
        bands={'1090','978'},observed_at=1000.0+index,config_revision=1,
        enabled=index<MAX_PENDING_EVENTS,required_bands={'1090','978'},
        receptions={'1090':'direct','978':'rebroadcast'})
    # count only created delivery events
    if event_id is not None:
        created+=1
assert created==MAX_PENDING_EVENTS,(created,MAX_PENDING_EVENTS)
maintenance_body='M'*8192
# baseline one existing review before adding new notification rows
assert store.observe_maintenance(reported_at=1.0,now=1.0,config_revision=1,smtp_configured=True,
    subject='bounded maintenance fixture',body=maintenance_body) is None
# populate the complete independent maintenance notification cap
for index in range(MAX_MAINTENANCE_NOTIFICATIONS):
    reported_at=float(index+2)
    event_id=store.observe_maintenance(reported_at=reported_at,now=reported_at,config_revision=1,
        smtp_configured=True,subject='bounded maintenance fixture',body=maintenance_body)
    assert event_id is not None
# prove one additional maintenance generation fails observably
try:
    store.observe_maintenance(reported_at=float(MAX_MAINTENANCE_NOTIFICATIONS+2),
        now=float(MAX_MAINTENANCE_NOTIFICATIONS+2),config_revision=1,smtp_configured=True,
        subject='bounded maintenance fixture',body=maintenance_body)
except RuntimeError:
    maintenance_cap_rejected=True
else:
    maintenance_cap_rejected=False
assert maintenance_cap_rejected
maintenance_counts=store._connection.execute(
    "SELECT COUNT(*) AS count, MIN(length(body)) AS minimum_body, MAX(length(body)) AS maximum_body, "
    "SUM(CASE WHEN state='pending' THEN 1 ELSE 0 END) AS pending FROM maintenance_notifications"
).fetchone()
assert tuple(maintenance_counts)==(MAX_MAINTENANCE_NOTIFICATIONS,8192,8192,MAX_MAINTENANCE_NOTIFICATIONS)
worker=AlertWorker(config_store=ConfigStore(),store=store,catalog=catalog,source_monitor=SourceMonitor(),
    status_path=Path('/state/worker-status.json'),continuity_path=Path('/state/continuity.json'),
    dispatcher=forbidden_dispatch)
now_wall=50000.0
now_mono=50000.0
first_rows=[]
second_rows=[]
# build the maximum normalized payload for each physical band
for index in range(MAX_ENCOUNTERS):
    first_rows.append({'hex':f'{index+1:06x}','messages':index+2,'fresh':True,
        'observed_at':now_wall,'last_observed_at':now_wall,'reception':'direct','dbFlags':1})
    second_rows.append({'hex':f'{0x800000+index:06x}','messages':index+2,'fresh':True,
        'observed_at':now_wall,'last_observed_at':now_wall,'reception':'rebroadcast','dbFlags':1})
samples=[
    {'band':'1090','generation':'g1090','expected':True,'healthy':True,'coverage_state':'healthy',
        'coverage_since':now_mono-1,'coverage_until':now_mono,'observed_at':now_wall,'aircraft':first_rows},
    {'band':'978','generation':'g978','expected':True,'healthy':True,'coverage_state':'healthy',
        'coverage_since':now_mono-1,'coverage_until':now_mono,'observed_at':now_wall,'aircraft':second_rows},
]
worker.engine.process_samples(samples,ConfigStore().get_private(),now_wall,now_mono)
assert worker.engine.capacity_error=='state_capacity_exceeded'
worker._publish_status(ConfigStore().get_private(),time.time(),time.monotonic())
counts=store.delivery_counts()
assert counts['pushover']['pending']==MAX_PENDING_EVENTS,counts
assert counts['email']['pending']==MAX_PENDING_EVENTS,counts
assert len(store.active_encounters())==MAX_ENCOUNTERS
rss=int(next(line.split()[1] for line in Path('/proc/self/status').read_text().splitlines() if line.startswith('VmRSS:')))
peak=int(resource.getrusage(resource.RUSAGE_SELF).ru_maxrss)
cgroup_current=int(Path('/sys/fs/cgroup/memory.current').read_text())//1024
assert rss<98304 and peak<98304 and cgroup_current<98304,(rss,peak,cgroup_current)
snapshot=json.loads(Path('/state/continuity.json').read_text())
assert len(snapshot['encounters'])==MAX_ENCOUNTERS
print(json.dumps({'max_encounters':MAX_ENCOUNTERS,'encounters':len(snapshot['encounters']),
    'normalized_source_rows':len(first_rows)+len(second_rows),'per_band_source_rows':MAX_ENCOUNTERS,
    'pending_event_cap':MAX_PENDING_EVENTS,'pending_events':created,'pending_jobs':created*2,
    'channels':['email','pushover'],'provider_dispatches':0,'catalog_entries':len(catalog._entries),
    'maintenance_notification_cap':MAX_MAINTENANCE_NOTIFICATIONS,
    'maintenance_notifications':maintenance_counts['count'],
    'maintenance_pending':maintenance_counts['pending'],'maintenance_body_bytes':8192,
    'maintenance_channel':'email','maintenance_cap_rejected':maintenance_cap_rejected,
    'rss_kib':rss,'peak_rss_kib':peak,'cgroup_current_kib':cgroup_current,
    'memory_limit_bytes':100663296,'capacity_error':'state_capacity_exceeded',
    'continuity_complete':True,'network':'none','readonly_root':True,'capabilities':'none'}))
# stop empty executors and close this fixture database
for pool in worker._pools.values():
    pool.shutdown(wait=True,cancel_futures=True)
store.close()
"""


# run one disposable container and decode its json result
def _run_json(arguments: list[str], *, timeout: int) -> dict[str, Any]:
    try:
        result = subprocess.run(arguments, check=True, capture_output=True, text=True, timeout=timeout)
    except subprocess.CalledProcessError as exc:
        # surface only bounded disposable-fixture diagnostics
        raise RuntimeError(f"isolated proof failed: {exc.stdout[-2000:]} {exc.stderr[-4000:]}") from exc
    return json.loads(result.stdout)


# validate externally collected production capacity aggregates
def _load_headroom(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text())
    expected = frozenset(
        (
            "captured_at",
            "mem_available_kib_samples",
            "vmstat_swap_in_kib_per_second",
            "vmstat_swap_out_kib_per_second",
            "oom_events_last_24h",
        )
    )
    # require one exact secret-free aggregate schema
    if not isinstance(value, dict) or frozenset(value) != expected:
        raise ValueError("invalid production headroom evidence")
    samples = value["mem_available_kib_samples"]
    swap_in = value["vmstat_swap_in_kib_per_second"]
    swap_out = value["vmstat_swap_out_kib_per_second"]
    # require five bounded numeric samples
    for series in (samples, swap_in, swap_out):
        if (
            not isinstance(series, list)
            or len(series) != 5
            or any(not isinstance(item, int) or isinstance(item, bool) or item < 0 for item in series)
        ):
            raise ValueError("invalid production headroom evidence")
    # require one nonnegative oom count
    if (
        not isinstance(value["oom_events_last_24h"], int)
        or isinstance(value["oom_events_last_24h"], bool)
        or value["oom_events_last_24h"] < 0
    ):
        raise ValueError("invalid production headroom evidence")
    planned_kib = 224 * 1024
    value["minimum_mem_available_kib"] = min(samples)
    value["planned_incremental_memory_kib"] = planned_kib
    value["residual_after_planned_increment_kib"] = min(samples) - planned_kib
    value["minimum_residual_requirement_kib"] = 256 * 1024
    value["headroom_passed"] = (
        value["residual_after_planned_increment_kib"] >= 256 * 1024
        and value["oom_events_last_24h"] == 0
        and not any(swap_in)
        and not any(swap_out)
    )
    return value


# copy only proof inputs with release-equivalent public source permissions
def _stage_worker_inputs(directory: Path) -> Path:
    root = directory / "release"
    shutil.copytree(ROOT / "adsb_admin", root / "adsb_admin")
    alerts = root / "deploy/alerts"
    alerts.mkdir(parents=True)
    # retain only immutable full-catalog inputs
    for name in ("catalog.json", "catalog-manifest.json"):
        shutil.copy2(ROOT / f"deploy/alerts/{name}", alerts / name)
    # normalize disposable bind permissions like the installer staging contract
    for path in (root, *root.rglob("*")):
        os.chmod(path, 0o755 if path.is_dir() else 0o644)
    return root


# execute opt-in cached-image proofs without provider or production traffic
def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--headroom-json", type=Path, required=True)
    parser.add_argument("--headroom-audit-json", type=Path, required=True)
    arguments = parser.parse_args()
    health = (ROOT / "deploy/alerts/source-health.sh").read_text()
    sources = []
    # prove both configured readsb physical input modes
    for band in ("1090", "978"):
        sources.append(
            _run_json(
                [
                    "docker",
                    "run",
                    "--rm",
                    "--pull=never",
                    "--network=none",
                    "--memory=64m",
                    "--read-only",
                    "--cap-drop=ALL",
                    "--security-opt=no-new-privileges:true",
                    "--tmpfs",
                    "/var/lib/adsb/alert-source:rw,nosuid,size=16m,mode=2750",
                    "--tmpfs",
                    "/tmp:rw,noexec,nosuid,size=8m",
                    "--entrypoint",
                    "/usr/bin/python3",
                    ULTRAFEEDER_PIN,
                    "-c",
                    READSB_PROBE,
                    band,
                    health,
                ],
                timeout=70,
            )
        )
    native = _run_json(
        [
            "docker",
            "run",
            "--rm",
            "--pull=never",
            "--network=none",
            "--memory=64m",
            "--read-only",
            "--cap-drop=ALL",
            "--security-opt=no-new-privileges:true",
            "--tmpfs",
            "/tmp:rw,noexec,nosuid,size=16m",
            "--entrypoint",
            "/usr/bin/python3",
            DUMP978_PIN,
            "-c",
            NATIVE_PROBE,
        ],
        timeout=30,
    )
    # stage private working-tree files without weakening their repository modes
    with tempfile.TemporaryDirectory(prefix="adsb-worker-proof-") as temporary:
        staged_root = _stage_worker_inputs(Path(temporary))
        worker = _run_json(
            [
                "docker",
                "run",
                "--rm",
                "--pull=never",
                "--network=none",
                "--memory=96m",
                "--read-only",
                "--cap-drop=ALL",
                "--security-opt=no-new-privileges:true",
                "--tmpfs",
                "/state:rw,nosuid,noexec,size=32m,mode=700",
                "--tmpfs",
                "/tmp:rw,nosuid,noexec,size=8m",
                "--mount",
                f"type=bind,src={staged_root},dst=/repo,readonly",
                "--env",
                "PYTHONPATH=/repo",
                "--entrypoint",
                "/usr/bin/python3",
                ULTRAFEEDER_PIN,
                "-c",
                WORKER_PROBE,
                "/repo/deploy/alerts/catalog.json",
                "/repo/deploy/alerts/catalog-manifest.json",
            ],
            timeout=180,
        )
    proof = {
        "schema_version": 1,
        "generated_at": dt.datetime.now(dt.UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z"),
        "image": ULTRAFEEDER_PIN,
        "dump978_image": DUMP978_PIN,
        "health_sha256": hashlib.sha256(health.encode()).hexdigest(),
        "sources": sources,
        "native978": {
            "selected": False,
            "failure_code": "independent_producer_coverage_unavailable",
            "identity_contract_passed": True,
            "producer_coverage_contract_passed": False,
            "existing_host_http_endpoint": "http://127.0.0.1:8978/skyaware978/data/aircraft.json",
            "native_http_host_port": 8978,
            "native_json_container_port": 30979,
            "native_json_tcp_host_port_published": False,
            "new_host_ports_allowed": False,
            "proof": native,
        },
        "worker": worker,
        "production_headroom": _load_headroom(arguments.headroom_json),
        "production_headroom_transient_audit": _load_headroom(arguments.headroom_audit_json),
    }
    # refuse an artifact that does not prove required deployment headroom
    if not proof["production_headroom"]["headroom_passed"]:
        raise RuntimeError("production headroom proof failed")
    arguments.output.write_text(json.dumps(proof, indent=2, sort_keys=True) + "\n")
    print(json.dumps(proof, sort_keys=True))
    return 0


# require explicit invocation before disposable fixture containers
if __name__ == "__main__":
    raise SystemExit(main())
