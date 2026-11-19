"""Archive validation, bounded memory, storage reserve and cache recovery."""
from io import BytesIO
import json
import struct

import pytest

from cvebeacon.errors import SourceError
from cvebeacon.watch import cve_list
from test_cve_explorer import official
from test_cve_list_feed import Release
from watch_support import mock_client


def test_corrupt_cache_is_evicted_and_next_attempt_downloads(tmp_path):
    fixture=Release([official()])
    asset=fixture.assets()[0]
    asset.pop('digest')
    cache=tmp_path/'cache'
    with mock_client(fixture) as http:
        assert list(cve_list.archive_records(http,asset,cache_directory=cache))
        path=next(cache.glob('*.zip'))
        path.write_bytes(b'x'*asset['size'])
        with pytest.raises(SourceError):
            list(cve_list.archive_records(http,asset,cache_directory=cache))
        assert not path.exists()
        assert list(cve_list.archive_records(http,asset,cache_directory=cache))
    assert len(fixture.requests)==2


def test_zip_offset_alias_is_rejected_before_constructor(monkeypatch):
    # EOCD points at benign headers; ZipFile would instead select the directory
    # immediately before EOCD, with twenty entries of the same total byte size.
    header=lambda name: struct.pack('<4s6H3L5H2L',b'PK\x01\x02',20,20,0,0,0,0,0,0,0,len(name),0,0,0,0,0,0)+name
    bad=b''.join(header(str(i).encode()) for i in range(20))
    benign=header(b'x'*(len(bad)-46))
    data=benign+bad+struct.pack('<4s4H2LH',b'PK\x05\x06',0,0,1,1,len(benign),0,0)
    monkeypatch.setattr(cve_list.zipfile,'ZipFile',lambda *a,**k:pytest.fail('allocated ambiguous directory'))
    with pytest.raises(SourceError):
        list(cve_list._members(BytesIO(data),allow_empty=True))


def test_expanded_storage_is_preflighted_before_any_import(tmp_path,monkeypatch):
    from collections import namedtuple
    usage=namedtuple('usage','total used free')
    fixture=Release([official(description='x'*200_000)],nested=True)
    asset=fixture.assets()[0]
    # The small compressed outer passes the old outer-only reserve. Its inner
    # directory exposes the large JSON before any provider can be inserted.
    monkeypatch.setattr(cve_list.shutil,'disk_usage',lambda _:usage(10**9,0,64*1024*1024+500_000))
    with mock_client(fixture) as http,pytest.raises(SourceError,match='disk'):
        list(cve_list.archive_records(http,asset,cache_directory=tmp_path/'cache'))


def test_targeted_cve_list_reply_uses_same_record_byte_cap():
    from cvebeacon.watch.refresh import _LookupHTTP
    class Fake:
        def stream_bytes(self,*args,**kwargs):
            assert kwargs['byte_cap']==cve_list.JSON_CAP
            yield b'{}'
    assert _LookupHTTP(Fake()).get_json('https://example.com',source='cve_list')=={}


def test_real_member_cap_uses_constant_directory_memory(tmp_path):
    import subprocess
    import sys
    if sys.platform != 'linux':
        pytest.skip('Linux peak RSS units')
    code=r'''
import json,resource,struct,sys
from cvebeacon.watch import cve_list
path=sys.argv[1]
count=cve_list.MAX_MEMBERS
header=struct.pack('<4s6H3L5H2L',b'PK\x01\x02',20,20,0,0,0,0,0,0,0,1,0,0,0,0,0,0)+b'x'
with open(path,'wb') as file:
    file.write(b'x')
    for _ in range(count//1000):
        file.write(header*1000)
    file.write(header*(count%1000))
    size=len(header)*count
    end=1+size
    file.write(struct.pack('<4sQ2H2L4Q',b'PK\x06\x06',44,45,45,0,0,count,count,size,1))
    file.write(struct.pack('<4sLQL',b'PK\x06\x07',0,end,1))
    file.write(struct.pack('<4s4H2LH',b'PK\x05\x06',0,0,65535,65535,size,1,0))
before=resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
with open(path,'rb') as file:
    assert list(cve_list._members(file,allow_empty=True))==[]
after=resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
print(json.dumps({'members':count,'growth_kib':after-before,'peak_kib':after}))
assert after-before < 32*1024, (before,after)
'''
    result=subprocess.run([sys.executable,'-c',code,str(tmp_path/'many.zip')],capture_output=True,text=True,timeout=90)
    assert result.returncode==0,result.stdout+result.stderr
    measurement=json.loads(result.stdout)
    assert measurement['members']==cve_list.MAX_MEMBERS
