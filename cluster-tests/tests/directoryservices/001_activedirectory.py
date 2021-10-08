import pytest

from config import CLUSTER_INFO, CLUSTER_IPS, CLUSTER_ADS
from utils import make_request, make_ws_request, wait_on_job
from exceptions import JobTimeOut
from pytest_dependency import depends


@pytest.mark.parametrize('ip', CLUSTER_IPS)
@pytest.mark.dependency(name="CTDB_IS_HEALTHY")
def test_001_ctdb_is_healthy(ip):
    url = f'http://{ip}/api/v2.0/ctdb/general/healthy'
    res = make_request('get', url)
    assert res.status_code == 200, res.text
    assert res.json() is True, res.text


@pytest.mark.parametrize('ip', CLUSTER_IPS)
@pytest.mark.dependency(name="CTDB_HAS_PUBLIC_IPS")
def test_002_ctdb_public_ip_check(ip, request):
    depends(request, ['CTDB_IS_HEALTHY'])

    payload = {'all_nodes': False}
    url = f'http://{ip}/api/v2.0/ctdb/general/status/'
    res = make_request('post', url, data=payload)
    assert res.status_code == 200, res.text
    this_node = res.json()[0]['pnn']

    payload = {
        'query-filters': [["id", "=", this_node]],
    }
    url = f'http://{ip}/api/v2.0/ctdb/public/ips'
    res = make_request('get', url, data=payload)
    assert res.status_code == 200, res.text

    try:
        data = set(res.json()[0]['configured_ips'].keys())
    except (KeyError, IndexError):
        data = set()

    to_add = set(CLUSTER_INFO['CLUSTER_IPS']) - data

    assert data or to_add, data
    for entry in to_add:
        payload = {
            "pnn": this_node,
            "ip": entry,
            "netmask": CLUSTER_INFO['NETMASK'],
            "interface": CLUSTER_INFO['INTERFACE'],
        }
        res = make_request('post', url, data=payload)
        assert res.status_code == 200, res.text
        try:
            status = wait_on_job(res.json(), ip, 5)
        except JobTimeOut:
            assert False, JobTimeOut
        else:
            assert status['state'] == 'SUCCESS', status

        assert status['result']


@pytest.mark.parametrize('ip', CLUSTER_IPS)
def test_003_validate_smb_bind_ips(ip, request):
    depends(request, ['CTDB_HAS_PUBLIC_IPS'])

    url = f'http://{ip}/api/v2.0/smb/bindip_choices'
    res = make_request('get', url)
    assert res.status_code == 200, res.text

    smb_ip_set = set(res.json().values())
    cluster_ip_set = set(CLUSTER_INFO['CLUSTER_IPS'])
    assert smb_ip_set == cluster_ip_set, res.text 


@pytest.mark.parametrize('ip', CLUSTER_IPS)
@pytest.mark.dependency(name="DS_NETWORK_CONFIGURED")
def test_004_validate_network_configuration(ip, request):
    depends(request, ['CTDB_HAS_PUBLIC_IPS'])

    url = f'http://{ip}/api/v2.0/network/configuration/'
    res = make_request('get', url)
    assert res.status_code == 200, res.text

    data = res.json()
    assert data['nameserver1'] == CLUSTER_INFO['DNS1']
    assert data['ipv4gateway'] == CLUSTER_INFO['DEFGW']

    payload = CLUSTER_ADS['DOMAIN']
    url = f'http://{ip}/api/v2.0/activedirectory/domain_info/'
    res = make_request('post', url, data=payload)
    assert res.status_code == 200, res.text

    domain_info = res.json()
    assert abs(domain_info['Server time offset']) < 180


@pytest.mark.dependency(name="JOINED_AD")
def test_005_join_activedirectory(request):
    depends(request, ['DS_NETWORK_CONFIGURED'])

    payload = {
        "domainname": CLUSTER_ADS['DOMAIN'],
        "bindname": CLUSTER_ADS['USERNAME'],
        "bindpw": CLUSTER_ADS['PASSWORD'],
        "enable": True
    }
    url = f'http://{CLUSTER_IPS[0]}/api/v2.0/activedirectory/'
    res = make_request('put', url, data=payload)
    assert res.status_code == 200, res.text

    try:
        status = wait_on_job(res.json()['job_id'], CLUSTER_IPS[0], 300)
    except JobTimeOut:
        assert False, JobTimeOut
    else:
        assert status['state'] == 'SUCCESS', status

    # Need to wait a little for cluster state to settle down

    for ip in CLUSTER_IPS:
        url = f'http://{ip}/api/v2.0/activedirectory/started'
        res = make_request('get', url)
        assert res.status_code == 200, f'ip: {ip}, res: {res.text}'
        assert res.json()

        url = f'http://{ip}/api/v2.0/activedirectory/get_state'
        res = make_request('get', url)
        assert res.status_code == 200, f'ip: {ip}, res: {res.text}'
        assert res.json() == 'HEALTHY'


@pytest.mark.parametrize('ip', CLUSTER_IPS)
@pytest.mark.dependency(name="DS_ACCOUNTS_CONFIGURED")
def test_006_verify_ad_accounts_present(ip, request):
    depends(request, ['JOINED_AD'])

    payload = {"username": f'administrator@{CLUSTER_ADS["DOMAIN"]}'}
    url = f'http://{ip}/api/v2.0/user/get_user_obj/'
    res = make_request('post', url, data=payload)
    assert res.status_code == 200, res.text

    payload = {"groupname": fr'{CLUSTER_ADS["DOMAIN"]}\domain users'}
    url = f'http://{ip}/api/v2.0/group/get_group_obj/'
    res = make_request('post', url, data=payload)
    assert res.status_code == 200, res.text


@pytest.mark.parametrize('ip', CLUSTER_IPS)
def test_007_validate_cached_ad_accounts(ip, request):
    depends(request, ['DS_ACCOUNTS_CONFIGURED'])

    payload = {
        'query-filters': [["method", "=", "activedirectory.fill_cache"]],
        'query-options': {'order_by': ['-id']},
    }
    url = f'http://{ip}/api/v2.0/core/get_jobs'
    res = make_request('get', url, data=payload)
    assert res.status_code == 200, res.text

    try:
        status = wait_on_job(res.json()[0]['id'], ip, 300)
    except JobTimeOut:
        assert False, JobTimeOut
    else:
        assert status['state'] == 'SUCCESS', status

    payload = {
        'query-filters': [["local", "=", False]],
        'query-options': {'extra': {"additional_information": ['DS']}},
    }
    url = f'http://{ip}/api/v2.0/user'
    res = make_request('get', url, data=payload)
    assert res.status_code == 200, res.text
    assert len(res.json()) != 0, 'No cached users'

    url = f'http://{ip}/api/v2.0/group'
    res = make_request('get', url, data=payload)
    assert res.status_code == 200, res.text
    assert len(res.json()) != 0, 'No cached groups'


@pytest.mark.parametrize('ip', CLUSTER_IPS)
def test_008_validate_kerberos_settings(ip, request):
    payload = {
        'query-filters': [["realm", "=", CLUSTER_ADS['DOMAIN']]],
        'query-options': {'get': True},
    }
    url = f'http://{ip}/api/v2.0/kerberos/realm'
    res = make_request('get', url, data=payload)
    assert res.status_code == 200, res.text

    payload = {
        'query-filters': [["name", "=", 'AD_MACHINE_ACCOUNT']],
        'query-options': {'get': True},
    }
    url = f'http://{ip}/api/v2.0/kerberos/keytab'
    res = make_request('get', url, data=payload)
    assert res.status_code == 200, res.text

    # check that kinit succeeded
    payload = {
        'msg': 'method',
        'method': 'kerberos.check_ticket',
    }
    res = make_ws_request(ip, payload)
    assert res.get('error') is None, res

    # check that keytab was generated
    payload = {
        'msg': 'method',
        'method': 'kerberos.keytab.kerberos_principal_choices',
    }
    res = make_ws_request(ip, payload)
    assert res.get('error') is None, res
    assert len(res['result']) != 0, res


def test_050_leave_activedirectory(request):
    depends(request, ['JOINED_AD'])

    payload = {
        "username": CLUSTER_ADS['USERNAME'],
        "password": CLUSTER_ADS['PASSWORD']
    }
    url = f'http://{CLUSTER_IPS[0]}/api/v2.0/activedirectory/leave/'
    res = make_request('post', url, data=payload)
    assert res.status_code == 200, res.text

    try:
        status = wait_on_job(res.json(), CLUSTER_IPS[0], 300)
    except JobTimeOut:
        assert False, JobTimeOut
    else:
        assert status['state'] == 'SUCCESS', status

    for ip in CLUSTER_IPS:
        url = f'http://{ip}/api/v2.0/activedirectory/get_state'
        res = make_request('get', url)
        assert res.status_code == 200, f'ip: {ip}, res: {res.text}'
        assert res.json() == 'DISABLED'

        url = f'http://{ip}/api/v2.0/activedirectory/started'
        res = make_request('get', url)
        assert res.status_code == 200, f'ip: {ip}, res: {res.text}'
        assert res.json() is False
