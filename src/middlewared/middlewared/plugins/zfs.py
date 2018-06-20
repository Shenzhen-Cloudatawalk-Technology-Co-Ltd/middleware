import errno
import socket
import subprocess
import threading
import time

from bsd import geom
import libzfs

from middlewared.schema import Dict, List, Str, Bool, Int, accepts
from middlewared.service import (
    CallError, CRUDService, Service, ValidationError, ValidationErrors,
    filterable, job,
)
from middlewared.utils import filter_list, start_daemon_thread

SCAN_THREADS = {}


def find_vdev(pool, vname):
    """
    Find a vdev in the given `pool` using `vname` looking for
    guid or path

    Returns:
        libzfs.ZFSVdev object
    """
    children = list(pool.root_vdev.children)
    while children:
        child = children.pop()

        if str(vname) == str(child.guid):
            return child

        if child.type == 'disk':
            path = child.path.replace('/dev/', '')
            if path == vname:
                return child

        children += list(child.children)


class ZFSPoolService(Service):

    class Config:
        namespace = 'zfs.pool'
        private = True

    @filterable
    def query(self, filters, options):
        with libzfs.ZFS() as zfs:
            # Handle `id` filter specially to avoiding getting all pool
            if filters and len(filters) == 1 and list(filters[0][:2]) == ['id', '=']:
                try:
                    pools = [zfs.get(filters[0][2]).__getstate__()]
                except libzfs.ZFSException:
                    pools = []
            else:
                pools = [i.__getstate__() for i in zfs.pools]
        return filter_list(pools, filters, options)

    @accepts(Str('pool'))
    async def get_disks(self, name):
        try:
            with libzfs.ZFS() as zfs:
                disks = list(zfs.get(name).disks)
        except libzfs.ZFSException as e:
            raise CallError(str(e), errno.ENOENT)

        await self.middleware.run_in_thread(geom.scan)
        labelclass = geom.class_by_name('LABEL')
        for absdev in disks:
            dev = absdev.replace('/dev/', '').replace('.eli', '')
            find = labelclass.xml.findall(f".//provider[name='{dev}']/../consumer/provider")
            name = None
            if find:
                name = geom.provider_by_id(find[0].get('ref')).geom.name
            else:
                g = geom.geom_by_name('DEV', dev)
                if g:
                    name = g.consumer.provider.geom.name

            if name and geom.geom_by_name('DISK', name):
                yield name
            else:
                self.logger.debug(f'Could not find disk for {dev}')

    @accepts(
        Str('name'),
        List('new'),
        List('existing', items=[
            Dict(
                'attachvdev',
                Str('target'),
                Str('type', enum=['DISK']),
                Str('path'),
            ),
        ]),
    )
    @job()
    def extend(self, job, name, new=None, existing=None):
        """
        Extend a zfs pool `name` with `new` vdevs or attach to `existing` vdevs.
        """

        if new is None and existing is None:
            raise CallError('New or existing vdevs must be provided', errno.EINVAL)

        if new:
            raise CallError('Adding new vdev is not implemented yet')

        try:
            with libzfs.ZFS() as zfs:
                pool = zfs.get(name)

                # Make sure we can find all target vdev
                for i in (existing or []):
                    target = find_vdev(pool, i['target'])
                    if target is None:
                        raise CallError(f"Failed to find vdev for {i['target']}", errno.EINVAL)
                    i['target'] = target

                for i in (existing or []):
                    newvdev = libzfs.ZFSVdev(zfs, i['type'].lower())
                    newvdev.path = i['path']
                    i['target'].attach(newvdev)

        except libzfs.ZFSException as e:
            raise CallError(str(e), e.code)

    @accepts(Str('pool'), Str('label'))
    def detach(self, name, label):
        """
        Detach device `label` from the pool `pool`.
        """
        try:
            with libzfs.ZFS() as zfs:
                pool = zfs.get(name)
                target = find_vdev(pool, label)
                if target is None:
                    raise CallError(f'Failed to find vdev for {label}', errno.EINVAL)
                target.detach()
        except libzfs.ZFSException as e:
            raise CallError(str(e), e.code)

    @accepts(Str('pool'), Str('label'), Str('dev'))
    def replace(self, name, label, dev):
        """
        Replace device `label` with `dev` in pool `name`.
        """
        try:
            with libzfs.ZFS() as zfs:
                pool = zfs.get(name)
                target = find_vdev(pool, label)
                if target is None:
                    raise CallError(f'Failed to find vdev for {label}', errno.EINVAL)

                newvdev = libzfs.ZFSVdev(zfs, 'disk')
                newvdev.path = f'/dev/{dev}'
                target.replace(newvdev)
        except libzfs.ZFSException as e:
            raise CallError(str(e), e.code)

    @accepts(Str('name'))
    @job(lock=lambda i: i[0])
    def scrub(self, job, name):
        """
        Start a scrub on pool `name`.
        """
        try:
            with libzfs.ZFS() as zfs:
                pool = zfs.get(name)
                pool.start_scrub()
        except libzfs.ZFSException as e:
            raise CallError(str(e), e.code)

        def watch():
            while True:
                with libzfs.ZFS() as zfs:
                    scrub = zfs.get(name).scrub.__getstate__()
                if scrub['function'] != 'SCRUB':
                    break

                if scrub['state'] == 'FINISHED':
                    job.set_progress(100, 'Scrub finished')
                    break

                if scrub['state'] == 'CANCELED':
                    break

                if scrub['state'] == 'SCANNING':
                    job.set_progress(scrub['percentage'], 'Scrubbing')
                time.sleep(1)

        t = threading.Thread(target=watch, daemon=True)
        t.start()
        t.join()

    @accepts()
    def find_import(self):
        with libzfs.ZFS() as zfs:
            return [i.__getstate__() for i in zfs.find_import()]


class ZFSDatasetService(CRUDService):

    class Config:
        namespace = 'zfs.dataset'
        private = True

    @filterable
    def query(self, filters, options):
        with libzfs.ZFS() as zfs:
            # Handle `id` filter specially to avoiding getting all datasets
            if filters and len(filters) == 1 and list(filters[0][:2]) == ['id', '=']:
                try:
                    datasets = [zfs.get_dataset(filters[0][2]).__getstate__()]
                except libzfs.ZFSException:
                    datasets = []
            else:
                datasets = [i.__getstate__() for i in zfs.datasets]
        return filter_list(datasets, filters, options)

    @accepts(Dict(
        'dataset_create',
        Str('name', required=True),
        Str('type', enum=['FILESYSTEM', 'VOLUME'], default='FILESYSTEM'),
        Dict(
            'properties',
            Bool('sparse'),
            additional_attrs=True,
        ),
    ))
    def do_create(self, data):
        """
        Creates a ZFS dataset.
        """

        verrors = ValidationErrors()

        if '/' not in data['name']:
            verrors.add('name', 'You need a full name, e.g. pool/newdataset')

        if verrors:
            raise verrors

        properties = data.get('properties') or {}
        sparse = properties.pop('sparse', False)
        params = {}

        for k, v in data['properties'].items():
            params[k] = v

        try:
            with libzfs.ZFS() as zfs:
                pool = zfs.get(data['name'].split('/')[0])
                pool.create(data['name'], params, fstype=getattr(libzfs.DatasetType, data['type']), sparse_vol=sparse)
        except libzfs.ZFSException as e:
            self.logger.error('Failed to create dataset', exc_info=True)
            raise CallError(f'Failed to create dataset: {e}')

    @accepts(
        Str('id'),
        Dict(
            'dataset_update',
            Dict(
                'properties',
                additional_attrs=True,
            ),
        ),
    )
    def do_update(self, id, data):
        try:
            with libzfs.ZFS() as zfs:
                dataset = zfs.get_dataset(id)

                if 'properties' in data:
                    for k, v in data['properties'].items():

                        # If prop already exists we just update it,
                        # otherwise create a user property
                        prop = dataset.properties.get(k)
                        if prop:
                            if v.get('source') == 'INHERIT':
                                if isinstance(prop, libzfs.ZFSUserProperty):
                                    # Workaround because libzfs crashes when trying to inherit user property
                                    subprocess.check_call(["zfs", "inherit", k, id])
                                else:
                                    prop.inherit()
                            elif 'value' in v and (
                                prop.value != v['value'] or prop.source.name == 'INHERITED'
                            ):
                                prop.value = v['value']
                            elif 'parsed' in v and (
                                prop.parsed != v['parsed'] or prop.source.name == 'INHERITED'
                            ):
                                prop.parsed = v['parsed']
                        else:
                            if v.get('source') == 'INHERIT':
                                pass
                            else:
                                if 'value' not in v:
                                    raise ValidationError('properties', f'properties.{k} needs a "value" attribute')
                                if ':' not in k:
                                    raise ValidationError('properties', f'User property needs a colon (:) in its name`')
                                prop = libzfs.ZFSUserProperty(v['value'])
                                dataset.properties[k] = prop

        except libzfs.ZFSException as e:
            self.logger.error('Failed to update dataset', exc_info=True)
            raise CallError(f'Failed to update dataset: {e}')

    def do_delete(self, id):
        try:
            with libzfs.ZFS() as zfs:
                ds = zfs.get_dataset(id)

                if ds.type == libzfs.DatasetType.FILESYSTEM:
                    ds.umount()

                ds.delete()
        except libzfs.ZFSException as e:
            self.logger.error('Failed to delete dataset', exc_info=True)
            raise CallError(f'Failed to delete dataset: {e}')

    def mount(self, name):
        try:
            with libzfs.ZFS() as zfs:
                dataset = zfs.get_dataset(name)
                dataset.mount()
        except libzfs.ZFSException as e:
            self.logger.error('Failed to mount dataset', exc_info=True)
            raise CallError(f'Failed to mount dataset: {e}')

    def promote(self, name):
        try:
            with libzfs.ZFS() as zfs:
                dataset = zfs.get_dataset(name)
                dataset.promote()
        except libzfs.ZFSException as e:
            self.logger.error('Failed to promote dataset', exc_info=True)
            raise CallError(f'Failed to promote dataset: {e}')


class ZFSSnapshot(CRUDService):

    class Config:
        namespace = 'zfs.snapshot'

    @filterable
    def query(self, filters, options):
        with libzfs.ZFS() as zfs:
            snapshots = [i.__getstate__() for i in list(zfs.snapshots)]
        # FIXME: awful performance with hundreds/thousands of snapshots
        return filter_list(snapshots, filters, options)

    @accepts(Dict(
        'snapshot_create',
        Str('dataset'),
        Str('name'),
        Bool('recursive'),
        Int('vmsnaps_count'),
        Dict('properties', additional_attrs=True)
    ))
    async def do_create(self, data):
        """
        Take a snapshot from a given dataset.

        Returns:
            bool: True if succeed otherwise False.
        """

        dataset = data.get('dataset', '')
        name = data.get('name', '')
        recursive = data.get('recursive', False)
        vmsnaps_count = data.get('vmsnaps_count', 0)
        properties = data.get('properties', None)

        if not dataset or not name:
            return False

        try:
            with libzfs.ZFS() as zfs:
                ds = zfs.get_dataset(dataset)
                ds.snapshot(f'{dataset}@{name}', recursive=recursive, fsopts=properties)

                if vmsnaps_count > 0:
                    ds.properties['freenas:vmsynced'] = libzfs.ZFSUserProperty('Y')

            self.logger.info(f"Snapshot taken: {dataset}@{name}")
            return True
        except libzfs.ZFSException as err:
            self.logger.error(f"{err}")
            return False

    @accepts(Dict(
        'snapshot_remove',
        Str('dataset', required=True),
        Str('name', required=True),
        Bool('defer_delete')
    ))
    async def remove(self, data):
        """
        Remove a snapshot from a given dataset.

        Returns:
            bool: True if succeed otherwise False.
        """
        snapshot_name = data['dataset'] + '@' + data['name']

        try:
            with libzfs.ZFS() as zfs:
                snap = zfs.get_snapshot(snapshot_name)
                snap.delete(True if data.get('defer_delete') else False)
        except libzfs.ZFSException as err:
            self.logger.error("{0}".format(err))
            return False
        else:
            self.logger.info(f"Destroyed snapshot: {snapshot_name}")

        return True

    @accepts(Dict(
        'snapshot_clone',
        Str('snapshot'),
        Str('dataset_dst'),
    ))
    async def clone(self, data):
        """
        Clone a given snapshot to a new dataset.

        Returns:
            bool: True if succeed otherwise False.
        """

        snapshot = data.get('snapshot', '')
        dataset_dst = data.get('dataset_dst', '')

        if not snapshot or not dataset_dst:
            return False

        try:
            with libzfs.ZFS() as zfs:
                snp = zfs.get_snapshot(snapshot)
                snp.clone(dataset_dst)
            self.logger.info("Cloned snapshot {0} to dataset {1}".format(snapshot, dataset_dst))
            return True
        except libzfs.ZFSException as err:
            self.logger.error("{0}".format(err))
            return False


class ScanWatch(object):

    def __init__(self, middleware, pool):
        self.middleware = middleware
        self.pool = pool
        self._cancel = threading.Event()

    def run(self):

        while not self._cancel.wait(2):
            with libzfs.ZFS() as zfs:
                scan = zfs.get(self.pool).scrub.__getstate__()
            if scan['state'] == 'SCANNING':
                self.send_scan(scan)
            elif scan['state'] == 'FINISHED':
                # Since this thread finishes on scrub/resilver end the event is sent
                # on devd event arrival
                break

    def send_scan(self, scan=None):
        if not scan:
            with libzfs.ZFS() as zfs:
                scan = zfs.get(self.pool).scrub.__getstate__()
        self.middleware.send_event('zfs.pool.scan', 'CHANGED', fields={
            'scan': scan,
            'name': self.pool,
        })

    def cancel(self):
        self._cancel.set()


async def _handle_zfs_events(middleware, event_type, args):
    data = args['data']
    if data.get('type') in ('misc.fs.zfs.resilver_start', 'misc.fs.zfs.scrub_start'):
        pool = data.get('pool_name')
        if not pool:
            return
        if pool in SCAN_THREADS:
            return
        scanwatch = ScanWatch(middleware, pool)
        SCAN_THREADS[pool] = scanwatch
        start_daemon_thread(target=scanwatch.run)

    elif data.get('type') in (
        'misc.fs.zfs.resilver_finish', 'misc.fs.zfs.scrub_finish', 'misc.fs.zfs.scrub_abort',
    ):
        pool = data.get('pool_name')
        if not pool:
            return
        scanwatch = SCAN_THREADS.pop(pool, None)
        if not scanwatch:
            return
        await middleware.run_in_thread(scanwatch.cancel)

        # Send the last event with SCRUB/RESILVER as FINISHED
        await middleware.run_in_thread(scanwatch.send_scan)

    if data.get('type') == 'misc.fs.zfs.scrub_finish':
        await middleware.call('mail.send', {
            'subject': f'{socket.gethostname()}: scrub finished',
            'text': f"scrub of pool '{data.get('pool_name')}' finished",
        })


def setup(middleware):
    middleware.event_subscribe('devd.zfs', _handle_zfs_events)
