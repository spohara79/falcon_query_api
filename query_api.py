""" falcon_query_api.py - API Wrapper for Falcon Host Query """

__author__ = "Sean O'Hara"
__email__ = "spohara@gmail.com"
__version__ = "0.0.2"

import requests
import os
from datetime import tzinfo, timedelta, datetime
import time as _time

# from https://docs.python.org/3/library/datetimehtml#datetime.tzinfo examples
# d = datetime.now(LocalTimeZone())
# d.isoformat('T')
class LocalTimeZone(tzinfo):
    
    def __init__(self):
        self.stdoffset = timedelta(seconds=-_time.timezone)
        self.dstoffset = timedelta(seconds=-_time.altzone) if _time.daylight else self.stdoffset
        self.dstdiff = self.dstoffset - self.stdoffset

    def utcoffset(self, dt):
        if self._isdst(dt):
            return self.dstoffset
        else:
            return self.stdoffset

    def dst(self, dt):
        if self._isdst(dt):
            return self.dstdiff
        else:
            return timedelta(0)

    def tzname(self, dt):
        return _time.tzname[self._isdst(dt)]

    def _isdst(self, dt):
        tt = (dt.year, dt.month, dt.day, dt.hour, dt.minute, dt.second, dt.weekday(), 0, 0)
        stamp = _time.mktime(tt)
        tt = _time.localtime(stamp)
        return tt.tm_isdst > 0

class FalconQueryAPI(object):

    '''
        falconhost query api wrapper
        IOC Types
            sha256: A hex-encoded sha256 hash string. Length - min: 64, max: 64.
            sha1: A hex-encoded sha1 hash string. Length - min 40, max: 40.
            md5: A hex-encoded md5 hash string. Length - min 32, max: 32.
            domain: A domain name. Length - min: 1, max: 200.
            ipv4: An IPv4 address. Must be a valid IP address.
            ipv6: An IPv6 address. Must be a valid IP address.
    '''

    def __init__(self, username, api_key, host="falconapi.crowdstrike.com", proxy_url=None, verify='fh_root.pem'):
        self.username = username
        self.api_key = api_key
        self.auth = (self.api_key, self.username)
        self.host = host
        if proxy_url:
            self.proxies = {'https': proxy_url}
        self.verify = os.path.abspath(os.path.join(os.path.dirname(__file__), verify))
        self.set_api_urls()

    def __chunk__(self, chunk_list, n):
        for i in xrange(0, len(chunk_list), n):
            yield chunk_list[i:i+n]

    def set_api_urls(self):
        self.base = 'https://' + self.host
        self.search = '/'.join([self.base, 'indicators', 'queries'])
        self.search_indicators = '/'.join([self.search, 'iocs', 'v1'])
        self.search_device = '/'.join([self.search, 'devices', 'v1'])
        self.search_process = '/'.join([self.search, 'processes', 'v1'])
        self.manage_indicators = '/'.join([self.base, 'indicators', 'entities', 'iocs', 'v1'])
        self.manage_device = '/'.join([self.base, 'devices', 'entities', 'devices', 'v1'])
        self.count_device = '/'.join([self.base, 'indicators', 'aggregates', 'devices-count', 'v1'])
        self.process_detail = '/'.join([self.base, 'processes', 'entities', 'processes', 'v1'])
        self.resolve_detect = '/'.join([self.base, 'detects', 'entities', 'detects', 'v1'])

    '''
        Return detail information on indicator(s)

        @param: ids List of dicts that hold type (see class comments above) and values (IOCS)
        e.g., [{'domain':'bad-domain.com'}]
        @returns list of dicts that describe the IOC(s)
    '''
    def get_iocs(self, ids, retries=0):
        params = {'ids': []}
        params['ids'].extend([":".join([k, v]) for x in ids for k,v in x.iteritems()])
        resp = requests.get(self.manage_indicators, proxies=self.proxies, verify=self.verify, params=params, auth=self.auth)
        if resp.status_code == requests.codes.ok:
            return resp.json()['resources']
        elif resp.status_code == 429:
            if not retries:
                time.sleep(resp.headers['retry-after'])
                return self.get_iocs(ids, retries=1)
        else:
            resp.raise_for_status()

    '''
        Upload a list of  indicators and metadata

        @param iocs is a list of dicts that contain the following:
            key name        type       value
            =========================================================================================================
            Required
            --------
            type            String     The type of the indicator.
            value           String     The string representation of the indicator.

            Optional
            --------
            expiration_days Integer    (default = 30) This represents the days the indicator should be valid for.
                                       This only applies to domain, ipv4, and ipv6 types.
            source          String     The source where this indicator originated. This can be used for tracking where 
                                       this indicator was defined. Limit 200 characters.
            description     String     The friendly description of the indicator. Limit 200 characters.
         
            E.g., [{'type':'domain', 'value': 'bad-domain.com'}
    '''
    def upload_iocs(self, iocs, retries=0):
        d = datetime.now(LocalTimeZone())
        dstamp = d.isoformat('T')
        resources = []
        for json_iocs in self.__chunk__(iocs, 200):
            for x,_ in enumerate(json_iocs):
                json_iocs[x]['share_level'] = 'red'
                json_iocs[x]['policy'] = 'detect'
                json_iocs[x]['description'] = json_iocs[x].get('description', '') +'|'+ dstamp
            resp = requests.post(self.manage_indicators, proxies=self.proxies, verify=self.verify, json=json_iocs, auth=self.auth)
            if resp.status_code == requests.codes.ok:
                resources.extend(resp.json()['resources'])
            elif resp.status_code == 429:
                if not retries:
                    time.sleep(resp.headers['retry-after'])
                    return self.upload_iocs(iocs, retries=1)
            else:
                resp.raise_for_status()
        return resources
    '''
        Update metadata of an indicator

        @param ids             List(Dict) list of dicts that contain 'type' and 'value' paris (see get_iocs/class notes)
        @param expiration_days Integer    number of days indicator is valid for (ip and domain)
        @param source          String     name of source where indicator originated
        @param description     String     description of indicator
    '''
    def update_iocs(self, ids, expiration_days=None, source=None, description=None, retries=0):
        resources = []
        for this_ids in self.__chunk__(ids, 100):
            params = {'ids': []}
            json_data = {
                'policy': 'detect',
                'share_level': 'red',
                'source': source,
                'exiration_days': expiration_days,
                'description': description,
            }
            params['ids'].extend([":".join([k, v]) for x in this_ids for k,v in x.iteritems()])
            resp = requests.patch(self.manage_indicators, proxies=self.proxies, verify=self.verify, json=json_data, auth=self.auth)
            if resp.status_code == requests.codes.ok:
                resources.extend(resp.json()['resources'])
            elif resp.status_code == 429:
                if not retries:
                    time.sleep(resp.headers['retry-after'])
                    return self.update_iocs(ids, expiration_days, source, description, retries=1)
            else:
                resp.raise_for_status()
        return resources
            
    '''
    Delete a list of iocs

    @params ids  List(Dict)  list of dicts that contain 'type' and 'value' pairs (see get_iocs/class notes)
    '''
    def delete_iocs(self, ids, retries=0):
        resources = []
        for this_ids in self.__chunk__(ids, 100):
            params = {'ids': []}
            params['ids'].extend([":".join([k, v]) for x in this_ids for k,v in x.iteritems()])
            resp = requests.delete(self.manage_indicators, proxies=self.proxies, verify=self.verify, params=params, auth=self.auth)
            if resp.status_code == requests.codes.ok:
                resources.extend(resp.json()['resources'])
            elif resp.status_code == 429:
                if not retries:
                    time.sleep(resp.headers['retry-after'])
                    return self.delete_iocs(ids, retries=1)
            else:
                resp.raise_for_status()
        return resources

    '''
        Search IOCs by different types/values or metadata

        @param   types                     List(strings) A list of indicator types.
        @param   values                    List(strings) A list of indicator values.
        @param   sources                   List(strings) A list of IOC sources.
        @param   from.expiration_timestamp datetime      python datetime object that represents the starting date range
                                                       to search for IOCs by their expiration timestamp.
        @param   to.expiration_timestamp   datetime      python datetime object that represents the ending date range to 
                                                       search for IOCs by their expiration timestamp.
        @param   sort                      String        The order of the results. Format is <field>.<asc|desc>. Full list can be found below.
            type: Sort by IOC type "type.asc" or "type.desc"
            value: Sort by IOC value "value.asc" or "value.desc"
            expiration_timestamp: Sort by expiration timestamp "expiration_timestamp.asc" or "expiration_timestamp.desc"
        @param   limit                     Integer       (default = 100) The maximum number of records to return.
        @param   offset                    Integer       (default = 0) The offset to begin the list from. i.
        @returns                           List(dict)    returns a list of dicts that are 'type' and 'value' pairs
    '''
    def search_iocs(
        self, types=None, values=None, sources=None, from_stamp=None,
        to_stamp=None, sort=None, limit=100, offset=0, retries=0):
        results = []
        while True:
            params = {
                'types': types, 'values': values, 'sources': sources, 'from.expiration_timestamp': from_stamp,
                'to.expiration_timestamp': to_stamp, 'sort': sort, 'limit': limit, 'offset': offset,
            }
            resp = requests.get(self.search_indicators, proxies=self.proxies, verify=self.verify, params=params, auth=self.auth)
            if resp.status_code == requests.codes.ok:
                results.extend([dict(zip([x.split(':')[0]], [x.split(':')[1]])) for x in resp.json()['resources']])
                if offset + limit > resp.json()['meta']['pagination']['total']:
                    break
                offset = resp.json()['meta']['pagination']['offset']
            elif resp.status_code == 429:
                if not retries:
                    time.sleep(resp.headers['retry-after'])
                    return self.search_iocs(types, values, sources, from_stamp, to_stamp, sort, limit, offset, retries=1)
            else:
                resp.raise_for_status()
        return results

    '''
        Get device ids (end points) that have seen an indicator

        @param   type  String       The type of the indicator.
        @param   value String       The string representation of the indicator.
        @returns       List(String) List device ids
    '''
    def get_devices_ioc(self, type_, value, retries=0):
        params = {'type': type_, 'value': value}
        resp = requests.get(self.search_device, proxies=self.proxies, verify=self.verify, params=params, auth=self.auth)
        if resp.status_code == requests.codes.ok:
            return resp.json()['resources']
        elif resp.status_code == 429:
            if not retries:
                time.sleep(resp.headers['retry-after'])
                return self.get_devices_ioc(type_, value, retries=1)
        else:
            resp.raise_for_status()

    '''
        Get device details from device id(s)

        @param   ids List(string) list of strings that contain the uuid of the clients to get device details
        @returns     List(dict)   returns a list of dictionaries that contain device details
    '''
    def get_devices(self, ids, retries=0):
        params = {'ids': ids}
        resp = requests.get(self.manage_device, proxies=self.proxies, verify=self.verify, params=params, auth=self.auth)
        if resp.status_code == requests.codes.ok:
            return resp.json()['resources']
        elif resp.status_code == 429:
            if not retries:
                time.sleep(resp.headers['retry-after'])
                return self.get_devices(ids, retries=1)
        else:
            resp.raise_for_status()

    '''
        Get number of end points that have seen an indicator

        @param   type  String  The type of the indicator.
        @param   value String  The string representation of the indicator.
        @returns       Integer The count devices 
    '''
    def get_device_count(self, type_, value, retries=0):
        params = {'type': type_, 'value': value}
        resp = requests.get(self.count_device, proxies=self.proxies, verify=self.verify, params=params, auth=self.auth)
        if resp.status_code == requests.codes.ok:
            resources = resp.json()['resources']
            return int(resources[0]['device_count']) if len(resources) else 0 
        elif resp.status_code == 429:
            if not retries:
                time.sleep(resp.headers['retry-after'])
                return self.get_device_count(type_, value, retries=1)
        else:
            resp.raise_for_status()

    '''
        Get the process id from device_id that triggered an indicator

        @param   type      String       The type of the indicator.
        @param   value     String       The string representation of the indicator.
        @param   device_id String       
        @returns           List(String) A list of client device_ids which the indicator was found.
    '''
    def get_processes(self, type_, value, device_id, retries=0):
        params = {'type': type_, 'value': value, 'device_id': device_id}
        resp = requests.get(self.search_process, proxies=self.proxies, verify=self.verify, params=params, auth=self.auth)
        if resp.status_code == requests.codes.ok:
            #return [dict(zip(['device_id', 'md5'], [x.split(':')[2], x.split(':')[1]])) for x in resp.json()['resources']]
            return [dict(zip(['pid'], [x[4:]])) for x in resp.json()['resources']]
        elif resp.status_code == 429:
            if not retries:
                time.sleep(resp.headers['retry-after'])
                return self.get_processes(type_, value, device_id, retries=1)
        else:
            resp.raise_for_status()

    '''
        Gets the process details given process id(s)

        @param   ids List(string) List of process ids to get details on
        @returns     List(dict)   List of dictionaries that detail the processes
    '''
    def get_process_details(self, ids, retries=0):
        params = {'ids': ids}
        resp = requests.get(self.process_detail, proxies=self.proxies, verify=self.verify, params=params, auth=self.auth)
        if resp.status_code == requests.codes.ok:
            #return resp.json()['resources']
            return resp.json()
        elif resp.status_code == 429:
            if not retries:
                time.sleep(resp.headers['retry-after'])
                return self.get_process_details(ids, retries=1)
        else:
            resp.raise_for_status()

    '''
        Set the detection state for specific detect id(s)

        @param  ids      List(string) List of detection ids to resolve
        @param  to_state String       The state to transition the detection IDs to
            Valid States:
                new
                in_progress
                true_positive
                false_positive
                ignored          
        @returns        List(dict)   List of dictionaries that detail the processes
    '''
    def resolve_detection(self, ids, to_state, retries=0):
        params = {'ids': ids, 'to_state': to_state}
        resp = requests.patch(self.resolve_detect, proxies=self.proxies, verify=self.verify, params=params, auth=self.auth)
        if resp.status_code == requests.codes.ok:
            return resp.json()['meta']['writes']['resources_affected']
        elif resp.status_code == 429:
            if not retries:
                time.sleep(resp.headers['retry-after'])
                return self.resolve_detection(ids, to_state, retries=1)
        else:
            resp.raise_for_status()
