import json
import getpass
import requests
import datetime
import copy
import xml.dom.minidom
from dicttoxml import dicttoxml


def unicode2str(stuff):
	if isinstance(stuff, dict):
		return dict((str(k), unicode2str(v)) for k, v in stuff.items())
	if isinstance(stuff, list):
		return [unicode2str(i) for i in stuff]
	if isinstance(stuff, unicode):
		return str(stuff)
	return stuff


def isip(s):
	if not isinstance(s, str):
		return False
	octets = s.split('.')
	if len(octets) != 4:
		return False
	for o in octets:
		if not o.isdigit():
			return False
		if not int(o) in range(256):
			return False
	return True


def wcard(obj, val):
	return 'wcard(%s, "%s")' % (obj, val)


def eq(obj, val):
	return 'eq(%s, "%s")' % (obj, val)


"""
apicip - IP address of apic
username/password for logging into APIC
if password is not provided it will be prompted for at login()
"""
class Apic(object):
	def __init__(self, apicaddr, username=None, password=None):
		self.__addr = None
		self.__hostname = None
		self.__password = password
		self.address = apicaddr
		self.username = username
		self.cookies = ""
		self.established = 0
		from requests.packages.urllib3.exceptions import InsecureRequestWarning
		requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
		self.ssn = requests.session()
		self.rsp = None
		self.status = ''

	@property
	def address(self):
		return self.__addr

	@address.setter
	def address(self, addr):
		self.__addr = addr
		if isip(addr):
			self.__hostname = None
		else:
			self.__hostname = addr

	@property
	def hostname(self):
		if self.__hostname is None:
			self.__hostname = self.__gethostname()
		return self.__hostname

	@property
	def password(self):
		return '********'

	@password.setter
	def password(self, pword):
		if pword == '':
			self.__password = None
		else:
			self.__password = pword

	def copy(self):
		return copy.deepcopy(self)

	def __prompt_for_password(self):
		self.__password = getpass.getpass("Password:")

	# private post function to do the real post work
	#  Path - url path (past https://<ip>/api/)
	#  Payload - The data to be posted to fabric
	def __post(self, path, payload):
		try:
			self.rsp = self.ssn.post('https://%s/api/%s' % (self.__addr, path), data=json.dumps(payload),
																cookies=self.cookies, verify=False)
		except Exception as e:
			print("Post failed. Exception %s" % e)
			return 666

	# private get function to do the real get work
	#  Path - url path (past https://<ip>/api/)
	#  Parameters - Parameters to be passed to ACI with the Get request
	def __get(self, path, parameters):
		try:
			self.rsp = self.ssn.get('https://%s/api/%s' % (self.__addr, path), params=parameters,
															cookies=self.cookies, verify=False)
		except Exception as e:
			print("Query failed. Exception %s" % e)
			return 666

	def get(self, path, parameters):
		self.__get(path, parameters)
		if self.rsp.status_code == 403:
			self.login()
			self.__get(path, parameters)
		if path[-5:] == '.json':
			return json.loads(self.rsp.text)
		return self.rsp.text

	# Identify the hostname of the APIC matching the ip
	def __gethostname(self):
		q = self.query('class/fabricNode.json', filter='eq(fabricNode.role,"controller")', propinclude='naming-only')
		jrv = q.run()
		for n in [n['fabricNode']['attributes']['dn'] for n in jrv['imdata']]:
			rvl = self.read_property('%s/sys' % n, ['name', 'oobMgmtAddr'])
			if rvl['oobMgmtAddr'] == self.__addr:
				return rvl['name']
		return None

	# Login function sends login request to APIC and, on success, populates cookies and established variables
	# Returns boolean of login success
	def login(self):
		if self.username is None or self.username == '':
			self.username = raw_input("Username:")
		if self.__password is None:
			self.__prompt_for_password()
		payload = {'aaaUser': {'attributes': {'name': self.username, 'pwd': self.__password}}}
		self.__post('aaaLogin.json', payload)

		if self.rsp.status_code == 401:
			print("Authentication failed.")
			self.__password = None
			return False
		if self.rsp.status_code >= 400:
			raise Exception("Error %s - HTTPS Request Error - ABORT!" % self.rsp.status_code)
		self.cookies = self.rsp.cookies
		self.established = datetime.datetime.now()
		return True

	# Refresh function sends a session refresh request to APIC.
	# Returns boolean of refresh success
	def refresh(self):
		self.__post('/mo/aaaRefresh.json', {})
		if self.rsp.status_code >= 400:
			print("Error %s - Unable to refresh APIC session - ABORT" % self.rsp.status_code)
			return False
		self.cookies = self.rsp.cookies
		return True

	# Logout function sends a logout request to APIC
	# Returns boolean of logout success
	def logout(self):
		payload = {'aaaUser': {'attributes': {'name': self.username}}}
		self.__post('/mo/aaaLogout.json', payload)
		if self.rsp.status_code >= 400:
			print("Error %s - HTTPS Request Error - ABORT!" % self.rsp.status_code)
			return False
		self.cookies = self.rsp.cookies
		self.established = 0
		self.__password = None
		return True

	# Post function used to send Post messages to fabric
	def post(self, path, payload):
		self.__post(path, payload)
		if self.rsp.status_code == 403:
			self.login()
			self.__post(path, payload)
		return self.rsp.status_code

	def query(self, path=None, filter=None, target=None, tclass=None, rspsub=None, propinclude=None, rspinclude=None):
		return Query(self, path=path, filter=filter, target=target, tclass=tclass, rspsub=rspsub, propinclude=propinclude, rspinclude=rspinclude)

	# Checks to see if an object exists with the provided dn
	def exists(self, obj):
		if type(obj) == str:
			dn = obj
		elif hasattr(obj, 'dn'):
			dn = obj.dn
		else:
			return False
		q = self.query('mo/%s.json' % dn, propinclude='naming-only')
		q.run(return_output=False)
		if q.output['totalCount'] == '0':
			return False
		if 'error' in q.output['imdata'][0].keys():
			return False
		return True

	# return the class of an object from its dn
	def get_class(self, dn):
		if not self.exists(dn):
			raise Exception('%s does not exist or is not a valid dn.' % dn)
		q = self.query('mo/%s.json' % dn)
		return q.run()['imdata'][0].keys()[0]

	# read a property value from a dn
	def read_property(self, dn, prop):
		if not self.exists(dn):
			return None
		q = self.query('mo/%s.json' % dn)
		q.run(return_output=False)
		subclass = str(q.output['imdata'][0].keys()[0])
		if q.output['totalCount'] == '0':
			return None
		if type(prop) == list:
			rt = {}
			for p in prop:
				val = q.output['imdata'][0][subclass]['attributes'][p]
				rt[p] = val if not p.isdigit() else int(val)
			return rt
		else:
			val = q.output['imdata'][0][subclass]['attributes'][prop]
			return val if not val.isdigit() else int(val)

	# read the property of a child (indicated by subclass) of a dn
	# may return a list if multiple child objects exist
	def read_child_property(self, dn, subclass, prop, return_list=False):
		if not self.exists(dn):
			return [] if return_list else None
		q = self.query(path='mo/%s.json' % dn, target='children', tclass=subclass)
		val = []
		for o in q.run()['imdata']:
			p = o[subclass]['attributes'][prop]
			val.append(p if not p.isdigit() else int(p))
		if val.__len__() == 1 and not return_list:
			return val[0]
		return val

	# set the attribute values of an object
	# dn - the dn of the object whose values are to be set.
	# attributes - a dictionary of valuse to be set e.g. {'name': 'Barney', 'color': 'purple}
	def set_property(self, dn, attributes, cls=None):
		if cls is None:
			cls = self.get_class(dn)
		status = 'modified' if self.exists(dn) else 'created'
		attributes.update({'status': status})
		payload = {cls: {'attributes': attributes}}
		return self.post('node/mo/%s.json' % dn, payload) < 300

	# create/modify child objects of a dn
	def set_child(self, dn, childclass, attributes, status='created'):
		if not self.exists(dn):
			return False
		cls = self.get_class(dn)
		attributes.update({'status': status})
		payload = {cls: {'attributes': {'status': 'modified'}, 'children': [{childclass: {'attributes': attributes}}]}}
		return self.post('node/mo/%s.json' % dn, payload) < 300

	# delete an object from aci (set status to 'deleted')
	def remove_object(self, dn, cls=None):
		if cls is None:
			cls = self.get_class(dn)
		payload = {cls: {'attributes': {'status': 'deleted'}}}
		return self.post('node/mo/%s.json' % dn, payload) < 300

	# Get the name of a provided dn
	def dn_name(self, dn):
		q = self.query('mo/%s.json' % dn)
		jrv = q.run()['imdata']
		return jrv[0][jrv[0].keys()[0]]['attributes']['name']


class Query(object):
	def __init__(self, apic, path=None, target=None, tclass=None, filter=None, rspsub=None, rspclass=None, rspfilter=None, propinclude=None,
								rspinclude=None, order=None, output_type='json'):
		self.__apic = None
		self.__path = None
		self.__target = None
		self.__tclass = None
		self.__rspsub = None
		self.__rspinclude = None
		self.__propinclude = None
		self.__output_type = 'json'
		self.output_type = output_type
		self.output = None
		self.apic = apic
		self.path = path
		self.target = target
		self.tclass = tclass
		self.filter = filter
		self.rspsub = rspsub
		self.rspclass = rspclass
		self.rspfilter = rspfilter
		self.propinclude = propinclude
		self.rspinclude = rspinclude
		self.order = order

	@property
	def apic(self):
		return self.__apic

	@apic.setter
	def apic(self, apic):
		if not isinstance(apic, Apic):
			raise Exception('Provided Apic object is not of type Apic.')
		self.__apic = apic

	@property
	def path(self):
		if self.__output_type == 'xml':
			return self.__path+'.xml'
		else:
			return self.__path+'.json'

	@path.setter
	def path(self, path):
		if path == '':
			path = None
		if path is not None:
			if type(path) is not str:
				raise Exception('Invalid type for path.  Should be string.')
			if path[:path.find('/')+1] not in ['mo/', 'class/']:
				if path.find('/') > 0:
					path = 'mo/'+path
				else:
					path = 'class/'+path
			if path[path.rfind('.'):] in ['.xml', '.json']:
				if path[path.rfind('.'):] == '.xml':
					self.output_type = 'xml'
				else:
					self.output_type = 'json'
				path = path[:path.rfind('.')]
		if not self.__path == path:
			self.output = None
		self.__path = path

	@property
	def target(self):
		return self.__target

	@target.setter
	def target(self, target):
		if target not in [None, 'self', 'children', 'subtree']:
			raise Exception("Invalid query target.  Options are self, children, and subtree.")
		self.__target = target

	@property
	def tclass(self):
		return self.__tclass

	@tclass.setter
	def tclass(self, tclass):
		if not (tclass is None or type(tclass) is str):
			raise Exception('Invalid tclass provided.  Must be of type str or None.')
		self.__tclass = tclass

	@property
	def rspsub(self):
		return self.__rspsub

	@rspsub.setter
	def rspsub(self, rspsub):
		if rspsub not in [None, 'no', 'children', 'full']:
			raise Exception('Invalid query response sub.  Options are no, children, and full.')
		self.__rspsub = rspsub

	@property
	def propinclude(self):
		return self.__propinclude

	@propinclude.setter
	def propinclude(self, propinclude):
		if propinclude not in [None, 'all', 'naming-only', 'config-only']:
			raise Exception('Invalid propinclude option.  Valid options are None, "all", "naming-only", "config-only".')
		self.__propinclude = propinclude

	@property
	def rspinclude(self):
		return self.__rspinclude

	@rspinclude.setter
	def rspinclude(self, rspinclude):
		if rspinclude is None:
			inc = None
			opt = None
		elif ',' in rspinclude:
			inc = rspinclude[:rspinclude.find(',')]
			opt = rspinclude[rspinclude.find(',')+1:]
		else:
			inc = rspinclude
			opt = None
		if inc not in ['faults', 'health', 'stats', 'fault-records', 'health-records', 'audit-logs', 'event-logs', 'relations',
										'relations-with-parent', 'no-scoped', 'subtree', 'deployment', 'port-deployment', 'full-deployment', 'required', 'count',
										'fault-count', 'tasks', 'deployment-records', 'ep-records', None]:
			raise Exception('Invalid value for rspinclude.')
		if opt not in ['count', 'no-scoped', 'required', None]:
			raise Exception('Invalid option for rspinclude.  Options are count, no-scoped, and required.')
		self.__rspinclude = rspinclude

	@property
	def parameters(self):
		pmtrs = {}
		if self.__target is not None:
			pmtrs.update({'query-target': self.__target})
		if self.tclass is not None:
			pmtrs.update({'target-subtree-class': self.tclass})
		if self.filter is not None:
			pmtrs.update({'query-target-filter': self.filter})
		if self.rspsub is not None:
			pmtrs.update({'rsp-subtree': self.rspsub})
		if self.rspclass is not None:
			pmtrs.update({'rsp-subtree-class': self.rspclass})
		if self.rspfilter is not None:
			pmtrs.update({'rsp-subtree-filter': self.rspfilter})
		if self.propinclude is not None:
			pmtrs.update({'rsp-prop-include': self.propinclude})
		if self.rspinclude is not None:
			pmtrs.update({'rsp-subtree-include': self.rspinclude})
		if self.order is not None:
			pmtrs.update({'order-by': self.order})
		return pmtrs

	@property
	def output_type(self):
		return self.__output_type

	@output_type.setter
	def output_type(self, output_type):
		if output_type in [None, '']:
			output_type = 'json'
		if output_type not in ['json', 'xml']:
			raise Exception('Invalid output type specified.  Supported values are "json" or "xml".')
		if self.output_type != output_type:
			self.__output_type = output_type
			if self.output is not None:
				self.run(return_output=False)

	@property
	def output_pretty(self):
		if self.output_type == 'json':
			return json.dumps(self.output, indent=2)
		if self.output_type == 'xml':
			x = xml.dom.minidom.parseString(self.output)
			return x.toprettyxml(indent="  ")
		return self.output

	@property
	def output_count(self):
		if isinstance(self.output, dict):
			if 'totalCount' in self.output.keys():
				return int(self.output['totalCount'])
			else:
				raise Exception('totalCount key not found in output.')
		if isinstance(self.output, str):
			if '<imdata totalCount=' in self.output:
				out = self.output[self.output.find('<imdata totalCount=')+20:]
				return int(out[:out.find('"')])
			else:
				raise Exception('totalCount key not found in output.')
		if self.output is None:
			return None

	def run(self, path=None, return_output=True, show_parameters=False):
		if path is not None:
			self.path = path
		if self.path is None:
			raise Exception('Path has not been set.')
		if show_parameters:
			print json.dumps(self.parameters, indent=2)
		self.output = unicode2str(self.apic.get(self.path, self.parameters))
		if return_output:
			return self.output

	def runq(self, path=None):
		self.run(path=path, return_output=False)

	def reset(self):
		self.path = None
		self.target = None
		self.tclass = None
		self.filter = None
		self.rspsub = None
		self.rspclass = None
		self.rspfilter = None
		self.propinclude = None
		self.rspinclude = None
		self.order = None

	def attribute(self, attr):
		return [o[o.keys()[0]]['attributes'][attr] for o in self.output['imdata']]

	def printout(self, idx=None):
		if idx is not None:
			if not isinstance(idx, int):
				raise Exception('Invalid index.  Must be an integer value')
			if idx < 0 or idx >= self.output_count:
				raise Exception('Invalid index.  Input is out of bounds of output array.')
		if self.output_type == 'json':
			if idx is None:
				print json.dumps(self.output, indent=2)
			else:
				print json.dumps(self.output['imdata'][idx], indent=2)
		elif self.output_type == 'xml':
			x = xml.dom.minidom.parseString(self.output)
			print x.toprettyxml(indent="  ")
		else:
			print self.output_pretty
