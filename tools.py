import datetime
import socket
import query


bmo = query.Apic('bmoapic03.jkhy.com')
mmo = query.Apic('mmoapic03.jkhy.com')
lks = query.Apic('lksapic03.jkhy.com')
smo = query.Apic('smoapic03.jkhy.com')


def find_vrf(apic, vrf):
	if ':' in vrf:
		tn = vrf[:vrf.find(':')]
		vrf = vrf[vrf.find(':')+1:]
	q = apic.query('fvCtx')
	q.filter = 'wcard(fvCtx.name,"%s")' % vrf
	if 'tn' in locals().keys():
		q.filter = 'and(wcard(fvCtx.dn,"tn-%s"),%s)' % (tn, q.filter)
	q.runq()
	if q.output_count == 0:
		raise Exception('VRF not found.')
	if q.output_count > 1:
		raise Exception('Multiple matching VRFs found.')
	return q.attribute('dn')[0].replace('uni/tn-', '').replace('/ctx-', ':')


def find_node_dn(apic, node):
	if isinstance(node, int) or node.isdigit():
		node = "node-" + str(node)
	if not isinstance(node, str):
		raise Exception('Invalid node provided.')
	if node.find('node-') == 0:
		q = apic.query('fabricNode')
		q.filter = 'wcard(fabricNode.dn,"%s")' % node
	else:
		q = apic.query('fabricNode')
		q.filter = 'wcard(fabricNode.name, "%s")' % node
	q.runq()
	if q.output_count == 0:
		raise Exception('Node not found.')
	if q.output_count > 1:
		raise Exception('Multiple matches found for %s.' % node)
	return q.attribute('dn')[0]


def find_node_by_ip(apic, ip):
	q = apic.query('ipv4Addr')
	q.filter = 'eq(ipv4Addr.addr,"%s")' % ip
	q.runq()
	if q.output_count == 0:
		return None
	dn = q.attribute('dn')[0]
	return dn[:dn.find('/sys/')]


def find_nh_vrf(apic, node, network, extcomm):
	q = apic.query(node+'/sys/bgp/inst')
	q.target = 'subtree'
	q.tclass = 'bgpPath'
	q.filter = 'and(wcard(bgpPath.dn, "%s"),' \
									'wcard(bgpPath.flags, "best-path"),' \
									'eq(bgpPath.extComm, "%s"),' \
									'not(wcard(bgpPath.dn, "overlay")))' % (network, extcomm)
	q.runq()
	vrf = q.attribute('dn')[0].split('/')[6].replace('dom-','')
	return vrf


def local_routing_table(apic, node, vrf, network=None):
	path = node+'/sys/uribv4/dom-'+vrf+'/db-rt'
	if network is not None:
		path += '/rt-['+network+']'
	q = apic.query(path)
	q.target = 'subtree'
	q.tclass = 'uribv4Nexthop'
	q.runq()
	routes = []
	for i in range(q.output_count):
		dn = q.attribute('dn')[i]
		route = dict()
		route['network'] = dn[dn.find('rt-[')+4:dn.find(']/nh-')]
		route['nexthop'] = q.attribute('addr')[i]
		route['interface'] = q.attribute('if')[i]
		route['vrf'] = q.attribute('vrf')[i]
		route['type'] = q.attribute('type')[i]
		routes.append(route)
	return routes


def get_node_and_route(apic, node, vrf, network):
	q = apic.query(node+'/sys/bgp/inst/dom-'+vrf+'/af-ipv4-ucast/rt-['+network+']')
	q.target = 'children'
	q.tclass = 'bgpPath'
	q.filter = 'wcard(bgpPath.flags, "best-path")'
	q.runq()
	nh_node = find_node_by_ip(apic, q.attribute('nh')[0])
	nh_vrf = find_nh_vrf(apic, nh_node, network, q.attribute('extComm')[0])
	route = local_routing_table(apic, nh_node, nh_vrf, network)
	rt = route[0]
	rt['node'] = nh_node
	return rt


def find_routes(apic, node, vrf):
	vrf = find_vrf(apic, vrf)
	node = find_node_dn(apic, node)
	routes = local_routing_table(apic, node, vrf)
	routes_out = list()
	for rt in routes:
		if 'overlay' in rt['vrf'] and 'attached' not in rt['type']:
			routes_out.append(get_node_and_route(apic, node, vrf, rt['network']))
		else:
			rt['node'] = node
			routes_out.append(rt)
	return routes_out


def dict_replace(stuff, fnd, rplc):
	if isinstance(stuff, dict):
		return dict((k.replace(fnd, rplc), dict_replace(v, fnd, rplc)) for k, v in stuff.items())
	if isinstance(stuff, list):
		return [dict_replace(i, fnd, rplc) for i in stuff]
	if isinstance(stuff, str):
		return stuff.replace(fnd, rplc)
	return stuff


# Master script that offers guided access to ACI cloning tools
def objectcloner(apic=None):
	if apic is None:
		apicip = ''
		while not valid_apic_ip(apicip):
			print 'Invalid input' if not apicip == '' else ''
			apicip = raw_input('APIC IP address: ')
			if apicip.lower() in ('', 'quit'):
				return False
		username = raw_input('APIC username:')
		apic = query.Apic(apicip, username)
	print "What would you like to do?"
	print "1. Clone bindings from one EPG to another EPG."
	print "2. Clone EPGs bound by one interface to another interface."
	print "3. Cancel."
	ch = raw_input("Choice: ")
	if int(ch) == 1:
		epgsrc = 'Not found'
		epgdst = 'Not found'
		while epgsrc == 'Not found':
			epgsrc = epg_search(apic, raw_input('Source EPG search string: '))
			print 'EPG source: %s' % epgsrc
		while epgdst == 'Not found':
			epgdst = epg_search(apic, raw_input('Destination EPG search string: '))
			print 'EPG destination: %s' % epgdst
		vlan = int(input('Destination EPG VLAN tag: '))
		print "Cloning bindings"
		print " from %s" % epgsrc
		print " to %s" % epgdst
		print " and tagging with VLAN %d." % vlan
		if raw_input("Clone? (yes/no):").lower() == "yes":
			clone_epg_bindings(apic, epgsrc, epgdst, vlan)
			print "Done."
			return True
		else:
			return False
	if int(ch) == 2:
		ifcsrc = 'Not found'
		ifcdst = 'Not found'
		while ifcsrc == 'Not found':
			ifcsrc = ifc_path_search(apic, raw_input('Source interface search string: '))
			print 'Source interface: %s' % ifcsrc
		while ifcdst == 'Not found':
			ifcdst = ifc_path_search(apic, raw_input('Destination interface search string: '))
			print 'Destination interface: %s' % ifcdst
		print "Cloning bindings"
		print " from %s" % ifcsrc
		print " to %s" % ifcdst
		if raw_input("Clone? (yes/no)").lower() == 'yes':
			clone_binding(apic, ifcsrc, ifcdst)
			print "Done"
			return True
		return False
	if ch == "3":
		return False


def value_sets(str):
	vs = {}
	s = 0
	parlvl = 0
	var = ''
	for i in range(str.__len__()):
		if var == '' and s < i and str[i] in ' :':
			var = str[s:i]
			s = i+1
		else:
			if str[i] == '(':
				parlvl += 1
			elif str[i] == ')':
				parlvl -= 1
			elif str[i] == ',' and parlvl == 0:
				if str[s]+str[i-1] == '()':
					vs[var] = str[s+1:i-1]
				else:
					vs[var] = str[s:i]
				var = ''
				s = i+2
	if var != '':
		if str[s]+str[str.__len__()-1] == '()':
			vs[var] = str[s+1:str.__len__()-1]
		else:
			vs[var] = str[s:str.__len__()]
	return vs


def list_upgrades(apic):
	qry = 'wcard(eventRecord.changeSet, "desiredVersion")'
	rv = apic.query('node/class/eventRecord.json', filter='%s' % qry)
	log = []
	for r in rv['imdata']:
		e = r['eventRecord']['attributes']
		dt = datetime.datetime.strptime(e['created'][:23], '%Y-%m-%dT%H:%M:%S.%f')
		cs = e['changeSet']
		cs = cs[cs.find('desiredVersion')+16:]
		cs = cs[:cs.find('))')+1]
		log.append([dt, e['descr'], cs, e['affected']])
	log.sort()
	dv = 'Farts'
	for l in log:
		if l[2] != dv:
			dv = l[2]
			print "%s: %s %s %s" % (l[0].strftime("%Y/%m/%d %H:%M:%S.%f"), l[1], l[2], l[3])


def review_upgrade(apic, startdate, enddate=''):
	if enddate == '':
		qry = 'wcard(eventRecord.created, "%s")' % startdate
	else:
		qry = 'or(wcard(eventRecord.created, "%s"), wcard(eventRecord.created, "%s"))' % (startdate, enddate)
	qry += ',or(wcard(eventRecord.descr, "Upgrade"), wcard(eventRecord.descr, "Install"))'
	rv = apic.query('node/class/eventRecord.json', query_target_filter='=and(%s)' % qry)
	log = []
	for r in rv['imdata']:
		e = r['eventRecord']['attributes']
		dt = e['created'][:23]
		log.append([datetime.datetime.strptime(dt, '%Y-%m-%dT%H:%M:%S.%f'), e['cause'], e['descr']])
	log.sort()
	for e in log:
		print "%s: %s" % (e[0].strftime("%Y/%m/%d %H:%M:%S.%f"), e[2])
	return log


def delete_epg_bindings(apic, epg):
	bnds = epg_bindings(apic, epg)
	for bnd in bnds:
		print bnd
	return True


#  Combines tenant, application profile and EPG into a proper EPG DN
def epg_dn(tenant, app_profile, epg):
	return 'uni/tn-%s/ap-%s/epg/%s' % (tenant, app_profile, epg)


#  Searches fabric (using Apic object) for an EPG matching the provided key and returns its DN
def epg_search(apic, key):
	rv = apic.query('class/fvAEPg', filter='and(wcard(fvAEPg.name, "%s"))' % key)
	cnt = int(rv['totalCount'])
	if cnt == 1:
		return str(rv['imdata'][0]['fvAEPg']['attributes']['dn'])
	elif cnt > 1:
		print "Multiple matches found.  Please select one:"
		for n in range(int(rv['totalCount'])):
			print "%d - %s" % (n, rv['imdata'][n]['fvAEPg']['attributes']['dn'])
		return str(rv['imdata'][int(input('Choice: '))]['fvAEPg']['attributes']['dn'])
	else:
		return "Not found"


# Search fabric (using Apic object) for a VPC where the name contains key and returns the path/dn
def vpc_path_search(apic, key):
	rv = apic.query('class/fabricExtProtPathEpCont.json', target='children', query_target_filter='and(wcard(fabricPathEp.name,"%s"))' % key)
	if int(rv['totalCount']) == 1:
		return str(rv['imdata'][0]['fabricPathEp']['attributes']['dn'])
	elif int(rv['totalCount']) > 1:
		print "Multiple matches found.  Please select one:"
		for n in range(int(rv['totalCount'])):
			print "%d - %s" % (n, rv['imdata'][n]['fabricPathEp']['attributes']['dn'])
		return str(rv['imdata'][int(input('Choice: '))]['fabricPathEp']['attributes']['dn'])
	else:
		return "Not found"


# Search fabric (using Apic object) for an interface path where the name contains key.
def ifc_path_search(apic, key):
	jrv = apic.query('class/fabricPathEp.json', query_target_filter='and(wcard(fabricPathEp.name,"%s"))' % key)
	cnt = int(jrv['totalCount'])
	if cnt == 1:
		return jrv['imdata'][0]['fabricPathEp']['attributes']['dn']
	if cnt > 1:
		print "Multiple matches found.  Please select one:"
		for n in range(cnt):
			print '%d - %s' % (n, jrv['imdata'][n]['fabricPathEp']['attributes']['dn'])
		return str(jrv['imdata'][int(raw_input('Choice: '))]['fabricPathEp']['attributes']['dn'])
	return "Not found"


# Combines pod, leaf, and interface into a path for use in Static Binding
def ifc_path(apic, pod, leaf, ifc):
	if '/' in ifc:
		ifc = ifc.lower().replace('eth','').split('/')
		if ifc.__len__() == 2:
			path = 'topology/pod-%s/paths-%s/pathep-[eth%s/%s]' % (pod, leaf, ifc[0], ifc[1])
		if ifc.__len__() == 3:
			path = 'topology/pod-%s/paths-%s/extpaths-%s/pathep-[eth%s/%s]' % (pod, leaf, ifc[0], ifc[1], ifc[2])
		if apic.exists(path):
			path = ''
		else:
			return None
		rt = 'topology/pod-%s/protpath'
	else:
		rt = 'blah'
	return rt


# Returns a list of EPG DNs from fabric (using Apic object)
def epg_list(apic):
	jrv = apic.query('class/fvAEPg')
	return [str(a['fvAEPg']['attributes']['dn']) for a in jrv['imdata']]


# Return a list of EPG Static binding interface path/DNs from fabric (using Apic object)
def epg_bindings(apic, epg_dn):
	return apic.read_child_property(epg_dn, 'fvRsPathAtt', 'tDn', True)


# Search for endpoint path/DN objects matching key
def endpoint_search(apic, key):
	jrv = apic.query('class/fabricPathEp.json', query_target_filter='and(wcard(fabricPathEp.name,"%s"))' % key)
	return [str(r['fabricPathEp']['attributes']['dn']) for r in jrv['imdata']]


# Search for EPGs with bindings whose path/Dn matches key
def epg_search_by_binding(apic, key):
	jrv = apic.query('class/fvRsPathAtt.json', query_target_filter='and(wcard(fvRsPathAtt.tDn,"%s"))' % key)
	rt = []
	for s in jrv['imdata']:
		epg = s['fvRsPathAtt']['attributes']['dn']
		epg = str(epg[:epg.find('/rspathAtt-')])
		vlan = s['fvRsPathAtt']['attributes']['encap']
		vlan = int(vlan[vlan.find('-')+1:])
		rt.append([epg, vlan])
	return rt


# Find EPGs with static bindings using an interface by interface path/DN
def epgs_with_binding(apic, ifc):
	jrv = apic.query('class/fvRsPathAtt.json', query_target_filter='and(eq(fvRsPathAtt.tDn,"%s"))' % ifc)
	rt = []
	for s in jrv['imdata']:
		epg = s['fvRsPathAtt']['attributes']['dn']
		epg = str(epg[:epg.find('/rspathAtt-')])
		vlan = s['fvRsPathAtt']['attributes']['encap']
		vlan = int(vlan[vlan.find('-')+1:])
		rt.append([epg, vlan])
	return rt


# Add the newbnd intereface to every EPG with srcbnd in a static binding, matching the encap (vlan-tag)
def clone_binding(apic, srcbnd, newbnd):
	epgs = epgs_with_binding(apic, srcbnd)
	for e in epgs:
		print "Cloning to %s." % e[0]
		payload = {
			"encap": "vlan-%s" % e[1],
			"instrImedcy": "immediate",
			"mode": "regular",
			"tDn": newbnd
		}
		apic.set_property('%s/rspathAtt-[%s]' % (e[0], newbnd), payload, 'fvRsPathAtt')


# Copy the bindings from source EPG (srcepg) to destintation EPG (dstepg) and set the encap to dstvlan
def clone_epg_bindings(apic, srcepg, dstepg, dstvlan):
	bds = epg_bindings(apic, srcepg)
	print "Cloning to %s" % dstepg
	for b in bds:
		print "Cloning %s" % b
		payload = {
			"encap": "vlan-%s" % dstvlan,
			"instrImedcy": "immediate",
			"mode": "regular",
			"tDn": b
		}
		apic.set_property('%s/rspathAtt-[%s]' % (dstepg, b), payload, 'fvRsPathAtt')


# Write a 2D list to csv file.
# header_list should be a list of header values
# value_list is the list of values to print to CSV
def write_csv(filename, header_list, value_list):
	f = open(filename, 'w')
	hd = ''
	for h in header_list:
		hd += '%s, ' % h;
	f.write(hd[:-2]+'\n')
	for r in value_list:
		row = ''
		for v in r:
			row += '%s, ' % v
		f.write(row[:-2]+'\n')
	f.close()


# Write a list of EPGs and the corresponding encapsulation (vlan-tag) using a given interface (static binding) to csv
def epgcsv_frombinding(apic, sb, csv):
	epgs = epgs_with_binding(apic, sb)
	write_csv(csv, ['epg', 'vlan'], epgs)


# Test a string to determine if it as a valid APIC IP
def valid_apic_ip(apicip):
	octs= apicip.split('.')
	if not len(octs) == 4:
		print "Not a valid IP address."
		return False
	for o in octs:
		if not o.isdigit():
			print "Not a valid IP address."
			return False
		if not 0 <= int(o) <= 255:
			print "Not a valid IP address."
			return False
	sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	rsp = sock.connect_ex((apicip, 443))
	sock.close()
	if not rsp == 0:
		print "IP not open on port 443."
		return False
	return True


def find_vpc(apic, vpc):
	rv = apic.query('node/class/infraRsAccBaseGrp.json', query_target_filter='and(wcard(infraRsAccBaseGrp.tDn, "%s"))' % vpc)
	lst=[]
	for ifc in rv['imdata']:
		lst.append(ifc['infraRsAccBaseGrp']['attributes']['dn'])
	return lst


def timestamp_to_datetime(ts):
	os = int(ts[-6:-3])
	dt = datetime.datetime.strptime(ts[:-6], '%Y-%m-%dT%H:%M:%S.%f')
	if os == 0:
		dt = datetime.datetime.now()-datetime.datetime.utcnow()+dt
	return dt


def search_flows(apic, tenant=None, ip=None):
	if tenant is None:
		flt_tn = None
	else:
		flt_tn = 'wcard(acllogPermitL3Flow.dn "/tn-%s/ctx")' % tenant
	if ip is None:
		flt = flt_tn
	else:
		flt_src = 'eq(acllogPermitL3Flow.srcIp, "%s")' % ip
		flt_dst = 'eq(acllogPermitL3Flow.dstIp, "%s")' % ip
		if flt_tn is None:
			flt = 'or(%s, %s)' % (flt_src, flt_dst)
		else:
			flt = "and(%s, or(%s, %s))" % (flt_tn, flt_src, flt_dst)
	rv = 'action, protocol, source IP, Source Port, Dest IP, Dest Port'
	if flt is None:
		pf = apic.query('class/acllogPermitL3Flow.json')
	else:
		pf = apic.query('class/acllogPermitL3Flow.json', filter=flt)
	for o in pf['imdata']:
		f = o['acllogPermitL3Flow']['attributes']
		rv = rv+str('\npermitted, %s, %s, %s, %s, %s' % (f['protocol'], f['srcIp'], f['srcPort'], f['dstIp'], f['dstPort']))

	if flt is None:
		df = apic.query('class/acllogDropL3Flow.json')
	else:
		df = apic.query('class/acllogDropL3Flow.json', filter=flt.replace('acllogPermitL3Flow', 'acllogDropL3Flow'))
	for o in df['imdata']:
		f = o['acllogDropL3Flow']['attributes']
		rv = rv+str('\ndropped, %s, %s, %s, %s, %s' % (f['protocol'], f['srcIp'], f['srcPort'], f['dstIp'], f['dstPort']))

	return rv


def search_packets(apic, tenant, ip, window_start=None, window_end=None):
	flt_tn = 'wcard(acllogPermitL3Pkt.dn, "/tn-%s/ctx")' % tenant
	flt_src = 'eq(acllogPermitL3Pkt.srcIp, "%s")' % ip
	flt_dst = 'eq(acllogPermitL3Pkt.dstIp, "%s")' % ip
	flt = '%s, or(%s, %s)' % (flt_tn, flt_src, flt_dst)

	if window_start is not None:
		ws = (datetime.datetime.utcnow() - datetime.datetime.now() + window_start).strftime('%Y-%m-%dT%H:%M:%S.%f+00:00')
		flt = '%s, ge(acllogPermitL3Pkt.timeStamp, "%s")' % (flt, ws)
	if window_end is not None:
		we = (datetime.datetime.utcnow() - datetime.datetime.now() + window_end).strftime('%Y-%m-%dT%H:%M:%S.%f+00:00')
		flt = '%s, le(acllogPermitL3Pkt.timeStamp, "%s")' % (flt, we)
	flt = 'and(%s)' % flt
	rv = 'timestamp, action, protocol, source IP, Source Port, Dest IP, Dest Port'
	pf = apic.query('class/acllogPermitL3Pkt.json', filter=flt)
	for o in pf['imdata']:
		f = o['acllogPermitL3Pkt']['attributes']
		ts = timestamp_to_datetime(f['timeStamp'])
		rv = rv+str('\n%s, permitted, %s, %s, %s, %s, %s' % (ts, f['protocol'], f['srcIp'], f['srcPort'], f['dstIp'], f['dstPort']))

	flt = flt.replace('acllogPermitL3Pkt', 'acllogDropL3Pkt')
	df = apic.query('class/acllogDropL3Pkt.json', filter=flt)
	for o in df['imdata']:
		f = o['acllogDropL3Pkt']['attributes']
		ts = timestamp_to_datetime(f['timeStamp'])
		rv = rv+str('\n%s, dropped, %s, %s, %s, %s, %s' % (ts, f['protocol'], f['srcIp'], f['srcPort'], f['dstIp'], f['dstPort']))

	return rv


def dropcount(apic, window_start=None):
	tenant = {}
	if window_start is None:
		d = datetime.datetime.now()
		ws = datetime.datetime(d.year, d.month, d.day)
	else:
		ws = (datetime.datetime.utcnow() - datetime.datetime.now() + window_start).strftime('%Y-%m-%dT%H:%M:%S.%f+00:00')
	flt = 'ge(acllogDropL3Pkt.timeStamp, "%s")' % ws
	for rs in apic.query('class/acllogDropL3Pkt.json', query_target_filter=flt)['imdata']:
		tn = rs['acllogDropL3Pkt']['attributes']['dn'].split('/')[5][3:]
		tenant[tn] = tenant[tn]+1 if tn in tenant else 1
	return tenant
