from nsxv import *
import datetime

nsx = Nsx('https://10.152.64.231:4443', 'admin', 'VMware1!')

n_sec = 1500
rules_per_sec = 20

print 
print '***** Teting creating %d sections with %d rules each *****' % (n_sec, rules_per_sec)
print
nsx.deleteAllFirewallLayer3Sections(False)
last = datetime.datetime.now()
for section in range(n_sec):
    s = FirewallSection('section-%d' % section, rules = [FirewallRule('allow') for rule in range(rules_per_sec)])
    nsx.createFirewallLayer3Section(s, False)
    now = datetime.datetime.now()
    delta = now - last
    print "Creating section %d took %d.%d sec" % (section, delta.seconds, delta.microseconds)
    last = now

