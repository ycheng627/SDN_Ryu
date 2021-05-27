from mininet.topo import Topo
 
class Tree( Topo ):
 
    def __init__(self):
 
        Topo.__init__(self)

        rootSwitch = self.addSwitch('s1')
        switches = [ self.addSwitch('s{}'.format(i+1)) for i in range(1, 4) ] 
        for i in range(3):
            self.addLink(rootSwitch, switches[i])

        hosts = [ self.addHost('h{}'.format(i)) for i in range(1, 6) ]
        for i in range(5):
            self.addLink(switches[i // 2], hosts[i])

class DataCenter( Topo ):
    '''
    The enumeration of an aggregation is like
            1     2
            |  x  |
            3     4

    The enumeration of hosts in an aggregation is like
            s3         s4
          /    \     /    \
         h1    h2   h3    h4

    The name of cores is 'core1', 'core2', ...
    The name of switches in a aggregation is 's11', 's12', 's13', 's14', ...
    The name of hosts is 'h11', 'h12', 'h13', 'h14', ...
    '''
    def __init__(self, n_core, n_aggr):

        Topo.__init__(self)

        cores = [self.addSwitch('core{}'.format(i+1)) for i in range(0, n_core)]

        aggregations = []
        hosts = []
        for i in range(n_aggr):
            aggregations.append([self.addSwitch('s{}{}'.format(i+1, j+1)) for j in range(4)])
            self.addLink(aggregations[i][0], aggregations[i][2])
            self.addLink(aggregations[i][0], aggregations[i][3])
            self.addLink(aggregations[i][1], aggregations[i][2])
            self.addLink(aggregations[i][1], aggregations[i][3])
            
            hosts.append([self.addHost('h{}{}'.format(i+1, j+1)) for j in range(4)])
            self.addLink(aggregations[i][2], hosts[i][0])
            self.addLink(aggregations[i][2], hosts[i][1])
            self.addLink(aggregations[i][3], hosts[i][2])
            self.addLink(aggregations[i][3], hosts[i][3])

        for i in range(n_core):
            for j in range(n_aggr):
                if i % 2 == 0:
                    self.addLink(cores[i], aggregations[j][0])
                else:
                    self.addLink(cores[i], aggregations[j][1])

topos = { 'Tree': ( lambda : Tree() ), 
          'DataCenter': (lambda n_core, n_aggr: DataCenter(n_core, n_aggr)) }