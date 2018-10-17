
import os
import psutil
from datetime import datetime
from graphviz import Source, Digraph

class ProcSleuth:

  def __init__(self, exe=None):
    self._connection_memory = {}
    self._process_memory = {} 
    self._go = True
    self._exe = exe
    self._lock_proc = None
    self._proc_cons = []
    self._proc_children = []
    self._proc_mem_map = []
    self._proc_con_memory = {}
  
  def set_state(self):
  
    ''' Set the current state of process list '''
    
    process_list = []
    for process_id in psutil.pids():
      try:
        temp_process = psutil.Process(process_id)
        process_list.append(temp_process)
        self._process_memory[process_id] = temp_process.name()
        self._connection_memory[temp_process.name()] = temp_process.connections()
      except Exception as err:
        pass
    return process_list
  
  def _set_proc_state(self):
  
    ''' Set the current state of process '''
    
    assert self._lock_proc, "No process locked"
    
    self._proc_cons.extend(self._lock_proc.connections())
    self._proc_children.extend(self._lock_proc.children(recursive=True))
    try: self._proc_mem_map.extend(self._lock_proc.mem_maps())
    except: pass   
   
  
  def make_dot(self, graphable):
  
    ''' generate a dot file 
    
      :graphable: a valid python dict
    '''
  
    with open('graph.dot','w') as out:
      for line in ('digraph G {','size="16,16";','splines=true;'):
        out.write('{}\n'.format(line))  
      for start, d in graphable.items():
        for end, weight in d.items():
          out.write('{} -> {} [ label="{}" color="{}" ];\n'.format(start,end,weight,'green'))
      out.write('}\n')
    return
  
  def create_graph(self, infile, outfile):
    
    ''' generates a graph and opens it
    
      :infile: a str representing a dot file name
      :outfile: the str name of the generated graph
      
    '''
    with open(infile, 'r') as fh:
      text = fh.read()
    Source(text).render(outfile, view=True)
  
    
  def print_change(self, previous_process_list):
    
    ''' Print changes to process list to stdout '''
    
    current_process_list = self.set_state()
    matched = 0
    
    for proc_current in current_process_list:
      for proc_previous in previous_process_list:
        if proc_previous == proc_current:
          matched = 1
          break
      if not matched:
        name = str(proc_current.name()).lower()
        print(' +++ ' + name + ' : ' + str(proc_current.pid))        
        if proc_current.connections():
          print(proc_current.connections())
          
        if name == self._exe:
          print('\nHooked Process\n')
          self._proc_con_memory[datetime.fromtimestamp(proc_current.create_time())] = []
          self._proc_con_memory[datetime.fromtimestamp(proc_current.create_time())].extend([(c, True) for c in proc_current.connections()])
          self._lock_proc = proc_current
          self._go = False
        
      matched = 0
    matched = 0
    
    for proc_previous in previous_process_list:
      try:
        name = str(proc_previous.name()).lower()
      except Exception as err:
        try:
          name = str(self._process_memory[proc_previous.pid])
        except Exception as err:
          name = proc_previous
      for proc_current in current_process_list:
        if proc_previous == proc_current:
          matched = 1
          break
      if not matched:
        print(' --- ' + str(name) + ' : ' + str(proc_previous.pid))
      matched = 0

    return current_process_list
 
 
  def _monitor(self):
    
    ''' monitor the target process '''
    
    assert self._lock_proc, "No process locked"
    
    self._go = True
    matched = 0
    
    while self._go:
    
      # connection info
      if not psutil.pid_exists(self._lock_proc.pid):
        self._go = False
        return
      try: cur_cons = psutil.Process(self._lock_proc.pid).connections()
      except:
        self._go = False
        return
      for new_con in cur_cons:
        for old_con in self._proc_cons:
          if new_con == old_con:
            matched = 1
            break
            
        if not matched:
          timestamp = datetime.now()
          try: self._proc_con_memory[timestamp].extend([(new_con, True)])
          except:
            self._proc_con_memory[timestamp] = []
            self._proc_con_memory[timestamp].extend([(new_con, True)])     
          # print(' +++ ' + str(new_con))
        matched = 0
      matched = 0
      
      for old_con in self._proc_cons:
        for new_con in cur_cons:
          if old_con == new_con:
            matched = 1
            break
            
        if not matched:
          timestamp = datetime.now()
          try: self._proc_con_memory[timestamp].extend([(old_con, False)])
          except:
            self._proc_con_memory[timestamp] = []
            self._proc_con_memory[timestamp].extend([(old_con, False)]) 
          # print(' --- ' + str(old_con))
        matched = 0
      
      self._proc_cons = cur_cons
      
 
  def run(self):
    
    ''' Loop to collect process state, check for not-allowed, and print changes to screen'''
    
    init = self.set_state()
    while self._go:
      init = self.print_change(init)
    self._set_proc_state()
    self._monitor()
    return
    
  def format_time(self, time):
    return '{}-{}-{} {}.{}.{}.{}'.format(str(time.year), str(time.month), str(time.day), str(time.hour), str(time.minute), str(time.second), str(time.microsecond))

  
  def graph_con_mem(self, outfile='net_connections'):
    
    '''
      create a pdf graph mapping network connections to times
      :outfile: the filename of saved graph
      
      green edge: new connection
      red edge: connection end
      blue edge: time travel
    '''
    digraph = Digraph('Network Connections', filename=outfile)
    digraph.attr(rankdir="TD")
    for k, v in self._proc_con_memory.items():
      digraph.attr('node', shape='doublecircle')
      digraph.node(self.format_time(k))
      
      for c in v:
        
        con = c[0]
        is_new = c[1]
        digraph.attr('node', shape='circle')
        data = 'Src {}\tPort {} \n\nDest {}\tPort {} \n\nFamily {} \n\nStatus {}'.format(con.laddr[0], con.laddr[1], con.raddr[0], con.raddr[1], str(con.family), con.status)
        digraph.edge(self.format_time(k), data , color='green' if is_new else 'red')

    digraph.attr('node', shape='doublecircle')
    for i in range(1, len(self._proc_con_memory.keys())):
      node1 = list(self._proc_con_memory.keys())[i - 1]
      node2 = list(self._proc_con_memory.keys())[i]

      digraph.edge(self.format_time(node1), self.format_time(node2), label=str(node2 - node1), color='blue')

    digraph.view()
    return
    
s = ProcSleuth('excel.exe')
s.run()
s.graph_con_mem(outfile="graph")

