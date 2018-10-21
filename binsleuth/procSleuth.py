#!/usr/bin/env python
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
    self._file_io = []
    self._file_memory = {}
    self._proc_children_memory = {}
  
  def set_state(self):
  
    ''' Set the current state of process list '''
    
    process_list = []
    for temp_process in psutil.process_iter():
      try:
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
    self._proc_children.append(self._lock_proc.children(recursive=True))
    try: self._proc_mem_map.extend(self._lock_proc.mem_maps())
    except: pass
    
  def monitor_processes(self, previous_process_list):
    
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
    
    while self._go:
      
      self._monitor_network_cons()
      self._monitor_file_io()
      self._monitor_children()
      
      
    return 

    
  def process_exits(self):
    
    ''' checks if the process is still running 
      return boolean
    '''
    
    if psutil.pid_exists(self._lock_proc.pid):
      try:
        if self._lock_proc.name() == psutil.Process(self._lock_proc.pid).name() and psutil.Process(self._lock_proc.pid).status() == 'running':
          return True
      except: pass
      
    for proc in psutil.process_iter():
      try:
        if self._lock_proc.name().lower() == proc.name().lower():
          self._lock_proc = psutil.Process(proc.pid)
          return True
      except: return False
    return False
  
  
  def _terminate(self):
    
    if self._proc_children:
      for child in self._proc_children[-1]:
        try: child.terminate()
        except: pass
      dead, alive = psutil.wait_procs(self._proc_children[-1], timeout=3)
      for kiddie in alive:
        try: kiddie.kill()
        except: pass
   
  def _monitor_file_io(self):
    
    matched = 0
    
    if not self.process_exits():
      self._terminate()
      self._go = False
      return
      
    try: cur_files = psutil.Process(self._lock_proc.pid).open_files()
    except:
      self._go = False
      return
    
    for new_file in cur_files:
      for old_file in self._file_io:
        if new_file == old_file:
          matched = 1
          break
      
      if not matched:
        timestamp = datetime.now()
        try: self._file_memory[timestamp].extend([(new_file, True)])
        except:
          self._file_memory[timestamp] = []
          self._file_memory[timestamp].extend([(new_file, True)])
        # print(' +++ ' + str(new_file))
      
      matched = 0
    matched = 0
    
    for old_file in self._file_io:
      for new_file in cur_files:
        if old_file ==new_file:
          matched = 1
          break
          
      if not matched:
        timestamp = datetime.now()
        try: self._file_memory[timestamp].extend([(old_file, False)])
        except:
          self._file_memory[timestamp] = []
          self._file_memory[timestamp].extend([(old_file, False)])
        # print(' --- ' + str(old_file))
      matched = 0
      
    self._file_io = cur_files


  def _monitor_network_cons(self):
    
    matched = 0

    if not self.process_exits():
      self._terminate()
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
 
 
  def _monitor_children(self):
    
    assert self._lock_proc, "No process locked"
 
    if not self.process_exits():
      self._terminate()
      self._go = False
      return
      
    try: child_state = [proc for proc in psutil.Process(self._lock_proc.pid).children(recursive=True)]
    except:
      self._go = False
      return
    
    matched = 0
    
    for new_child in child_state:
      for old_child in self._proc_children:
        if new_child == old_child:
          matched = 1
          break
        
      if not matched:
        timestamp = datetime.now()
        try: self._proc_children_memory[timestamp].extend([(new_child, True)])
        except:
          self._proc_children_memory[timestamp] = []
          self._proc_children_memory[timestamp].extend([(new_child, True)])
      matched = 0
    matched = 0
    
    for old_child in self._proc_children:
      for new_child in child_state:
        if new_child == old_child:
          matched = 1
          break
        
      if not matched:
        timestamp = datetime.now()
        try: self._proc_children_memory[timestamp].extend([(old_child, False)])
        except:
          self._proc_children_memory[timestamp] = []
          self._proc_children_memory[timestamp].extend([(old_child, False)])
      matched = 0
    
    self._proc_children = child_state
 
 
  def run(self):
    
    ''' Loop to collect process state, check for not-allowed, and print changes to screen'''
    
    init = self.set_state()
    while self._go:
      init = self.monitor_processes(init)
    self._set_proc_state()
    self._monitor()
    return
    
  def format_time(self, time):
  
    ''' graphviz keeps tying to turn colons into ip:port relationship
      so this method prevents that
    '''
    return '{}-{}-{} {}.{}.{}.{}'.format(str(time.year), str(time.month), str(time.day), str(time.hour), str(time.minute), str(time.second), str(time.microsecond))


  def _data_hub(self, type, object_field, digraph):
    
    if type == 'file':
      try: data = '{}\nmode {}\nflags {}\nposition {}'.format(str(object_field.path).replace(':', '[colon]'), str(object_field.mode), str(object_field.flags), str(object_field.position))
      except: data = '{}'.format(str(object_field.path).replace(':', '[colon]').replace('\\', '/'))
  
    elif type == 'con':
      if object_field.status == 'NONE':
        digraph.attr('node', shape='square', color='cyan')
        data = 'laddr {}\tport {} \nfamily {} \nstatus {}'.format(object_field.laddr[0], object_field.laddr[1], str(object_field.family), object_field.status)
      
      else:
        digraph.attr('node', shape='circle', color='black')
        data = 'laddr {}\tport {} \nraddr {}\tport {} \nfamily {} \nstatus {}'.format(object_field.laddr[0], object_field.laddr[1], object_field.raddr[0], object_field.raddr[1], str(object_field.family), object_field.status)
      
    elif type == 'child':
      
      data = '{}'.format(str(object_field))
      
    else:
      assert False, "Invalid type error at hub"
    
    return data
     
  def graph_memory(self, type, memory, fast_ugly=False, outfile='graphSleuth', view=False):
    
    '''
      create a pdf graph mapping memory to times
      :outfile: the filename of saved graph
      :view: if True, pop open graph when done
      
      green edge: creation/open
      red edge: destruction/close
      purple edge: time travel
    '''
    digraph = Digraph(type, filename=outfile)
    digraph.attr(rankdir='TB')
    if fast_ugly: digraph.attr(splines='line')
    for k, v in memory.items():
      digraph.attr('node', shape='doublecircle', color='black')
      digraph.node(self.format_time(k))
      
      for f in v:
        if not f[0]: continue
        is_new = f[1]
        digraph.attr('node', shape='circle', color='black')
        data = self._data_hub(type, f[0], digraph)
        digraph.edge(self.format_time(k), data, color='green' if is_new else 'red')
    
    digraph.attr('node', shape='doublecircle', color='black')
    sorted_memory = sorted(memory.keys())
    for i in range(1, len(memory.keys())):
      
      node1 = sorted_memory[i - 1]
      node2 = sorted_memory[i]
      
      digraph.edge(self.format_time(node1), self.format_time(node2), label=str(node2 - node1), color='purple')
    digraph.render(view=view)
    return
    
    
if os.name == 'nt': s = ProcSleuth('slack.exe')
else: s = ProcSleuth('firefox-esr')
s.run()
s.graph_memory('con', s._proc_con_memory, outfile='connections')
s.graph_memory('file', s._file_memory, outfile='files')
s.graph_memory('child', s._proc_children_memory, outfile='children')

#for k,v in s._proc_children_memory.items():
#  print(k,v)
#for k,v in s._file_memory.items():
#  print(k,v)
#for k,v in s._proc_con_memory.items():
#  print(k,v)