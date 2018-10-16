#!/usr/bin/env python2

import os
import psutil
from graphviz import Source

class ProcSleuth:

  def __init__(self, exe=None):
    self._connection_memory = {}
    self._process_memory = {} 
    self._go = 1
    self._exe = exe
    self._lock_proc = None
    self._proc_cons = []
    self._proc_children = []
    self._proc_mem_map = []
    self._proc_child_map = {}
  
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
    self._proc_children.extend(self._lock_proc.children())
    try: self._proc_mem_map.extend(self._lock_proc.mem_maps())
    except: pass
    self._proc_child_map[self._lock_proc] = self.child_tree(self._lock_proc)
    
  
  def make_dot(self, graphable):
  
    with open('graph.dot','w') as out:
      for line in ('digraph G {','size="16,16";','splines=true;'):
        out.write('{}\n'.format(line))  
      for start, d in graphable.items():
        for end, weight in d.items():
          out.write('{} -> {} [ label="{}" color="{}" ];\n'.format(start,end,weight,'green'))
      out.write('}\n')
    return
  
  def create_graph(self, infile, outfile):
    
    with open(infile, 'r') as fh:
      text = fh.read()
    Source(text).render(outfile, view=True)
  
  def child_tree(self, parent):
    
    for child in parent.children():
      self._map[child] = self.child_tree(child)
    return None
    
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
          self._lock_proc = proc_current
          self._go = 0
        
      matched = 0
    matched = 0
    
    for proc_previous in previous_process_list:
      try:
        name = proc_previous.name()
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
    
    assert self._lock_proc, "No process locked"
    
    self._go = 1
    matched = 0
    while self._go:
      
      cur_cons = psutil.Process(self._lock_proc.pid).connections()
      for new_con in cur_cons:
        for old_con in self._proc_cons:
          if new_con == old_con:
            matched = 1
            break
        if not matched:
          print(' +++ ' + str(new_con))
        matched = 0
      matched = 0
      
      for old_con in self._proc_cons:
        for new_con in cur_cons:
          if old_con == new_con:
            matched = 1
            break
        if not matched:
          print(' --- ' + str(old_con))
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
    
s = ProcSleuth('excel.exe')
s.run()
  
