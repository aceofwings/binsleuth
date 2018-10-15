import psutil

class ProcSleuth:

  def __init__(self, exe=None):
    self._connection_memory = {}
    self._process_memory = {} 
    self._go = 1
    self._exe = exe
    self._lock_proc = None
    self._proc_cons = []
    self._proc_children = []
  
  def set_state(self):
  
    ''' Set the current state of process list'''
    
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

  def print_change(self, previous_process_list):
    
    ''' Print changes to process list to stdout'''
    
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
          name = str(PROCESS_MEMORY[proc_previous.pid])
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
    while self._go:
      
      print(self._lock_proc.connections())
      print(self._lock_proc.children())
      #etc
      
 
  def run(self):
    
    ''' Loop to collect process state, check for not-allowed, and print changes to screen'''
    
    init = self.set_state()
    while self._go:
      init = self.print_change(init)
      
    self._monitor()
    return
    
s = ProcSleuth('excel.exe')
s.run()
  